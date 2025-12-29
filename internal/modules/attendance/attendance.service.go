package attendance

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"time"

	"github.com/waqasmani/go-boilerplate/internal/config"
	"github.com/waqasmani/go-boilerplate/internal/infrastructure/observability"
	"github.com/waqasmani/go-boilerplate/internal/infrastructure/sqlc"
	"github.com/waqasmani/go-boilerplate/internal/shared/errors"
	"github.com/waqasmani/go-boilerplate/internal/shared/validator"
)

// Service handles attendance business logic
type Service struct {
	queries     *sqlc.Queries
	auditLogger *observability.AuditLogger
	validator   *validator.Validator
	logger      *observability.Logger
	cfg         *config.Config
}

// NewService creates a new attendance service
func NewService(
	queries *sqlc.Queries,
	auditLogger *observability.AuditLogger,
	validator *validator.Validator,
	logger *observability.Logger,
	cfg *config.Config,
) *Service {
	return &Service{
		queries:     queries,
		auditLogger: auditLogger,
		validator:   validator,
		logger:      logger,
		cfg:         cfg,
	}
}

// CheckIn creates a new attendance record
func (s *Service) CheckIn(ctx context.Context, userID uint64, req CheckInRequest) (*AttendanceResponse, error) {
	now := time.Now().UTC()

	// Validate client timestamp skew if provided
	if req.ClientTimestamp != nil {
		skew := now.Sub(*req.ClientTimestamp).Abs()
		if skew > 5*time.Minute {
			return nil, ErrTimeSkewTooLarge
		}
	}
	lockKey := fmt.Sprintf("checkin_lock_%d", userID)

	// Acquire distributed lock
	if err := s.queries.AcquireLock(ctx, lockKey); err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeInternal, "Failed to acquire lock")
	}
	defer s.queries.ReleaseLock(ctx, lockKey)
	// Check for existing open session (if multi-session disabled)
	openSession, err := s.queries.GetOpenAttendanceForUser(ctx, userID)
	if err == nil && openSession.ID > 0 {
		// Multi-session disabled by default
		return nil, ErrOpenSessionExists
	}

	if err != nil && err != sql.ErrNoRows {
		return nil, WrapAttendanceError(err, "Failed to check existing sessions")
	}

	// Get shift for today
	shiftAssignment, err := s.queries.GetEmployeeShiftForDate(ctx, sqlc.GetEmployeeShiftForDateParams{
		UserID:        userID,
		EffectiveDate: now,
		EndDate:       sql.NullTime{Valid: true, Time: now},
	})
	var shiftID *uint64
	isLate := false
	if err == nil {
		shiftID = &shiftAssignment.ShiftID
		// Check if late: compare with shift start time
		shiftStart, _ := time.Parse("15:04:05", shiftAssignment.StartTime.Format("15:04:05"))
		todayShiftStart := time.Date(now.Year(), now.Month(), now.Day(), shiftStart.Hour(), shiftStart.Minute(), 0, 0, time.UTC)
		if now.After(todayShiftStart.Add(5 * time.Minute)) { // 5 min grace period
			isLate = true
		}
	}

	var shiftIDParam sql.NullInt64
	if shiftID != nil {
		shiftIDParam = sql.NullInt64{Valid: true, Int64: int64(*shiftID)}
	}

	// Safely handle optional fields to avoid nil pointer dereference
	var checkInLat, checkInLng sql.NullString
	if req.Latitude != nil {
		checkInLat = sql.NullString{Valid: true, String: fmt.Sprintf("%f", *req.Latitude)}
	}
	if req.Longitude != nil {
		checkInLng = sql.NullString{Valid: true, String: fmt.Sprintf("%f", *req.Longitude)}
	}

	var clientCheckInAt sql.NullTime
	if req.ClientTimestamp != nil {
		clientCheckInAt = sql.NullTime{Valid: true, Time: *req.ClientTimestamp}
	}

	result, err := s.queries.CreateAttendance(ctx, sqlc.CreateAttendanceParams{
		UserID:          userID,
		ShiftID:         shiftIDParam,
		CheckInAt:       now,
		CheckInLat:      checkInLat,
		CheckInLng:      checkInLng,
		ClientCheckInAt: clientCheckInAt,
		IsLate:          isLate,
		Status:          sqlc.AttendanceRecordsStatusPresent,
	})
	if err != nil {
		return nil, WrapAttendanceError(err, "Failed to create attendance record")
	}

	attendanceID, _ := result.LastInsertId()

	// Create exception if late
	if isLate {
		_ = s.queries.CreateAttendanceException(ctx, sqlc.CreateAttendanceExceptionParams{
			AttendanceID:  uint64(attendanceID),
			ExceptionType: sqlc.AttendanceExceptionsExceptionTypeLateCheckin,
			Severity:      sqlc.AttendanceExceptionsSeverityWarning,
			AutoFlagged:   true,
		})
	}

	// Audit log
	s.auditLogger.LogSecurityEvent(ctx, observability.SecurityEvent{
		Type:     "attendance",
		Action:   "check_in",
		UserID:   userID,
		Resource: fmt.Sprintf("attendance:%d", attendanceID),
		Success:  true,
	})

	// Fetch and return created record
	attendance, err := s.queries.GetAttendanceByID(ctx, uint64(attendanceID))
	if err != nil {
		return nil, WrapAttendanceError(err, "Failed to fetch created attendance")
	}

	return s.toAttendanceResponse(attendance), nil
}

// CheckOut closes an attendance session
func (s *Service) CheckOut(ctx context.Context, userID uint64, req CheckOutRequest) (*AttendanceResponse, error) {
	now := time.Now().UTC()

	// Validate client timestamp skew
	if req.ClientTimestamp != nil {
		skew := now.Sub(*req.ClientTimestamp).Abs()
		if skew > 5*time.Minute {
			return nil, ErrTimeSkewTooLarge
		}
	}

	// Find session to close
	var attendance sqlc.AttendanceRecord
	var err error
	if req.AttendanceID != nil {
		attendance, err = s.queries.GetAttendanceByID(ctx, *req.AttendanceID)
		if err == sql.ErrNoRows {
			return nil, ErrSessionNotFound
		}
	} else {
		// Find latest open session
		openSession, err := s.queries.GetOpenAttendanceForUser(ctx, userID)
		if err == sql.ErrNoRows {
			return nil, ErrNoOpenSession
		}
		if err != nil {
			return nil, WrapAttendanceError(err, "Failed to find open session")
		}
		attendance = openSession
	}

	if err != nil {
		return nil, WrapAttendanceError(err, "Failed to fetch attendance")
	}

	// Verify ownership
	if attendance.UserID != userID {
		return nil, errors.ErrForbidden
	}

	// Check if already checked out
	if attendance.CheckOutAt.Valid {
		return nil, ErrAlreadyCheckedOut
	}

	// Calculate duration
	duration := uint32(now.Sub(attendance.CheckInAt).Seconds())

	// Calculate overtime if shift assigned
	overtime := uint32(0)
	isEarlyLeave := false
	if attendance.ShiftID.Valid {
		shift, err := s.queries.GetShift(ctx, uint64(attendance.ShiftID.Int64))
		if err == nil {
			shiftDuration := s.calculateShiftDuration(shift.StartTime, shift.EndTime, uint32(shift.BreakMinutes))
			if duration > shiftDuration {
				overtime = duration - shiftDuration
			}
			// Check early leave
			shiftEnd, _ := time.Parse("15:04:05", shift.EndTime.Format("15:04:05"))
			expectedEnd := time.Date(now.Year(), now.Month(), now.Day(), shiftEnd.Hour(), shiftEnd.Minute(), 0, 0, time.UTC)
			if now.Before(expectedEnd.Add(-5 * time.Minute)) {
				isEarlyLeave = true
			}
		}
	}

	// Safely handle optional fields to avoid nil pointer dereference
	var checkOutLat, checkOutLng sql.NullString
	if req.Latitude != nil {
		checkOutLat = sql.NullString{Valid: true, String: fmt.Sprintf("%f", *req.Latitude)}
	}
	if req.Longitude != nil {
		checkOutLng = sql.NullString{Valid: true, String: fmt.Sprintf("%f", *req.Longitude)}
	}

	var clientCheckOutAt sql.NullTime
	if req.ClientTimestamp != nil {
		clientCheckOutAt = sql.NullTime{Valid: true, Time: *req.ClientTimestamp}
	}

	// Update attendance
	err = s.queries.CloseAttendance(ctx, sqlc.CloseAttendanceParams{
		ID:               attendance.ID,
		CheckOutAt:       sql.NullTime{Valid: true, Time: now},
		DurationSeconds:  sql.NullInt32{Valid: true, Int32: int32(duration)},
		OvertimeSeconds:  sql.NullInt32{Valid: true, Int32: int32(overtime)},
		CheckOutLat:      checkOutLat,
		CheckOutLng:      checkOutLng,
		ClientCheckOutAt: clientCheckOutAt,
		IsEarlyLeave:     isEarlyLeave,
	})
	if err != nil {
		return nil, WrapAttendanceError(err, "Failed to update attendance")
	}

	// Create exception if early leave
	if isEarlyLeave {
		_ = s.queries.CreateAttendanceException(ctx, sqlc.CreateAttendanceExceptionParams{
			AttendanceID:  attendance.ID,
			ExceptionType: sqlc.AttendanceExceptionsExceptionTypeEarlyCheckout,
			Severity:      sqlc.AttendanceExceptionsSeverityWarning,
			AutoFlagged:   true,
		})
	}

	// Audit log
	s.auditLogger.LogSecurityEvent(ctx, observability.SecurityEvent{
		Type:     "attendance",
		Action:   "check_out",
		UserID:   userID,
		Resource: fmt.Sprintf("attendance:%d", attendance.ID),
		Success:  true,
	})

	// Return updated record
	updated, err := s.queries.GetAttendanceByID(ctx, attendance.ID)
	if err != nil {
		return nil, WrapAttendanceError(err, "Failed to fetch updated attendance record")
	}
	return s.toAttendanceResponse(updated), nil
}

// ListAttendance retrieves attendance records with filters
func (s *Service) ListAttendance(ctx context.Context, req ListAttendanceRequest) (*ListAttendanceResponse, error) {
	if req.Limit <= 0 {
		req.Limit = 20
	}
	if req.Page <= 0 {
		req.Page = 1
	}
	offset := (req.Page - 1) * req.Limit

	// Use zero values for optional filters
	userID := uint64(0)
	if req.UserID != nil {
		userID = *req.UserID
	}

	var from, to *time.Time
	if req.From != nil {
		from = req.From
	}
	if req.To != nil {
		to = req.To
	}

	// Initialize with empty filters
	params := sqlc.CountAttendanceParams{
		Column1:     0,
		UserID:      0,
		Column3:     nil,
		CheckInAt:   time.Time{},
		Column5:     nil,
		CheckInAt_2: time.Time{},
		Column7:     "",
		Status:      "",
		Column9:     0,
		ShiftID:     sql.NullInt64{},
	}

	// Apply filters conditionally
	if userID > 0 {
		params.Column1 = 1
		params.UserID = userID
	}

	if from != nil {
		params.Column3 = from
		params.CheckInAt = *from
	}

	if to != nil {
		params.Column5 = to
		params.CheckInAt_2 = *to
	}

	if req.Status != "" {
		params.Column7 = req.Status
	}

	if req.ShiftID != nil {
		params.Column9 = 1
		params.ShiftID = sql.NullInt64{Valid: true, Int64: int64(*req.ShiftID)}
	}

	// Count total
	total, err := s.queries.CountAttendance(ctx, params)
	if err != nil {
		return nil, WrapAttendanceError(err, "Failed to count attendance")
	}

	// Fetch records
	records, err := s.queries.ListAttendance(ctx, sqlc.ListAttendanceParams{
		Column1:     params.Column1,
		UserID:      params.UserID,
		Column3:     params.Column3,
		CheckInAt:   params.CheckInAt,
		Column5:     params.Column5,
		CheckInAt_2: params.CheckInAt_2,
		Column7:     params.Column7,
		Status:      params.Status,
		Column9:     params.Column9,
		ShiftID:     params.ShiftID,
		Limit:       int32(req.Limit),
		Offset:      int32(offset),
	})
	if err != nil {
		return nil, WrapAttendanceError(err, "Failed to list attendance")
	}

	responses := make([]AttendanceResponse, len(records))
	for i, rec := range records {
		responses[i] = AttendanceResponse{
			ID:              rec.ID,
			UserID:          rec.UserID,
			ShiftID:         toUint64Ptr(rec.ShiftID),
			CheckInAt:       rec.CheckInAt,
			CheckOutAt:      toTimePtr(rec.CheckOutAt),
			DurationSeconds: toUint32Ptr(rec.DurationSeconds),
			OvertimeSeconds: uint32(rec.OvertimeSeconds.Int32),
			Status:          string(rec.Status),
			IsLate:          rec.IsLate,
			IsEarlyLeave:    rec.IsEarlyLeave,
			CreatedAt:       rec.CreatedAt,
			UpdatedAt:       rec.UpdatedAt,
		}
	}

	return &ListAttendanceResponse{
		Records: responses,
		Total:   total,
		Page:    req.Page,
		Limit:   req.Limit,
	}, nil
}

// AutoCheckoutStaleSessions closes sessions older than threshold
func (s *Service) AutoCheckoutStaleSessions(ctx context.Context, olderThanHours int) (int64, error) {
	result, err := s.queries.AutoCloseStaleAttendance(ctx, olderThanHours)
	if err != nil {
		return 0, WrapAttendanceError(err, "Failed to auto-close stale sessions")
	}

	count, _ := result.RowsAffected()
	s.logger.Info(ctx, fmt.Sprintf("Auto-closed %d stale attendance sessions", count))
	return count, nil
}

// GetLeaveBalance calculates leave balance for user
func (s *Service) GetLeaveBalance(ctx context.Context, userID uint64, leaveType string) (*LeaveBalanceResponse, error) {
	year := time.Now().Year()
	var sqlLeaveType sqlc.LeaveAccrualsLeaveType
	switch leaveType {
	case "sick":
		sqlLeaveType = sqlc.LeaveAccrualsLeaveTypeSick
	case "vacation":
		sqlLeaveType = sqlc.LeaveAccrualsLeaveTypeVacation
	case "personal":
		sqlLeaveType = sqlc.LeaveAccrualsLeaveTypePersonal
	default:
		return nil, errors.New(errors.ErrCodeValidation, "Invalid leave type")
	}

	balance, err := s.queries.GetLeaveBalance(ctx, sqlc.GetLeaveBalanceParams{
		UserID:    userID,
		LeaveType: sqlLeaveType,
		Year:      uint32(year),
	})
	if err == sql.ErrNoRows {
		// Initialize with defaults
		return &LeaveBalanceResponse{
			LeaveType:     leaveType,
			AccruedDays:   0,
			UsedDays:      0,
			CarryoverDays: 0,
			AvailableDays: 0,
			Year:          year,
		}, nil
	}
	if err != nil {
		return nil, WrapAttendanceError(err, "Failed to fetch leave balance")
	}

	// Convert string values to float64
	accruedDays, _ := convertToFloat(balance.AccruedDays)
	usedDays, _ := convertToFloat(balance.UsedDays)
	carryoverDays, _ := convertToFloat(balance.CarryoverDays)
	available := accruedDays + carryoverDays - usedDays

	return &LeaveBalanceResponse{
		LeaveType:     string(balance.LeaveType),
		AccruedDays:   accruedDays,
		UsedDays:      usedDays,
		CarryoverDays: carryoverDays,
		AvailableDays: available,
		Year:          int(balance.Year),
	}, nil
}

// RequestTimeOff creates a new time off request
func (s *Service) RequestTimeOff(ctx context.Context, userID uint64, req TimeOffRequest) (uint64, error) {
	var leaveType sqlc.TimeOffRequestsLeaveType
	switch req.LeaveType {
	case "sick":
		leaveType = sqlc.TimeOffRequestsLeaveTypeSick
	case "vacation":
		leaveType = sqlc.TimeOffRequestsLeaveTypeVacation
	case "personal":
		leaveType = sqlc.TimeOffRequestsLeaveTypePersonal
	case "unpaid":
		leaveType = sqlc.TimeOffRequestsLeaveTypeUnpaid
	default:
		return 0, errors.New(errors.ErrCodeValidation, "Invalid leave type")
	}

	startDate, err := time.Parse("2006-01-02", req.StartDate)
	if err != nil {
		return 0, errors.New(errors.ErrCodeValidation, "Invalid start date format")
	}

	endDate, err := time.Parse("2006-01-02", req.EndDate)
	if err != nil {
		return 0, errors.New(errors.ErrCodeValidation, "Invalid end date format")
	}

	daysCount := calculateBusinessDays(startDate, endDate)

	result, err := s.queries.CreateTimeOffRequest(ctx, sqlc.CreateTimeOffRequestParams{
		UserID:    userID,
		LeaveType: leaveType,
		StartDate: startDate,
		EndDate:   endDate,
		DaysCount: fmt.Sprintf("%.2f", daysCount),
		Reason:    sql.NullString{Valid: true, String: req.Reason},
		Status:    sqlc.TimeOffRequestsStatusPending,
	})
	if err != nil {
		return 0, WrapAttendanceError(err, "Failed to create time off request")
	}

	timeOffID, _ := result.LastInsertId()
	return uint64(timeOffID), nil
}

// Helper functions
func (s *Service) toAttendanceResponse(a sqlc.AttendanceRecord) *AttendanceResponse {
	return &AttendanceResponse{
		ID:                a.ID,
		UserID:            a.UserID,
		ShiftID:           toUint64Ptr(a.ShiftID),
		CheckInAt:         a.CheckInAt,
		CheckOutAt:        toTimePtr(a.CheckOutAt),
		DurationSeconds:   toUint32Ptr(a.DurationSeconds),
		OvertimeSeconds:   uint32(a.OvertimeSeconds.Int32),
		Status:            string(a.Status),
		IsLate:            a.IsLate,
		IsEarlyLeave:      a.IsEarlyLeave,
		CheckInLatitude:   toFloat64PtrFromString(a.CheckInLat),
		CheckInLongitude:  toFloat64PtrFromString(a.CheckInLng),
		CheckOutLatitude:  toFloat64PtrFromString(a.CheckOutLat),
		CheckOutLongitude: toFloat64PtrFromString(a.CheckOutLng),
		CreatedAt:         a.CreatedAt,
		UpdatedAt:         a.UpdatedAt,
	}
}

func (s *Service) calculateShiftDuration(start, end time.Time, breakMinutes uint32) uint32 {
	duration := end.Sub(start).Seconds()
	return uint32(duration) - (breakMinutes * 60)
}

func toUint64Ptr(val sql.NullInt64) *uint64 {
	if val.Valid {
		u := uint64(val.Int64)
		return &u
	}
	return nil
}

func toTimePtr(val sql.NullTime) *time.Time {
	if val.Valid {
		return &val.Time
	}
	return nil
}

func toUint32Ptr(val sql.NullInt32) *uint32 {
	if val.Valid {
		u := uint32(val.Int32)
		return &u
	}
	return nil
}

func toFloat64PtrFromString(val sql.NullString) *float64 {
	if val.Valid {
		var f float64
		fmt.Sscanf(val.String, "%f", &f)
		return &f
	}
	return nil
}

func calculateBusinessDays(start, end time.Time) float64 {
	if start.After(end) {
		return 0
	}

	totalDays := 0.0
	current := time.Date(start.Year(), start.Month(), start.Day(), 0, 0, 0, 0, start.Location())
	endDateOnly := time.Date(end.Year(), end.Month(), end.Day(), 0, 0, 0, 0, end.Location())

	for !current.After(endDateOnly) {
		// Skip weekends (Saturday and Sunday)
		if current.Weekday() != time.Saturday && current.Weekday() != time.Sunday {
			if current.Equal(time.Date(start.Year(), start.Month(), start.Day(), 0, 0, 0, 0, start.Location())) &&
				current.Equal(endDateOnly) {
				// Same day leave
				hours := end.Sub(start).Hours()
				totalDays += math.Min(1.0, hours/8.0)
			} else if current.Equal(time.Date(start.Year(), start.Month(), start.Day(), 0, 0, 0, 0, start.Location())) {
				// First day of multi-day leave (from start time to end of day)
				dayEnd := time.Date(start.Year(), start.Month(), start.Day(), 17, 0, 0, 0, start.Location())
				hours := dayEnd.Sub(start).Hours()
				totalDays += math.Min(1.0, math.Max(0.5, hours/8.0))
			} else if current.Equal(endDateOnly) {
				// Last day of multi-day leave (from start of day to end time)
				dayStart := time.Date(end.Year(), end.Month(), end.Day(), 9, 0, 0, 0, end.Location())
				hours := end.Sub(dayStart).Hours()
				totalDays += math.Min(1.0, math.Max(0.5, hours/8.0))
			} else {
				// Full middle day
				totalDays += 1.0
			}
		}
		current = current.AddDate(0, 0, 1)
	}
	return math.Max(totalDays, 0.5)
}

func convertToFloat(val string) (float64, error) {
	if val == "" {
		return 0.0, nil
	}

	var f float64
	_, err := fmt.Sscanf(val, "%f", &f)
	return f, err
}

// DailySummary retrieves attendance summary for a specific date
func (s *Service) DailySummary(ctx context.Context, date time.Time) (*DailySummaryResponse, error) {
	rows, err := s.queries.DailySummary(ctx, date)
	if err != nil && err != sql.ErrNoRows {
		return nil, WrapAttendanceError(err, "Failed to fetch daily summary")
	}

	if len(rows) == 0 || err == sql.ErrNoRows {
		// If no attendance records for the date, return empty summary
		return &DailySummaryResponse{
			Date: date.Format("2006-01-02"),
		}, nil
	}

	row := rows[0]

	// Helper function to safely convert interface{} to float64
	toFloat64 := func(val interface{}) float64 {
		if val == nil {
			return 0
		}
		switch v := val.(type) {
		case int64:
			return float64(v)
		case float64:
			return v
		default:
			return 0
		}
	}

	// Helper function to safely convert interface{} to int
	toInt := func(val interface{}) int {
		if val == nil {
			return 0
		}
		switch v := val.(type) {
		case int64:
			return int(v)
		default:
			return 0
		}
	}

	// Convert seconds to hours
	totalHours := toFloat64(row.TotalSeconds) / 3600.0
	overtimeHours := toFloat64(row.TotalOvertimeSeconds) / 3600.0

	return &DailySummaryResponse{
		Date:               date.Format("2006-01-02"),
		TotalAttendance:    int(row.TotalAttendance),
		PresentCount:       toInt(row.PresentCount),
		OnLeaveCount:       toInt(row.OnLeaveCount),
		AbsentCount:        toInt(row.AbsentCount),
		LateCount:          toInt(row.LateCount),
		TotalHours:         totalHours,
		TotalOvertimeHours: overtimeHours,
	}, nil
}

// ExportTimesheetForPeriod exports timesheet data for an employee for a specific period
func (s *Service) ExportTimesheetForPeriod(ctx context.Context, employeeID uint64, startDate, endDate time.Time) ([]sqlc.ExportTimesheetForPeriodRow, error) {
	params := sqlc.ExportTimesheetForPeriodParams{
		CheckInAt:   startDate,
		CheckInAt_2: endDate,
		Column3:     1, // Enable user filter
		UserID:      employeeID,
	}

	return s.queries.ExportTimesheetForPeriod(ctx, params)
}

func (s *Service) ApproveTimeOff(ctx context.Context, requestID uint64, adminID uint64, note string) error {
	request, err := s.queries.GetTimeOffByID(ctx, requestID)
	if err != nil {
		if err == sql.ErrNoRows {
			return errors.ErrNotFound
		}
		return err
	}

	if request.Status != "pending" {
		return errors.New(errors.ErrInvalidStatus, "Only pending requests can be approved")
	}

	err = s.queries.ApproveTimeOff(ctx, sqlc.ApproveTimeOffParams{
		ID:         requestID,
		ReviewedBy: sql.NullInt64{Int64: int64(adminID), Valid: true},
		ReviewNote: sql.NullString{String: note, Valid: true},
	})

	if err == nil {
		s.auditLogger.LogSecurityEvent(ctx, observability.SecurityEvent{
			Type: "attendance", Action: "approve_time_off", UserID: adminID, Resource: "time_off", Success: true,
		})
	}
	return err
}

func (s *Service) RejectTimeOff(ctx context.Context, requestID uint64, adminID uint64, note string) error {
	request, err := s.queries.GetTimeOffByID(ctx, requestID)
	if err != nil {
		if err == sql.ErrNoRows {
			return errors.ErrNotFound
		}
		return err
	}

	if request.Status != "pending" {
		return errors.New(errors.ErrInvalidStatus, "Only pending requests can be rejected")
	}

	return s.queries.RejectTimeOff(ctx, sqlc.RejectTimeOffParams{
		ID:         requestID,
		ReviewedBy: sql.NullInt64{Int64: int64(adminID), Valid: true},
		ReviewNote: sql.NullString{String: note, Valid: true},
	})
}
