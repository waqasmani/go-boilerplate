package attendance

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/waqasmani/go-boilerplate/internal/config"
	"github.com/waqasmani/go-boilerplate/internal/infrastructure/observability"
	"github.com/waqasmani/go-boilerplate/internal/infrastructure/sqlc"
	"github.com/waqasmani/go-boilerplate/internal/shared/validator"
)

type serviceDeps struct {
	mockDB      sqlmock.Sqlmock
	service     *Service
	cfg         *config.Config
	logger      *observability.Logger
	auditLogger *observability.AuditLogger
	validator   *validator.Validator
	queries     *sqlc.Queries
}

func setupServiceTest(t *testing.T) (*serviceDeps, func()) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)

	cfg := &config.Config{
		Server:   config.ServerConfig{Env: "test"},
		Security: config.SecurityConfig{BcryptCost: 4},
		JWT: config.JWTConfig{
			AccessSecret: "test_secret_key_must_be_32_bytes_long",
			AccessExpiry: 15 * time.Minute,
		},
	}

	logger, _ := observability.NewLogger("info", "console")
	auditLogger := observability.NewAuditLogger(logger)
	validatorInstance := validator.New()
	queries := sqlc.New(db)

	service := NewService(queries, auditLogger, validatorInstance, logger, cfg)

	deps := &serviceDeps{
		mockDB:      mock,
		service:     service,
		cfg:         cfg,
		logger:      logger,
		auditLogger: auditLogger,
		validator:   validatorInstance,
		queries:     queries,
	}

	return deps, func() { db.Close() }
}

func TestService_CheckIn_ExistingSession(t *testing.T) {
	deps, cleanup := setupServiceTest(t)
	defer cleanup()

	userID := uint64(1)
	lockKey := fmt.Sprintf("checkin_lock_%d", userID)

	// Acquire lock
	deps.mockDB.ExpectExec("SELECT GET_LOCK").WithArgs(lockKey).WillReturnResult(sqlmock.NewResult(1, 1))

	// Existing open session found
	deps.mockDB.ExpectQuery("SELECT (.+) FROM attendance_records WHERE user_id").
		WithArgs(userID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "user_id", "shift_id", "check_in_at", "check_out_at", "duration_seconds",
			"overtime_seconds", "status", "check_in_lat", "check_in_lng", "check_out_lat", "check_out_lng",
			"client_check_in_at", "client_check_out_at", "is_late", "is_early_leave", "created_at", "updated_at",
		}).AddRow(1, userID, nil, time.Now(), nil, nil, 0, "present", nil, nil, nil, nil, nil, nil, false, false, time.Now(), time.Now()))

	// Release lock
	deps.mockDB.ExpectExec("SELECT RELEASE_LOCK").WithArgs(lockKey).WillReturnResult(sqlmock.NewResult(1, 1))

	ctx := context.Background()
	req := CheckInRequest{}

	_, err := deps.service.CheckIn(ctx, userID, req)
	assert.Error(t, err)
	assert.Equal(t, ErrOpenSessionExists, err)
}

func TestService_CheckIn_WithShift_Late(t *testing.T) {
	deps, cleanup := setupServiceTest(t)
	defer cleanup()

	userID := uint64(1)
	shiftID := uint64(1)
	lockKey := fmt.Sprintf("checkin_lock_%d", userID)

	// Shift starts at 9 AM, checking in at 9:10 AM (late)
	now := time.Date(2024, 1, 1, 9, 10, 0, 0, time.UTC)
	shiftStart := time.Date(2024, 1, 1, 9, 0, 0, 0, time.UTC)

	deps.mockDB.ExpectExec("SELECT GET_LOCK").WithArgs(lockKey).WillReturnResult(sqlmock.NewResult(1, 1))
	deps.mockDB.ExpectQuery("SELECT (.+) FROM attendance_records WHERE user_id").WithArgs(userID).WillReturnError(sql.ErrNoRows)
	deps.mockDB.ExpectQuery("SELECT (.+) FROM employee_shifts").WillReturnRows(
		sqlmock.NewRows([]string{"id", "user_id", "shift_id", "effective_date", "end_date", "name", "start_time", "end_time", "break_minutes"}).
			AddRow(1, userID, shiftID, now, nil, "Morning", shiftStart, time.Date(2024, 1, 1, 17, 0, 0, 0, time.UTC), 60),
	)

	deps.mockDB.ExpectExec("INSERT INTO attendance_records").WillReturnResult(sqlmock.NewResult(1, 1))

	// Get the created record first (this happens before exception creation)
	deps.mockDB.ExpectQuery("SELECT (.+) FROM attendance_records WHERE id").WillReturnRows(
		sqlmock.NewRows([]string{
			"id", "user_id", "shift_id", "check_in_at", "check_out_at", "duration_seconds",
			"overtime_seconds", "status", "check_in_lat", "check_in_lng", "check_out_lat", "check_out_lng",
			"client_check_in_at", "client_check_out_at", "is_late", "is_early_leave", "created_at", "updated_at",
		}).AddRow(1, userID, shiftID, now, nil, nil, 0, "present", nil, nil, nil, nil, nil, nil, true, false, now, now),
	)

	// Expect exception for late check-in
	deps.mockDB.ExpectExec("INSERT INTO attendance_exceptions").WillReturnResult(sqlmock.NewResult(1, 1))

	deps.mockDB.ExpectExec("SELECT RELEASE_LOCK").WithArgs(lockKey).WillReturnResult(sqlmock.NewResult(1, 1))

	ctx := context.Background()
	result, err := deps.service.CheckIn(ctx, userID, CheckInRequest{})

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.IsLate)
}

func TestService_CheckIn_TimeSkewTooLarge(t *testing.T) {
	deps, cleanup := setupServiceTest(t)
	defer cleanup()

	userID := uint64(1)
	// Client timestamp 10 minutes in the past (exceeds 5 min tolerance)
	clientTime := time.Now().Add(-10 * time.Minute)

	ctx := context.Background()
	req := CheckInRequest{ClientTimestamp: &clientTime}

	_, err := deps.service.CheckIn(ctx, userID, req)
	assert.Error(t, err)
	assert.Equal(t, ErrTimeSkewTooLarge, err)
}

func TestService_CheckOut_NoOpenSession(t *testing.T) {
	deps, cleanup := setupServiceTest(t)
	defer cleanup()

	userID := uint64(1)

	deps.mockDB.ExpectQuery("SELECT (.+) FROM attendance_records WHERE user_id").
		WithArgs(userID).
		WillReturnError(sql.ErrNoRows)

	ctx := context.Background()
	_, err := deps.service.CheckOut(ctx, userID, CheckOutRequest{})

	assert.Error(t, err)
	assert.Equal(t, ErrNoOpenSession, err)
}

func TestService_CheckOut_AlreadyCheckedOut(t *testing.T) {
	deps, cleanup := setupServiceTest(t)
	defer cleanup()

	userID := uint64(1)
	attendanceID := uint64(1)

	deps.mockDB.ExpectQuery("SELECT (.+) FROM attendance_records WHERE user_id").
		WithArgs(userID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "user_id", "shift_id", "check_in_at", "check_out_at", "duration_seconds",
			"overtime_seconds", "status", "check_in_lat", "check_in_lng", "check_out_lat", "check_out_lng",
			"client_check_in_at", "client_check_out_at", "is_late", "is_early_leave", "created_at", "updated_at",
		}).AddRow(
			attendanceID, userID, nil, time.Now().Add(-8*time.Hour), time.Now(), 28800,
			0, "present", nil, nil, nil, nil, nil, nil, false, false, time.Now(), time.Now(),
		))

	ctx := context.Background()
	_, err := deps.service.CheckOut(ctx, userID, CheckOutRequest{})

	assert.Error(t, err)
	assert.Equal(t, ErrAlreadyCheckedOut, err)
}

func TestService_CheckOut_WithOvertime(t *testing.T) {
	deps, cleanup := setupServiceTest(t)
	defer cleanup()

	userID := uint64(1)
	shiftID := uint64(1)
	attendanceID := uint64(1)

	// Check in at 9 AM, check out at 6 PM (9 hours = 1 hour overtime for 8-hour shift)
	checkInTime := time.Date(2024, 1, 1, 9, 0, 0, 0, time.UTC)
	checkOutTime := time.Date(2024, 1, 1, 18, 0, 0, 0, time.UTC)

	deps.mockDB.ExpectQuery("SELECT (.+) FROM attendance_records WHERE user_id").
		WithArgs(userID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "user_id", "shift_id", "check_in_at", "check_out_at", "duration_seconds",
			"overtime_seconds", "status", "check_in_lat", "check_in_lng", "check_out_lat", "check_out_lng",
			"client_check_in_at", "client_check_out_at", "is_late", "is_early_leave", "created_at", "updated_at",
		}).AddRow(
			attendanceID, userID, sql.NullInt64{Int64: int64(shiftID), Valid: true}, checkInTime, nil, nil,
			0, "present", nil, nil, nil, nil, nil, nil, false, false, time.Now(), time.Now(),
		))

	// Get shift details
	deps.mockDB.ExpectQuery("SELECT (.+) FROM shifts WHERE id").
		WithArgs(shiftID).
		WillReturnRows(sqlmock.NewRows([]string{"id", "name", "start_time", "end_time", "break_minutes", "is_active", "created_at", "updated_at"}).
			AddRow(shiftID, "Morning", time.Date(2024, 1, 1, 9, 0, 0, 0, time.UTC), time.Date(2024, 1, 1, 17, 0, 0, 0, time.UTC), 60, true, time.Now(), time.Now()))

	deps.mockDB.ExpectExec("UPDATE attendance_records SET check_out_at").WillReturnResult(sqlmock.NewResult(1, 1))

	deps.mockDB.ExpectQuery("SELECT (.+) FROM attendance_records WHERE id").
		WithArgs(attendanceID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "user_id", "shift_id", "check_in_at", "check_out_at", "duration_seconds",
			"overtime_seconds", "status", "check_in_lat", "check_in_lng", "check_out_lat", "check_out_lng",
			"client_check_in_at", "client_check_out_at", "is_late", "is_early_leave", "created_at", "updated_at",
		}).AddRow(
			attendanceID, userID, sql.NullInt64{Int64: int64(shiftID), Valid: true}, checkInTime, checkOutTime, 32400,
			3600, "present", nil, nil, nil, nil, nil, nil, false, false, time.Now(), time.Now(),
		))

	ctx := context.Background()
	result, err := deps.service.CheckOut(ctx, userID, CheckOutRequest{})

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, uint32(3600), result.OvertimeSeconds) // 1 hour overtime
}

func TestService_CheckOut_EarlyLeave(t *testing.T) {
	deps, cleanup := setupServiceTest(t)
	defer cleanup()

	userID := uint64(1)
	shiftID := uint64(1)
	attendanceID := uint64(1)

	// Check in at 9 AM, check out at 4 PM (early - shift ends at 5 PM)
	checkInTime := time.Date(2024, 1, 1, 9, 0, 0, 0, time.UTC)
	checkOutTime := time.Date(2024, 1, 1, 16, 0, 0, 0, time.UTC)

	deps.mockDB.ExpectQuery("SELECT (.+) FROM attendance_records WHERE user_id").
		WithArgs(userID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "user_id", "shift_id", "check_in_at", "check_out_at", "duration_seconds",
			"overtime_seconds", "status", "check_in_lat", "check_in_lng", "check_out_lat", "check_out_lng",
			"client_check_in_at", "client_check_out_at", "is_late", "is_early_leave", "created_at", "updated_at",
		}).AddRow(
			attendanceID, userID, sql.NullInt64{Int64: int64(shiftID), Valid: true}, checkInTime, nil, nil,
			0, "present", nil, nil, nil, nil, nil, nil, false, false, time.Now(), time.Now(),
		))

	deps.mockDB.ExpectQuery("SELECT (.+) FROM shifts WHERE id").
		WithArgs(shiftID).
		WillReturnRows(sqlmock.NewRows([]string{"id", "name", "start_time", "end_time", "break_minutes", "is_active", "created_at", "updated_at"}).
			AddRow(shiftID, "Morning", time.Date(2024, 1, 1, 9, 0, 0, 0, time.UTC), time.Date(2024, 1, 1, 17, 0, 0, 0, time.UTC), 60, true, time.Now(), time.Now()))

	deps.mockDB.ExpectExec("UPDATE attendance_records SET check_out_at").WillReturnResult(sqlmock.NewResult(1, 1))

	// Expect early leave exception
	deps.mockDB.ExpectExec("INSERT INTO attendance_exceptions").WillReturnResult(sqlmock.NewResult(1, 1))

	deps.mockDB.ExpectQuery("SELECT (.+) FROM attendance_records WHERE id").
		WithArgs(attendanceID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "user_id", "shift_id", "check_in_at", "check_out_at", "duration_seconds",
			"overtime_seconds", "status", "check_in_lat", "check_in_lng", "check_out_lat", "check_out_lng",
			"client_check_in_at", "client_check_out_at", "is_late", "is_early_leave", "created_at", "updated_at",
		}).AddRow(
			attendanceID, userID, sql.NullInt64{Int64: int64(shiftID), Valid: true}, checkInTime, checkOutTime, 25200,
			0, "present", nil, nil, nil, nil, nil, nil, false, true, time.Now(), time.Now(),
		))

	ctx := context.Background()
	result, err := deps.service.CheckOut(ctx, userID, CheckOutRequest{})

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.IsEarlyLeave)
}

func TestService_AutoCheckoutStaleSessions(t *testing.T) {
	deps, cleanup := setupServiceTest(t)
	defer cleanup()

	deps.mockDB.ExpectExec("UPDATE attendance_records SET check_out_at").
		WillReturnResult(sqlmock.NewResult(0, 5))

	ctx := context.Background()
	count, err := deps.service.AutoCheckoutStaleSessions(ctx, 24)

	assert.NoError(t, err)
	assert.Equal(t, int64(5), count)
}

func TestService_GetLeaveBalance_NoRecord(t *testing.T) {
	deps, cleanup := setupServiceTest(t)
	defer cleanup()

	userID := uint64(1)

	deps.mockDB.ExpectQuery("SELECT (.+) FROM leave_accruals").
		WillReturnError(sql.ErrNoRows)

	ctx := context.Background()
	balance, err := deps.service.GetLeaveBalance(ctx, userID, "sick")

	assert.NoError(t, err)
	assert.NotNil(t, balance)
	assert.Equal(t, 0.0, balance.AccruedDays)
	assert.Equal(t, 0.0, balance.AvailableDays)
}

func TestService_GetLeaveBalance_WithBalance(t *testing.T) {
	deps, cleanup := setupServiceTest(t)
	defer cleanup()

	userID := uint64(1)

	deps.mockDB.ExpectQuery("SELECT (.+) FROM leave_accruals").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "user_id", "leave_type", "accrued_days", "used_days", "carryover_days", "year",
		}).AddRow(1, userID, "sick", "10.00", "2.50", "1.00", 2024))

	ctx := context.Background()
	balance, err := deps.service.GetLeaveBalance(ctx, userID, "sick")

	assert.NoError(t, err)
	assert.NotNil(t, balance)
	assert.Equal(t, 10.0, balance.AccruedDays)
	assert.Equal(t, 2.5, balance.UsedDays)
	assert.Equal(t, 1.0, balance.CarryoverDays)
	assert.Equal(t, 8.5, balance.AvailableDays) // 10 + 1 - 2.5
}

func TestService_ApproveTimeOff(t *testing.T) {
	deps, cleanup := setupServiceTest(t)
	defer cleanup()

	requestID := uint64(1)
	adminID := uint64(2)

	t.Run("Success", func(t *testing.T) {
		deps.mockDB.ExpectQuery("SELECT (.+) FROM time_off_requests WHERE id").
			WithArgs(requestID).
			WillReturnRows(sqlmock.NewRows([]string{
				"id", "user_id", "leave_type", "start_date", "end_date", "days_count", "reason",
				"status", "reviewed_by", "reviewed_at", "review_note", "created_at", "updated_at",
			}).AddRow(
				requestID, uint64(1), "sick", time.Now(), time.Now().AddDate(0, 0, 1),
				"1.00", "sick", "pending", nil, nil, nil, time.Now(), time.Now(),
			))

		deps.mockDB.ExpectExec("UPDATE time_off_requests SET status = 'approved'").
			WillReturnResult(sqlmock.NewResult(1, 1))

		ctx := context.Background()
		err := deps.service.ApproveTimeOff(ctx, requestID, adminID, "Approved")

		assert.NoError(t, err)
	})

	t.Run("AlreadyReviewed", func(t *testing.T) {
		deps.mockDB.ExpectQuery("SELECT (.+) FROM time_off_requests WHERE id").
			WithArgs(requestID).
			WillReturnRows(sqlmock.NewRows([]string{
				"id", "user_id", "leave_type", "start_date", "end_date", "days_count", "reason",
				"status", "reviewed_by", "reviewed_at", "review_note", "created_at", "updated_at",
			}).AddRow(
				requestID, uint64(1), "sick", time.Now(), time.Now().AddDate(0, 0, 1),
				"1.00", "sick", "approved", adminID, time.Now(), "Already approved", time.Now(), time.Now(),
			))

		ctx := context.Background()
		err := deps.service.ApproveTimeOff(ctx, requestID, adminID, "Approved")

		assert.Error(t, err)
	})

	t.Run("NotFound", func(t *testing.T) {
		deps.mockDB.ExpectQuery("SELECT (.+) FROM time_off_requests WHERE id").
			WithArgs(uint64(999)).
			WillReturnError(sql.ErrNoRows)

		ctx := context.Background()
		err := deps.service.ApproveTimeOff(ctx, 999, adminID, "Approved")

		assert.Error(t, err)
	})
}

func TestService_RejectTimeOff(t *testing.T) {
	deps, cleanup := setupServiceTest(t)
	defer cleanup()

	requestID := uint64(1)
	adminID := uint64(2)

	deps.mockDB.ExpectQuery("SELECT (.+) FROM time_off_requests WHERE id").
		WithArgs(requestID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "user_id", "leave_type", "start_date", "end_date", "days_count", "reason",
			"status", "reviewed_by", "reviewed_at", "review_note", "created_at", "updated_at",
		}).AddRow(
			requestID, uint64(1), "sick", time.Now(), time.Now().AddDate(0, 0, 1),
			"1.00", "sick", "pending", nil, nil, nil, time.Now(), time.Now(),
		))

	deps.mockDB.ExpectExec("UPDATE time_off_requests SET status = 'rejected'").
		WillReturnResult(sqlmock.NewResult(1, 1))

	ctx := context.Background()
	err := deps.service.RejectTimeOff(ctx, requestID, adminID, "Not enough coverage")

	assert.NoError(t, err)
}

func TestService_DailySummary(t *testing.T) {
	deps, cleanup := setupServiceTest(t)
	defer cleanup()

	date := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	t.Run("WithData", func(t *testing.T) {
		deps.mockDB.ExpectQuery("SELECT DATE\\(check_in_at\\)").
			WillReturnRows(sqlmock.NewRows([]string{
				"date", "total_attendance", "present_count", "on_leave_count",
				"absent_count", "late_count", "total_seconds", "total_overtime_seconds",
			}).AddRow(date, int64(10), int64(8), int64(1), int64(1), int64(2), int64(288000), int64(3600)))

		ctx := context.Background()
		summary, err := deps.service.DailySummary(ctx, date)

		assert.NoError(t, err)
		assert.NotNil(t, summary)
		assert.Equal(t, 10, summary.TotalAttendance)
		assert.Equal(t, 8, summary.PresentCount)
		assert.Equal(t, 80.0, summary.TotalHours)        // 288000 seconds = 80 hours
		assert.Equal(t, 1.0, summary.TotalOvertimeHours) // 3600 seconds = 1 hour
	})

	t.Run("NoData", func(t *testing.T) {
		deps.mockDB.ExpectQuery("SELECT DATE\\(check_in_at\\)").
			WillReturnError(sql.ErrNoRows)

		ctx := context.Background()
		summary, err := deps.service.DailySummary(ctx, date)

		assert.NoError(t, err)
		assert.NotNil(t, summary)
		assert.Equal(t, 0, summary.TotalAttendance)
	})
}

func TestService_HelperFunctions(t *testing.T) {
	deps, cleanup := setupServiceTest(t)
	defer cleanup()

	t.Run("calculateShiftDuration", func(t *testing.T) {
		start := time.Date(2024, 1, 1, 9, 0, 0, 0, time.UTC)
		end := time.Date(2024, 1, 1, 17, 0, 0, 0, time.UTC)
		breakMinutes := uint32(60)

		duration := deps.service.calculateShiftDuration(start, end, breakMinutes)
		expectedDuration := uint32(8*3600 - 60*60) // 8 hours - 1 hour break = 7 hours
		assert.Equal(t, expectedDuration, duration)
	})

	t.Run("calculateBusinessDays - SingleDay", func(t *testing.T) {
		start := time.Date(2024, 1, 1, 9, 0, 0, 0, time.UTC)
		end := time.Date(2024, 1, 1, 17, 0, 0, 0, time.UTC)
		days := calculateBusinessDays(start, end)
		assert.Equal(t, 1.0, days)
	})

	t.Run("calculateBusinessDays - MultipleDays", func(t *testing.T) {
		start := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
		end := time.Date(2024, 1, 5, 0, 0, 0, 0, time.UTC)
		days := calculateBusinessDays(start, end)
		assert.True(t, days >= 4.0) // At least 4 business days (excluding weekends)
	})

	t.Run("calculateBusinessDays - InvalidRange", func(t *testing.T) {
		start := time.Date(2024, 1, 5, 0, 0, 0, 0, time.UTC)
		end := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
		days := calculateBusinessDays(start, end)
		assert.Equal(t, 0.0, days)
	})

	t.Run("toAttendanceResponse", func(t *testing.T) {
		mockLat := "40.7128"
		mockLng := "-74.0060"
		record := sqlc.AttendanceRecord{
			ID:           1,
			UserID:       1,
			ShiftID:      sql.NullInt64{Int64: 1, Valid: true},
			CheckInAt:    time.Now(),
			CheckOutAt:   sql.NullTime{Time: time.Now(), Valid: true},
			CheckInLat:   sql.NullString{String: mockLat, Valid: true},
			CheckInLng:   sql.NullString{String: mockLng, Valid: true},
			Status:       "present",
			IsLate:       false,
			IsEarlyLeave: false,
		}

		response := deps.service.toAttendanceResponse(record)
		assert.NotNil(t, response)
		assert.Equal(t, uint64(1), response.ID)
		assert.NotNil(t, response.ShiftID)
		assert.NotNil(t, response.CheckOutAt)
		assert.NotNil(t, response.CheckInLatitude)
		assert.Equal(t, 40.7128, *response.CheckInLatitude)
	})
}

func TestService_CheckIn_DatabaseErrors(t *testing.T) {
	deps, cleanup := setupServiceTest(t)
	defer cleanup()

	userID := uint64(1)
	lockKey := fmt.Sprintf("checkin_lock_%d", userID)

	t.Run("LockAcquisitionError", func(t *testing.T) {
		deps.mockDB.ExpectExec("SELECT GET_LOCK").
			WithArgs(lockKey).
			WillReturnError(fmt.Errorf("connection failed"))

		ctx := context.Background()
		_, err := deps.service.CheckIn(ctx, userID, CheckInRequest{})

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Failed to acquire lock")
	})

	t.Run("ExistingSessionCheckError", func(t *testing.T) {
		deps.mockDB.ExpectExec("SELECT GET_LOCK").WithArgs(lockKey).WillReturnResult(sqlmock.NewResult(1, 1))
		deps.mockDB.ExpectQuery("SELECT (.+) FROM attendance_records WHERE user_id").
			WithArgs(userID).
			WillReturnError(fmt.Errorf("database error"))
		deps.mockDB.ExpectExec("SELECT RELEASE_LOCK").WithArgs(lockKey).WillReturnResult(sqlmock.NewResult(1, 1))

		ctx := context.Background()
		_, err := deps.service.CheckIn(ctx, userID, CheckInRequest{})

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Failed to check existing sessions")
	})

	t.Run("CreateAttendanceError", func(t *testing.T) {
		deps.mockDB.ExpectExec("SELECT GET_LOCK").WithArgs(lockKey).WillReturnResult(sqlmock.NewResult(1, 1))
		deps.mockDB.ExpectQuery("SELECT (.+) FROM attendance_records WHERE user_id").WithArgs(userID).WillReturnError(sql.ErrNoRows)
		deps.mockDB.ExpectQuery("SELECT (.+) FROM employee_shifts").WillReturnError(sql.ErrNoRows)
		deps.mockDB.ExpectExec("INSERT INTO attendance_records").WillReturnError(fmt.Errorf("insert failed"))
		deps.mockDB.ExpectExec("SELECT RELEASE_LOCK").WithArgs(lockKey).WillReturnResult(sqlmock.NewResult(1, 1))

		ctx := context.Background()
		_, err := deps.service.CheckIn(ctx, userID, CheckInRequest{})

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Failed to create attendance record")
	})

	t.Run("FetchCreatedRecordError", func(t *testing.T) {
		deps.mockDB.ExpectExec("SELECT GET_LOCK").WithArgs(lockKey).WillReturnResult(sqlmock.NewResult(1, 1))
		deps.mockDB.ExpectQuery("SELECT (.+) FROM attendance_records WHERE user_id").WithArgs(userID).WillReturnError(sql.ErrNoRows)
		deps.mockDB.ExpectQuery("SELECT (.+) FROM employee_shifts").WillReturnError(sql.ErrNoRows)
		deps.mockDB.ExpectExec("INSERT INTO attendance_records").WillReturnResult(sqlmock.NewResult(1, 1))
		deps.mockDB.ExpectQuery("SELECT (.+) FROM attendance_records WHERE id").WithArgs(uint64(1)).WillReturnError(fmt.Errorf("fetch failed"))
		deps.mockDB.ExpectExec("SELECT RELEASE_LOCK").WithArgs(lockKey).WillReturnResult(sqlmock.NewResult(1, 1))

		ctx := context.Background()
		_, err := deps.service.CheckIn(ctx, userID, CheckInRequest{})

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Failed to fetch created attendance")
	})
}

func TestService_CheckOut_DatabaseErrors(t *testing.T) {
	deps, cleanup := setupServiceTest(t)
	defer cleanup()

	userID := uint64(1)
	attendanceID := uint64(1)
	checkInTime := time.Now().Add(-8 * time.Hour)

	t.Run("FetchSessionError", func(t *testing.T) {
		deps.mockDB.ExpectQuery("SELECT (.+) FROM attendance_records WHERE user_id").
			WithArgs(userID).
			WillReturnError(fmt.Errorf("database error"))

		ctx := context.Background()
		_, err := deps.service.CheckOut(ctx, userID, CheckOutRequest{})

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Failed to find open session")
	})

	t.Run("SpecificAttendanceNotFound", func(t *testing.T) {
		specificID := uint64(999)
		deps.mockDB.ExpectQuery("SELECT (.+) FROM attendance_records WHERE id").
			WithArgs(specificID).
			WillReturnError(sql.ErrNoRows)

		ctx := context.Background()
		_, err := deps.service.CheckOut(ctx, userID, CheckOutRequest{AttendanceID: &specificID})

		assert.Error(t, err)
		assert.Equal(t, ErrSessionNotFound, err)
	})

	t.Run("UnauthorizedAccess", func(t *testing.T) {
		otherUserID := uint64(2)
		deps.mockDB.ExpectQuery("SELECT (.+) FROM attendance_records WHERE user_id").
			WithArgs(otherUserID).
			WillReturnRows(sqlmock.NewRows([]string{
				"id", "user_id", "shift_id", "check_in_at", "check_out_at", "duration_seconds",
				"overtime_seconds", "status", "check_in_lat", "check_in_lng", "check_out_lat", "check_out_lng",
				"client_check_in_at", "client_check_out_at", "is_late", "is_early_leave", "created_at", "updated_at",
			}).AddRow(
				attendanceID, userID, nil, checkInTime, nil, nil,
				0, "present", nil, nil, nil, nil, nil, nil, false, false, time.Now(), time.Now(),
			))

		ctx := context.Background()
		_, err := deps.service.CheckOut(ctx, otherUserID, CheckOutRequest{})

		assert.Error(t, err)
	})

	t.Run("UpdateError", func(t *testing.T) {
		deps.mockDB.ExpectQuery("SELECT (.+) FROM attendance_records WHERE user_id").
			WithArgs(userID).
			WillReturnRows(sqlmock.NewRows([]string{
				"id", "user_id", "shift_id", "check_in_at", "check_out_at", "duration_seconds",
				"overtime_seconds", "status", "check_in_lat", "check_in_lng", "check_out_lat", "check_out_lng",
				"client_check_in_at", "client_check_out_at", "is_late", "is_early_leave", "created_at", "updated_at",
			}).AddRow(
				attendanceID, userID, nil, checkInTime, nil, nil,
				0, "present", nil, nil, nil, nil, nil, nil, false, false, time.Now(), time.Now(),
			))

		deps.mockDB.ExpectExec("UPDATE attendance_records SET check_out_at").
			WillReturnError(fmt.Errorf("update failed"))

		ctx := context.Background()
		_, err := deps.service.CheckOut(ctx, userID, CheckOutRequest{})

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Failed to update attendance")
	})

	t.Run("ShiftFetchError", func(t *testing.T) {
		shiftID := uint64(1)
		deps.mockDB.ExpectQuery("SELECT (.+) FROM attendance_records WHERE user_id").
			WithArgs(userID).
			WillReturnRows(sqlmock.NewRows([]string{
				"id", "user_id", "shift_id", "check_in_at", "check_out_at", "duration_seconds",
				"overtime_seconds", "status", "check_in_lat", "check_in_lng", "check_out_lat", "check_out_lng",
				"client_check_in_at", "client_check_out_at", "is_late", "is_early_leave", "created_at", "updated_at",
			}).AddRow(
				attendanceID, userID, sql.NullInt64{Int64: int64(shiftID), Valid: true}, checkInTime, nil, nil,
				0, "present", nil, nil, nil, nil, nil, nil, false, false, time.Now(), time.Now(),
			))

		deps.mockDB.ExpectQuery("SELECT (.+) FROM shifts WHERE id").
			WithArgs(shiftID).
			WillReturnError(fmt.Errorf("shift not found"))

		deps.mockDB.ExpectExec("UPDATE attendance_records SET check_out_at").
			WillReturnResult(sqlmock.NewResult(1, 1))

		deps.mockDB.ExpectQuery("SELECT (.+) FROM attendance_records WHERE id").
			WithArgs(attendanceID).
			WillReturnRows(sqlmock.NewRows([]string{
				"id", "user_id", "shift_id", "check_in_at", "check_out_at", "duration_seconds",
				"overtime_seconds", "status", "check_in_lat", "check_in_lng", "check_out_lat", "check_out_lng",
				"client_check_in_at", "client_check_out_at", "is_late", "is_early_leave", "created_at", "updated_at",
			}).AddRow(
				attendanceID, userID, sql.NullInt64{Int64: int64(shiftID), Valid: true}, checkInTime, time.Now(), 28800,
				0, "present", nil, nil, nil, nil, nil, nil, false, false, time.Now(), time.Now(),
			))

		ctx := context.Background()
		result, err := deps.service.CheckOut(ctx, userID, CheckOutRequest{})

		assert.NoError(t, err) // Should succeed even if shift fetch fails
		assert.NotNil(t, result)
	})
}

func TestService_ListAttendance_DatabaseErrors(t *testing.T) {
	deps, cleanup := setupServiceTest(t)
	defer cleanup()

	t.Run("CountError", func(t *testing.T) {
		deps.mockDB.ExpectQuery("SELECT COUNT").
			WillReturnError(fmt.Errorf("count failed"))

		ctx := context.Background()
		req := ListAttendanceRequest{Limit: 20, Page: 1}
		_, err := deps.service.ListAttendance(ctx, req)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Failed to count attendance")
	})

	t.Run("ListError", func(t *testing.T) {
		deps.mockDB.ExpectQuery("SELECT COUNT").
			WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(10))

		deps.mockDB.ExpectQuery("SELECT (.+) FROM attendance_records").
			WillReturnError(fmt.Errorf("list failed"))

		ctx := context.Background()
		req := ListAttendanceRequest{Limit: 20, Page: 1}
		_, err := deps.service.ListAttendance(ctx, req)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Failed to list attendance")
	})
}

func TestService_GetLeaveBalance_DatabaseError(t *testing.T) {
	deps, cleanup := setupServiceTest(t)
	defer cleanup()

	userID := uint64(1)

	deps.mockDB.ExpectQuery("SELECT (.+) FROM leave_accruals").
		WillReturnError(fmt.Errorf("database error"))

	ctx := context.Background()
	_, err := deps.service.GetLeaveBalance(ctx, userID, "sick")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Failed to fetch leave balance")
}

func TestService_RequestTimeOff_InvalidDates(t *testing.T) {
	deps, cleanup := setupServiceTest(t)
	defer cleanup()

	userID := uint64(1)
	ctx := context.Background()

	t.Run("InvalidStartDate", func(t *testing.T) {
		req := TimeOffRequest{
			LeaveType: "sick",
			StartDate: "invalid-date",
			EndDate:   "2024-01-02",
			Reason:    "Need time off",
		}

		_, err := deps.service.RequestTimeOff(ctx, userID, req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Invalid start date format")
	})

	t.Run("InvalidEndDate", func(t *testing.T) {
		req := TimeOffRequest{
			LeaveType: "sick",
			StartDate: "2024-01-01",
			EndDate:   "invalid-date",
			Reason:    "Need time off",
		}

		_, err := deps.service.RequestTimeOff(ctx, userID, req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Invalid end date format")
	})

	t.Run("DatabaseInsertError", func(t *testing.T) {
		deps.mockDB.ExpectExec("INSERT INTO time_off_requests").
			WillReturnError(fmt.Errorf("insert failed"))

		req := TimeOffRequest{
			LeaveType: "sick",
			StartDate: "2024-01-01",
			EndDate:   "2024-01-02",
			Reason:    "Need time off",
		}

		_, err := deps.service.RequestTimeOff(ctx, userID, req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Failed to create time off request")
	})
}

func TestService_DailySummary_DatabaseError(t *testing.T) {
	deps, cleanup := setupServiceTest(t)
	defer cleanup()

	date := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	deps.mockDB.ExpectQuery("SELECT DATE\\(check_in_at\\)").
		WillReturnError(fmt.Errorf("database error"))

	ctx := context.Background()
	_, err := deps.service.DailySummary(ctx, date)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Failed to fetch daily summary")
}

func TestService_ExportTimesheetForPeriod_Success(t *testing.T) {
	deps, cleanup := setupServiceTest(t)
	defer cleanup()

	employeeID := uint64(1)
	startDate := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	endDate := time.Date(2024, 1, 31, 23, 59, 59, 0, time.UTC)

	deps.mockDB.ExpectQuery("SELECT (.+) FROM attendance_records ar JOIN users").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "user_id", "email", "first_name", "last_name", "work_date",
			"check_in_at", "check_out_at", "duration_seconds", "overtime_seconds",
			"shift_id", "shift_name", "status", "is_late", "is_early_leave",
		}).AddRow(
			1, employeeID, "emp@test.com", "John", "Doe", startDate,
			startDate, startDate.Add(8*time.Hour), 28800, 0, nil, nil, "present", false, false,
		))

	ctx := context.Background()
	result, err := deps.service.ExportTimesheetForPeriod(ctx, employeeID, startDate, endDate)

	assert.NoError(t, err)
	assert.Len(t, result, 1)
}

// Fail
func TestService_AutoCheckoutStaleSessions_Error(t *testing.T) {
	deps, cleanup := setupServiceTest(t)
	defer cleanup()

	deps.mockDB.ExpectExec("UPDATE attendance_records SET check_out_at").
		WillReturnError(fmt.Errorf("update failed"))

	ctx := context.Background()
	_, err := deps.service.AutoCheckoutStaleSessions(ctx, 24)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Failed to auto-close stale sessions")
}

func TestService_CheckOut_FetchUpdatedRecordError(t *testing.T) {
	deps, cleanup := setupServiceTest(t)
	defer cleanup()

	userID := uint64(1)
	attendanceID := uint64(1)
	checkInTime := time.Now().Add(-8 * time.Hour)

	deps.mockDB.ExpectQuery("SELECT (.+) FROM attendance_records WHERE user_id").
		WithArgs(userID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "user_id", "shift_id", "check_in_at", "check_out_at", "duration_seconds",
			"overtime_seconds", "status", "check_in_lat", "check_in_lng", "check_out_lat", "check_out_lng",
			"client_check_in_at", "client_check_out_at", "is_late", "is_early_leave", "created_at", "updated_at",
		}).AddRow(
			attendanceID, userID, nil, checkInTime, nil, nil,
			0, "present", nil, nil, nil, nil, nil, nil, false, false, time.Now(), time.Now(),
		))

	deps.mockDB.ExpectExec("UPDATE attendance_records SET check_out_at").
		WillReturnResult(sqlmock.NewResult(1, 1))

	deps.mockDB.ExpectQuery("SELECT (.+) FROM attendance_records WHERE id").
		WithArgs(attendanceID).
		WillReturnError(fmt.Errorf("fetch failed"))

	ctx := context.Background()
	// Even if final fetch fails, checkout should succeed (it updates the DB)
	result, err := deps.service.CheckOut(ctx, userID, CheckOutRequest{})

	// This will fail because we can't fetch the updated record
	assert.Error(t, err)
	assert.Nil(t, result)
}

func TestService_SpecificAttendanceID_Fetch(t *testing.T) {
	deps, cleanup := setupServiceTest(t)
	defer cleanup()

	userID := uint64(1)
	specificID := uint64(5)
	checkInTime := time.Now().Add(-8 * time.Hour)

	deps.mockDB.ExpectQuery("SELECT (.+) FROM attendance_records WHERE id").
		WithArgs(specificID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "user_id", "shift_id", "check_in_at", "check_out_at", "duration_seconds",
			"overtime_seconds", "status", "check_in_lat", "check_in_lng", "check_out_lat", "check_out_lng",
			"client_check_in_at", "client_check_out_at", "is_late", "is_early_leave", "created_at", "updated_at",
		}).AddRow(
			specificID, userID, nil, checkInTime, nil, nil,
			0, "present", nil, nil, nil, nil, nil, nil, false, false, time.Now(), time.Now(),
		))

	deps.mockDB.ExpectExec("UPDATE attendance_records SET check_out_at").
		WillReturnResult(sqlmock.NewResult(1, 1))

	deps.mockDB.ExpectQuery("SELECT (.+) FROM attendance_records WHERE id").
		WithArgs(specificID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "user_id", "shift_id", "check_in_at", "check_out_at", "duration_seconds",
			"overtime_seconds", "status", "check_in_lat", "check_in_lng", "check_out_lat", "check_out_lng",
			"client_check_in_at", "client_check_out_at", "is_late", "is_early_leave", "created_at", "updated_at",
		}).AddRow(
			specificID, userID, nil, checkInTime, time.Now(), 28800,
			0, "present", nil, nil, nil, nil, nil, nil, false, false, time.Now(), time.Now(),
		))

	ctx := context.Background()
	result, err := deps.service.CheckOut(ctx, userID, CheckOutRequest{AttendanceID: &specificID})

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, specificID, result.ID)
}

func TestService_CheckOut_SpecificAttendanceFetchError(t *testing.T) {
	deps, cleanup := setupServiceTest(t)
	defer cleanup()

	userID := uint64(1)
	specificID := uint64(5)

	deps.mockDB.ExpectQuery("SELECT (.+) FROM attendance_records WHERE id").
		WithArgs(specificID).
		WillReturnError(fmt.Errorf("fetch error"))

	ctx := context.Background()
	_, err := deps.service.CheckOut(ctx, userID, CheckOutRequest{AttendanceID: &specificID})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Failed to fetch attendance")
}

func TestConvertToFloat_EdgeCases(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expectErr bool
	}{
		{"Valid", "123.45", false},
		{"Empty", "", false},
		{"Invalid", "abc", true},
		{"Integer", "123", false},
		{"Negative", "-45.67", false},
		{"Zero", "0", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := convertToFloat(tt.input)
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
