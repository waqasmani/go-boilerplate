package attendance

import (
	"database/sql"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/waqasmani/go-boilerplate/internal/infrastructure/middleware"
	"github.com/waqasmani/go-boilerplate/internal/infrastructure/observability"
	"github.com/waqasmani/go-boilerplate/internal/infrastructure/sqlc"
	"github.com/waqasmani/go-boilerplate/internal/shared/errors"
	"github.com/waqasmani/go-boilerplate/internal/shared/utils"
	"github.com/waqasmani/go-boilerplate/internal/shared/validator"
)

// Handler handles HTTP requests for attendance
type Handler struct {
	service *Service
}

// NewHandler creates a new attendance handler
func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

// CheckIn godoc
// @Summary Check in to work
// @Description Records employee check-in with optional geolocation
// @Tags Attendance
// @Accept json
// @Produce json
// @Param body body CheckInRequest true "Check-in details"
// @Success 201 {object} utils.Response{data=AttendanceResponse}
// @Failure 400 {object} utils.Response
// @Failure 401 {object} utils.Response
// @Failure 409 {object} utils.Response
// @Security     Bearer
// @Router /attendance/check-in [post]
func (h *Handler) CheckIn(c *gin.Context) {
	userID, err := middleware.GetCurrentUserID(c)
	if err != nil {
		utils.Error(c, err)
		return
	}

	var req CheckInRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.Error(c, errors.Wrap(err, errors.ErrCodeBadRequest, "Invalid request body"))
		return
	}

	// Add this validation block
	if err := h.service.validator.Validate(req); err != nil {
		validationErrors := validator.TranslateValidationErrors(err)
		utils.Error(c, errors.WithDetails(errors.ErrCodeValidation, "Validation failed", validationErrors))
		return
	}

	attendance, err := h.service.CheckIn(c.Request.Context(), userID, req)
	if err != nil {
		utils.Error(c, err)
		return
	}

	utils.Success(c, http.StatusCreated, attendance)
}

// CheckOut godoc
// @Summary Check out from work
// @Description Records employee check-out and calculates duration
// @Tags Attendance
// @Accept json
// @Produce json
// @Param body body CheckOutRequest true "Check-out details"
// @Success 200 {object} utils.Response{data=AttendanceResponse}
// @Failure 400 {object} utils.Response
// @Failure 401 {object} utils.Response
// @Failure 404 {object} utils.Response
// @Security     Bearer
// @Router /attendance/check-out [post]
func (h *Handler) CheckOut(c *gin.Context) {
	userID, err := middleware.GetCurrentUserID(c)
	if err != nil {
		utils.Error(c, err)
		return
	}

	var req CheckOutRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.Error(c, errors.Wrap(err, errors.ErrCodeBadRequest, "Invalid request body"))
		return
	}

	// Add this validation block
	if err := h.service.validator.Validate(req); err != nil {
		validationErrors := validator.TranslateValidationErrors(err)
		utils.Error(c, errors.WithDetails(errors.ErrCodeValidation, "Validation failed", validationErrors))
		return
	}

	attendance, err := h.service.CheckOut(c.Request.Context(), userID, req)
	if err != nil {
		utils.Error(c, err)
		return
	}

	utils.Success(c, http.StatusOK, attendance)
}

// ListAttendance godoc
// @Summary List attendance records
// @Description Retrieves attendance records with pagination and filters
// @Tags Attendance
// @Accept json
// @Produce json
// @Param user_id query int false "User ID filter"
// @Param from query string false "Start date (RFC3339)"
// @Param to query string false "End date (RFC3339)"
// @Param status query string false "Status filter" Enums(present, on_leave, absent, manual)
// @Param shift_id query int false "Shift ID filter"
// @Param limit query int false "Page size" default(20) minimum(1) maximum(100)
// @Param page query int false "Page number" default(1) minimum(1)
// @Success 200 {object} utils.Response{data=ListAttendanceResponse}
// @Failure 400 {object} utils.Response
// @Failure 401 {object} utils.Response
// @Security     Bearer
// @Router /attendance [get]
func (h *Handler) ListAttendance(c *gin.Context) {
	var req ListAttendanceRequest
	if err := c.ShouldBindQuery(&req); err != nil {
		utils.Error(c, errors.Wrap(err, errors.ErrCodeBadRequest, "Invalid query parameters"))
		return
	}

	if err := h.service.validator.Validate(req); err != nil {
		validationErrors := validator.TranslateValidationErrors(err)
		utils.Error(c, errors.WithDetails(errors.ErrCodeValidation, "Validation failed", validationErrors))
		return
	}

	result, err := h.service.ListAttendance(c.Request.Context(), req)
	if err != nil {
		utils.Error(c, err)
		return
	}

	utils.Success(c, http.StatusOK, result)
}

// GetAttendance godoc
// @Summary Get attendance by ID
// @Description Retrieves a single attendance record by ID
// @Tags Attendance
// @Accept json
// @Produce json
// @Param id path int true "Attendance ID"
// @Success 200 {object} utils.Response{data=AttendanceResponse}
// @Failure 401 {object} utils.Response
// @Failure 404 {object} utils.Response
// @Security     Bearer
// @Router /attendance/{id} [get]
func (h *Handler) GetAttendance(c *gin.Context) {
	attendanceID, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		utils.Error(c, errors.New(errors.ErrCodeBadRequest, "Invalid attendance ID"))
		return
	}

	attendance, err := h.service.queries.GetAttendanceByID(c.Request.Context(), attendanceID)
	if err != nil {
		utils.Error(c, ErrSessionNotFound)
		return
	}

	// Authorization: user can only view own records unless admin/manager
	userID, _ := middleware.GetCurrentUserID(c)
	if attendance.UserID != userID && !middleware.IsAdmin(c) {
		utils.Error(c, errors.ErrForbidden)
		return
	}

	utils.Success(c, http.StatusOK, h.service.toAttendanceResponse(attendance))
}

// ManualAttendance godoc
// @Summary Manually edit attendance (Admin/Manager only)
// @Description Allows managers to manually create or edit attendance records
// @Tags Attendance
// @Accept json
// @Produce json
// @Param id path int true "Attendance ID (0 for new)"
// @Param body body ManualAttendanceRequest true "Manual attendance data"
// @Success 200 {object} utils.Response{data=AttendanceResponse}
// @Failure 400 {object} utils.Response
// @Failure 401 {object} utils.Response
// @Failure 403 {object} utils.Response
// @Security     Bearer
// @Router /attendance/{id}/manual [put]
func (h *Handler) ManualAttendance(c *gin.Context) {
	attendanceID, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		utils.Error(c, errors.New(errors.ErrCodeBadRequest, "Invalid attendance ID"))
		return
	}

	var req ManualAttendanceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.Error(c, errors.Wrap(err, errors.ErrCodeBadRequest, "Invalid request body"))
		return
	}

	if err := h.service.validator.Validate(req); err != nil {
		validationErrors := validator.TranslateValidationErrors(err)
		utils.Error(c, errors.WithDetails(errors.ErrCodeValidation, "Validation failed", validationErrors))
		return
	}

	duration := uint32(req.CheckOutAt.Sub(req.CheckInAt).Seconds())
	overtime := uint32(0)
	if req.OvertimeSeconds != nil {
		overtime = *req.OvertimeSeconds
	}

	err = h.service.queries.UpdateAttendanceManual(c.Request.Context(), sqlc.UpdateAttendanceManualParams{
		ID:              attendanceID,
		CheckInAt:       req.CheckInAt,
		CheckOutAt:      sql.NullTime{Valid: true, Time: req.CheckOutAt},
		DurationSeconds: sql.NullInt32{Valid: true, Int32: int32(duration)},
		OvertimeSeconds: sql.NullInt32{Valid: true, Int32: int32(overtime)},
	})
	if err != nil {
		utils.Error(c, WrapAttendanceError(err, "Failed to update attendance"))
		return
	}

	// Add audit note
	managerID, _ := middleware.GetCurrentUserID(c)
	_ = h.service.queries.CreateAttendanceNote(c.Request.Context(), sqlc.CreateAttendanceNoteParams{
		AttendanceID: attendanceID,
		AddedBy:      managerID,
		Note:         fmt.Sprintf("Manual edit: %s", req.Reason),
	})

	// Audit log
	h.service.auditLogger.LogSecurityEvent(c.Request.Context(), observability.SecurityEvent{
		Type:     "attendance",
		Action:   "manual_edit",
		UserID:   managerID,
		Resource: fmt.Sprintf("attendance:%d", attendanceID),
		Success:  true,
	})

	updated, _ := h.service.queries.GetAttendanceByID(c.Request.Context(), attendanceID)
	utils.Success(c, http.StatusOK, h.service.toAttendanceResponse(updated))
}

// GetLeaveBalance godoc
// @Summary Get leave balance
// @Description Retrieves current leave balance for authenticated user
// @Tags Attendance
// @Accept json
// @Produce json
// @Param leave_type query string false "Leave type" Enums(sick, vacation, personal)
// @Success 200 {object} utils.Response{data=[]LeaveBalanceResponse}
// @Failure 401 {object} utils.Response
// @Security     Bearer
// @Router /attendance/leave-balance [get]
func (h *Handler) GetLeaveBalance(c *gin.Context) {
	userID, err := middleware.GetCurrentUserID(c)
	if err != nil {
		utils.Error(c, err)
		return
	}

	leaveType := c.Query("leave_type")
	leaveTypes := []string{"sick", "vacation", "personal"}
	var balances []LeaveBalanceResponse

	if leaveType != "" {
		balance, err := h.service.GetLeaveBalance(c.Request.Context(), userID, leaveType)
		if err != nil {
			utils.Error(c, err)
			return
		}
		balances = append(balances, *balance)
	} else {
		// Return all types
		for _, lt := range leaveTypes {
			balance, err := h.service.GetLeaveBalance(c.Request.Context(), userID, lt)
			if err != nil {
				continue
			}
			balances = append(balances, *balance)
		}
	}

	utils.Success(c, http.StatusOK, balances)
}

// RequestTimeOff godoc
// @Summary Request time off
// @Description Employee submits a time off request
// @Tags Time Off
// @Accept json
// @Produce json
// @Param body body TimeOffRequest true "Time off request"
// @Success 201 {object} utils.Response{data=TimeOffResponse}
// @Failure 400 {object} utils.Response
// @Failure 401 {object} utils.Response
// @Security     Bearer
// @Router /attendance/time-off [post]
func (h *Handler) RequestTimeOff(c *gin.Context) {
	userID, err := middleware.GetCurrentUserID(c)
	if err != nil {
		utils.Error(c, err)
		return
	}

	var req TimeOffRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.Error(c, errors.Wrap(err, errors.ErrCodeBadRequest, "Invalid request body"))
		return
	}

	if err := h.service.validator.Validate(req); err != nil {
		validationErrors := validator.TranslateValidationErrors(err)
		utils.Error(c, errors.WithDetails(errors.ErrCodeValidation, "Validation failed", validationErrors))
		return
	}

	startDate, _ := time.Parse("2006-01-02", req.StartDate)
	endDate, _ := time.Parse("2006-01-02", req.EndDate)
	daysCount := calculateBusinessDays(startDate, endDate)

	result, err := h.service.queries.CreateTimeOffRequest(c.Request.Context(), sqlc.CreateTimeOffRequestParams{
		UserID:    userID,
		LeaveType: req.LeaveType,
		StartDate: startDate,
		EndDate:   endDate,
		DaysCount: fmt.Sprintf("%.2f", daysCount),
		Reason:    sql.NullString{Valid: true, String: req.Reason},
		Status:    "pending",
	})
	if err != nil {
		utils.Error(c, WrapAttendanceError(err, "Failed to create time off request"))
		return
	}

	timeOffID, _ := result.LastInsertId()
	utils.Success(c, http.StatusCreated, gin.H{"id": timeOffID, "status": "pending"})
}

// ApproveTimeOff godoc
// @Summary Approve time off (Manager only)
// @Description Manager approves a pending time off request
// @Tags Time Off
// @Accept json
// @Produce json
// @Param id path int true "Time off request ID"
// @Param body body ReviewTimeOffRequest true "Review note"
// @Success 200 {object} utils.Response
// @Failure 401 {object} utils.Response
// @Failure 403 {object} utils.Response
// @Failure 404 {object} utils.Response
// @Security     Bearer
// @Router /attendance/time-off/{id}/approve [patch]
func (h *Handler) ApproveTimeOff(c *gin.Context) {
	timeOffID, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		utils.Error(c, errors.New(errors.ErrCodeBadRequest, "Invalid time off ID"))
		return
	}

	managerID, _ := middleware.GetCurrentUserID(c)

	var req ReviewTimeOffRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.Error(c, errors.Wrap(err, errors.ErrCodeBadRequest, "Invalid request body"))
		return
	}

	err = h.service.ApproveTimeOff(c.Request.Context(), timeOffID, managerID, req.ReviewNote)
	if err != nil {
		utils.Error(c, WrapAttendanceError(err, "Failed to approve time off"))
		return
	}

	h.service.auditLogger.LogSecurityEvent(c.Request.Context(), observability.SecurityEvent{
		Type:     "time_off",
		Action:   "approve",
		UserID:   managerID,
		Resource: fmt.Sprintf("time_off:%d", timeOffID),
		Success:  true,
	})

	utils.Success(c, http.StatusOK, gin.H{"message": "Time off approved"})
}

// RejectTimeOff godoc
// @Summary Reject time off (Manager only)
// @Description Manager rejects a pending time off request
// @Tags Time Off
// @Accept json
// @Produce json
// @Param id path int true "Time off request ID"
// @Param body body ReviewTimeOffRequest true "Review note"
// @Success 200 {object} utils.Response
// @Failure 401 {object} utils.Response
// @Failure 403 {object} utils.Response
// @Failure 404 {object} utils.Response
// @Security     Bearer
// @Router /attendance/time-off/{id}/reject [patch]
func (h *Handler) RejectTimeOff(c *gin.Context) {
	timeOffID, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		utils.Error(c, errors.New(errors.ErrCodeBadRequest, "Invalid time off ID"))
		return
	}

	managerID, _ := middleware.GetCurrentUserID(c)

	var req ReviewTimeOffRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.Error(c, errors.Wrap(err, errors.ErrCodeBadRequest, "Invalid request body"))
		return
	}

	err = h.service.RejectTimeOff(c.Request.Context(), timeOffID, managerID, req.ReviewNote)
	if err != nil {
		utils.Error(c, WrapAttendanceError(err, "Failed to reject time off"))
		return
	}

	h.service.auditLogger.LogSecurityEvent(c.Request.Context(), observability.SecurityEvent{
		Type:     "time_off",
		Action:   "reject",
		UserID:   managerID,
		Resource: fmt.Sprintf("time_off:%d", timeOffID),
		Success:  true,
	})

	utils.Success(c, http.StatusOK, gin.H{"message": "Time off rejected"})
}

// DailySummary godoc
// @Summary Get daily attendance summary
// @Description Retrieves attendance summary for a specific date
// @Tags Reports
// @Accept json
// @Produce json
// @Param date query string true "Date (YYYY-MM-DD format)"
// @Success 200 {object} utils.Response{data=DailySummaryResponse}
// @Failure 400 {object} utils.Response
// @Failure 401 {object} utils.Response
// @Failure 404 {object} utils.Response
// @Security     Bearer
// @Router /reports/daily-summary [get]
func (h *Handler) DailySummary(c *gin.Context) {
	dateStr := c.Query("date")
	if dateStr == "" {
		utils.Error(c, errors.New(errors.ErrCodeBadRequest, "Date parameter is required"))
		return
	}

	date, err := time.Parse("2006-01-02", dateStr)
	if err != nil {
		utils.Error(c, errors.New(errors.ErrCodeBadRequest, "Invalid date format. Use YYYY-MM-DD format"))
		return
	}

	summary, err := h.service.DailySummary(c.Request.Context(), date)
	if err != nil {
		utils.Error(c, err)
		return
	}

	utils.Success(c, http.StatusOK, summary)
}

// ExportEmployee godoc
// @Summary Export employee timesheet
// @Description Exports timesheet data for an employee for a specific period
// @Tags Reports
// @Accept json
// @Param id path int true "Employee ID"
// @Param start_date query string true "Start date (YYYY-MM-DD format)"
// @Param end_date query string true "End date (YYYY-MM-DD format)"
// @Success 200 {file} file "Timesheet CSV file"
// @Failure 400 {object} utils.Response
// @Failure 401 {object} utils.Response
// @Failure 404 {object} utils.Response
// @Security     Bearer
// @Router /reports/employee/{id}/export [get]
func (h *Handler) ExportEmployee(c *gin.Context) {
	employeeID, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		utils.Error(c, errors.New(errors.ErrCodeBadRequest, "Invalid employee ID"))
		return
	}

	startDateStr := c.Query("start_date")
	endDateStr := c.Query("end_date")

	if startDateStr == "" || endDateStr == "" {
		utils.Error(c, errors.New(errors.ErrCodeBadRequest, "Start date and end date parameters are required"))
		return
	}

	startDate, err := time.Parse("2006-01-02", startDateStr)
	if err != nil {
		utils.Error(c, errors.New(errors.ErrCodeBadRequest, "Invalid start date format. Use YYYY-MM-DD format"))
		return
	}

	endDate, err := time.Parse("2006-01-02", endDateStr)
	if err != nil {
		utils.Error(c, errors.New(errors.ErrCodeBadRequest, "Invalid end date format. Use YYYY-MM-DD format"))
		return
	}

	if endDate.Before(startDate) {
		utils.Error(c, errors.New(errors.ErrCodeBadRequest, "End date must be after start date"))
		return
	}

	// Add one day to end date to include the entire last day
	endDate = endDate.AddDate(0, 0, 1)

	// Authorization: user can only export their own data unless admin/manager
	userID, _ := middleware.GetCurrentUserID(c)
	if employeeID != userID && !middleware.IsAdmin(c) {
		utils.Error(c, errors.ErrForbidden)
		return
	}

	timesheet, err := h.service.ExportTimesheetForPeriod(c.Request.Context(), employeeID, startDate, endDate)
	if err != nil {
		utils.Error(c, err)
		return
	}

	// Set headers for CSV download
	c.Header("Content-Type", "text/csv")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=timesheet_%s_%s.csv", startDateStr, endDateStr))

	// Write CSV header
	c.String(http.StatusOK, "Date,Employee,CheckIn,CheckOut,DurationHours,OvertimeHours,Status,Shift\n")

	// Write CSV rows
	for _, record := range timesheet {
		durationHours := 0.0
		if record.DurationSeconds.Valid {
			durationHours = float64(record.DurationSeconds.Int32) / 3600.0
		}

		overtimeHours := 0.0
		if record.OvertimeSeconds.Valid {
			overtimeHours = float64(record.OvertimeSeconds.Int32) / 3600.0
		}

		checkInStr := ""
		if !record.CheckInAt.IsZero() {
			checkInStr = record.CheckInAt.Format("2006-01-02 15:04:05")
		}

		checkOutStr := ""
		if record.CheckOutAt.Valid {
			checkOutStr = record.CheckOutAt.Time.Format("2006-01-02 15:04:05")
		}

		shiftName := ""
		if record.ShiftName.Valid {
			shiftName = record.ShiftName.String
		}

		row := fmt.Sprintf("%s,%s %s,%s,%s,%.2f,%.2f,%s,%s\n",
			record.WorkDate.Format("2006-01-02"),
			record.FirstName,
			record.LastName,
			checkInStr,
			checkOutStr,
			durationHours,
			overtimeHours,
			record.Status,
			shiftName,
		)
		c.Writer.WriteString(row)
	}
}
