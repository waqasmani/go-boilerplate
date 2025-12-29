package attendance

import (
	"time"

	"github.com/waqasmani/go-boilerplate/internal/infrastructure/sqlc"
)

// CheckInRequest represents a check-in request
// @Description Check-in request with optional geolocation
type CheckInRequest struct {
	Latitude        *float64   `json:"latitude,omitempty" validate:"omitempty,latitude"`
	Longitude       *float64   `json:"longitude,omitempty" validate:"omitempty,longitude"`
	ClientTimestamp *time.Time `json:"client_timestamp,omitempty"`
} // @name CheckInRequest

// CheckOutRequest represents a check-out request
// @Description Check-out request with optional geolocation
type CheckOutRequest struct {
	AttendanceID    *uint64    `json:"attendance_id,omitempty"` // Optional: specify which session to close
	Latitude        *float64   `json:"latitude,omitempty" validate:"omitempty,latitude"`
	Longitude       *float64   `json:"longitude,omitempty" validate:"omitempty,longitude"`
	ClientTimestamp *time.Time `json:"client_timestamp,omitempty"`
} // @name CheckOutRequest

// AttendanceResponse represents an attendance record
// @Description Attendance record response
type AttendanceResponse struct {
	ID                uint64     `json:"id"`
	UserID            uint64     `json:"user_id"`
	ShiftID           *uint64    `json:"shift_id,omitempty"`
	CheckInAt         time.Time  `json:"check_in_at"`
	CheckOutAt        *time.Time `json:"check_out_at,omitempty"`
	DurationSeconds   *uint32    `json:"duration_seconds,omitempty"`
	OvertimeSeconds   uint32     `json:"overtime_seconds"`
	Status            string     `json:"status"`
	IsLate            bool       `json:"is_late"`
	IsEarlyLeave      bool       `json:"is_early_leave"`
	CheckInLatitude   *float64   `json:"check_in_latitude,omitempty"`
	CheckInLongitude  *float64   `json:"check_in_longitude,omitempty"`
	CheckOutLatitude  *float64   `json:"check_out_latitude,omitempty"`
	CheckOutLongitude *float64   `json:"check_out_longitude,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
} // @name AttendanceResponse

// ListAttendanceRequest represents filters for listing attendance
type ListAttendanceRequest struct {
	UserID  *uint64    `form:"user_id"`
	From    *time.Time `form:"from"`
	To      *time.Time `form:"to"`
	Status  string     `form:"status" validate:"omitempty,oneof=present on_leave absent manual"`
	ShiftID *uint64    `form:"shift_id"`
	Limit   int        `form:"limit" validate:"min=1,max=100"`
	Page    int        `form:"page" validate:"min=1"`
}

// ListAttendanceResponse paginated response
type ListAttendanceResponse struct {
	Records []AttendanceResponse `json:"records"`
	Total   int64                `json:"total"`
	Page    int                  `json:"page"`
	Limit   int                  `json:"limit"`
} // @name ListAttendanceResponse

// ManualAttendanceRequest for admin manual attendance entry/edit
type ManualAttendanceRequest struct {
	UserID          uint64    `json:"user_id" validate:"required"`
	CheckInAt       time.Time `json:"check_in_at" validate:"required"`
	CheckOutAt      time.Time `json:"check_out_at" validate:"required,gtfield=CheckInAt"`
	Reason          string    `json:"reason" validate:"required,min=10"`
	OvertimeSeconds *uint32   `json:"overtime_seconds,omitempty"`
} // @name ManualAttendanceRequest

// ShiftRequest for creating shifts
type ShiftRequest struct {
	Name         string `json:"name" validate:"required,min=3,max=100"`
	StartTime    string `json:"start_time" validate:"required,datetime=15:04"`
	EndTime      string `json:"end_time" validate:"required,datetime=15:04"`
	BreakMinutes uint32 `json:"break_minutes" validate:"min=0,max=180"`
} // @name ShiftRequest

// ShiftResponse represents a shift
type ShiftResponse struct {
	ID           uint64    `json:"id"`
	Name         string    `json:"name"`
	StartTime    string    `json:"start_time"`
	EndTime      string    `json:"end_time"`
	BreakMinutes uint32    `json:"break_minutes"`
	IsActive     bool      `json:"is_active"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
} // @name ShiftResponse

// AssignShiftRequest assigns shift to employee
type AssignShiftRequest struct {
	UserID        uint64 `json:"user_id" validate:"required"`
	ShiftID       uint64 `json:"shift_id" validate:"required"`
	EffectiveDate string `json:"effective_date" validate:"required,datetime=2006-01-02"`
	EndDate       string `json:"end_date,omitempty" validate:"omitempty,datetime=2006-01-02"`
} // @name AssignShiftRequest

// TimeOffRequest for employee leave request
type TimeOffRequest struct {
	LeaveType sqlc.TimeOffRequestsLeaveType `json:"leave_type" validate:"required,oneof=sick vacation personal unpaid"`
	StartDate string                        `json:"start_date" validate:"required,datetime=2006-01-02"`
	EndDate   string                        `json:"end_date" validate:"required,datetime=2006-01-02"`
	Reason    string                        `json:"reason" validate:"required,min=10"`
} // @name TimeOffRequest

// TimeOffResponse represents a time off request
type TimeOffResponse struct {
	ID         uint64     `json:"id"`
	UserID     uint64     `json:"user_id"`
	LeaveType  string     `json:"leave_type"`
	StartDate  string     `json:"start_date"`
	EndDate    string     `json:"end_date"`
	DaysCount  float64    `json:"days_count"`
	Reason     string     `json:"reason"`
	Status     string     `json:"status"`
	ReviewedBy *uint64    `json:"reviewed_by,omitempty"`
	ReviewedAt *time.Time `json:"reviewed_at,omitempty"`
	ReviewNote *string    `json:"review_note,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
	FirstName  *string    `json:"first_name,omitempty"`
	LastName   *string    `json:"last_name,omitempty"`
	Email      *string    `json:"email,omitempty"`
} // @name TimeOffResponse

// ReviewTimeOffRequest for manager approval/rejection
type ReviewTimeOffRequest struct {
	ReviewNote string `json:"review_note" validate:"required,min=5"`
} // @name ReviewTimeOffRequest

// HolidayRequest for creating holidays
type HolidayRequest struct {
	Name        string `json:"name" validate:"required,min=3"`
	Date        string `json:"date" validate:"required,datetime=2006-01-02"`
	IsPaid      bool   `json:"is_paid"`
	Description string `json:"description,omitempty"`
} // @name HolidayRequest

// HolidayResponse represents a holiday
type HolidayResponse struct {
	ID          uint64    `json:"id"`
	Name        string    `json:"name"`
	Date        string    `json:"date"`
	IsPaid      bool      `json:"is_paid"`
	Description *string   `json:"description,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
} // @name HolidayResponse

// LeaveBalanceResponse represents leave balance
type LeaveBalanceResponse struct {
	LeaveType     string  `json:"leave_type"`
	AccruedDays   float64 `json:"accrued_days"`
	UsedDays      float64 `json:"used_days"`
	CarryoverDays float64 `json:"carryover_days"`
	AvailableDays float64 `json:"available_days"`
	Year          int     `json:"year"`
} // @name LeaveBalanceResponse

// DailySummaryResponse represents daily attendance summary
type DailySummaryResponse struct {
	Date               string  `json:"date"`
	TotalAttendance    int     `json:"total_attendance"`
	PresentCount       int     `json:"present_count"`
	OnLeaveCount       int     `json:"on_leave_count"`
	AbsentCount        int     `json:"absent_count"`
	LateCount          int     `json:"late_count"`
	TotalHours         float64 `json:"total_hours"`
	TotalOvertimeHours float64 `json:"total_overtime_hours"`
} // @name DailySummaryResponse

// EmployeeMonthlySummaryResponse monthly aggregate
type EmployeeMonthlySummaryResponse struct {
	UserID             uint64  `json:"user_id"`
	TotalDays          int     `json:"total_days"`
	TotalHours         float64 `json:"total_hours"`
	TotalOvertimeHours float64 `json:"total_overtime_hours"`
	LateCount          int     `json:"late_count"`
	EarlyLeaveCount    int     `json:"early_leave_count"`
} // @name EmployeeMonthlySummaryResponse
