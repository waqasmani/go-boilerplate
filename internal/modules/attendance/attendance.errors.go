package attendance

import "github.com/waqasmani/go-boilerplate/internal/shared/errors"

// Domain-specific attendance errors
var (
	// Check-in/out errors
	ErrOpenSessionExists = errors.New(errors.ErrCodeConflict, "An open attendance session already exists. Please check out first")
	ErrNoOpenSession     = errors.New(errors.ErrCodeBadRequest, "No open attendance session found")
	ErrSessionNotFound   = errors.New(errors.ErrCodeNotFound, "Attendance session not found")
	ErrAlreadyCheckedOut = errors.New(errors.ErrCodeBadRequest, "This session has already been checked out")

	// Time validation errors
	ErrTimeSkewTooLarge = errors.New(errors.ErrCodeBadRequest, "Client timestamp differs from server time by more than allowed tolerance")
	ErrCheckOutBeforeIn = errors.New(errors.ErrCodeBadRequest, "Check-out time cannot be before check-in time")
	ErrInvalidDateRange = errors.New(errors.ErrCodeValidation, "Invalid date range: end date must be after start date")
	ErrFutureDate       = errors.New(errors.ErrCodeBadRequest, "Cannot check in/out with future timestamps")

	// Geofence errors
	ErrGeofenceViolation = errors.New(errors.ErrCodeForbidden, "Location outside allowed geofence area")
	ErrLocationRequired  = errors.New(errors.ErrCodeBadRequest, "Location coordinates are required when geofence is enabled")

	// Shift errors
	ErrShiftNotFound    = errors.New(errors.ErrCodeNotFound, "Shift not found")
	ErrNoShiftAssigned  = errors.New(errors.ErrCodeNotFound, "No shift assigned for this date")
	ErrShiftOverlap     = errors.New(errors.ErrCodeConflict, "Shift assignment overlaps with existing assignment")
	ErrInvalidShiftTime = errors.New(errors.ErrCodeValidation, "Invalid shift time: end time must be after start time")

	// Time off errors
	ErrTimeOffNotFound          = errors.New(errors.ErrCodeNotFound, "Time off request not found")
	ErrTimeOffAlreadyReviewed   = errors.New(errors.ErrCodeConflict, "Time off request has already been reviewed")
	ErrInsufficientLeaveBalance = errors.New(errors.ErrCodeBadRequest, "Insufficient leave balance for this request")
	ErrTimeOffOverlap           = errors.New(errors.ErrCodeConflict, "Time off request overlaps with existing approved leave")

	// Authorization errors
	ErrUnauthorizedShiftEdit   = errors.New(errors.ErrCodeForbidden, "Only managers can modify shift assignments")
	ErrUnauthorizedApproval    = errors.New(errors.ErrCodeForbidden, "Only managers can approve time off requests")
	ErrCannotApproveOwnRequest = errors.New(errors.ErrCodeForbidden, "Cannot approve your own time off request")

	// Holiday errors
	ErrHolidayNotFound = errors.New(errors.ErrCodeNotFound, "Holiday not found")
	ErrHolidayExists   = errors.New(errors.ErrCodeConflict, "A holiday already exists for this date")

	// Report errors
	ErrInvalidReportPeriod = errors.New(errors.ErrCodeBadRequest, "Invalid report period: must not exceed 90 days")
	ErrNoDataForPeriod     = errors.New(errors.ErrCodeNotFound, "No attendance data found for specified period")
)

// WrapAttendanceError wraps a generic error with context
func WrapAttendanceError(err error, message string) *errors.AppError {
	return errors.Wrap(err, errors.ErrCodeInternal, message)
}

// ValidationError creates a validation error with details
func ValidationError(field, message string) *errors.AppError {
	return errors.WithDetails(
		errors.ErrCodeValidation,
		"Validation failed",
		map[string]string{field: message},
	)
}
