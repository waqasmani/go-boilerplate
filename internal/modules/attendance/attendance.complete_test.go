package attendance

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/waqasmani/go-boilerplate/internal/infrastructure/sqlc"
	"github.com/waqasmani/go-boilerplate/internal/shared/validator"
)

// ============================================================================
// GEOFENCING AND LOCATION TESTS
// ============================================================================

func TestService_CheckIn_WithLocation(t *testing.T) {
	deps, cleanup := setupServiceTest(t)
	defer cleanup()

	userID := uint64(1)
	lockKey := fmt.Sprintf("checkin_lock_%d", userID)
	latitude := 40.7128
	longitude := -74.0060

	t.Run("ValidLocation", func(t *testing.T) {
		deps.mockDB.ExpectExec("SELECT GET_LOCK").WithArgs(lockKey).WillReturnResult(sqlmock.NewResult(1, 1))
		deps.mockDB.ExpectQuery("SELECT (.+) FROM attendance_records WHERE user_id").WithArgs(userID).WillReturnError(sql.ErrNoRows)
		deps.mockDB.ExpectQuery("SELECT (.+) FROM employee_shifts").WillReturnError(sql.ErrNoRows)
		deps.mockDB.ExpectExec("INSERT INTO attendance_records").WillReturnResult(sqlmock.NewResult(1, 1))
		deps.mockDB.ExpectQuery("SELECT (.+) FROM attendance_records WHERE id").WillReturnRows(
			sqlmock.NewRows([]string{
				"id", "user_id", "shift_id", "check_in_at", "check_out_at", "duration_seconds",
				"overtime_seconds", "status", "check_in_lat", "check_in_lng", "check_out_lat", "check_out_lng",
				"client_check_in_at", "client_check_out_at", "is_late", "is_early_leave", "created_at", "updated_at",
			}).AddRow(1, userID, nil, time.Now(), nil, nil, 0, "present", "40.7128", "-74.0060", nil, nil, nil, nil, false, false, time.Now(), time.Now()),
		)
		deps.mockDB.ExpectExec("SELECT RELEASE_LOCK").WithArgs(lockKey).WillReturnResult(sqlmock.NewResult(1, 1))

		ctx := context.Background()
		result, err := deps.service.CheckIn(ctx, userID, CheckInRequest{
			Latitude:  &latitude,
			Longitude: &longitude,
		})

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.NotNil(t, result.CheckInLatitude)
		assert.NotNil(t, result.CheckInLongitude)
		assert.Equal(t, latitude, *result.CheckInLatitude)
		assert.Equal(t, longitude, *result.CheckInLongitude)
	})
}

func TestService_CheckOut_WithLocation(t *testing.T) {
	deps, cleanup := setupServiceTest(t)
	defer cleanup()

	userID := uint64(1)
	attendanceID := uint64(1)
	checkInTime := time.Now().Add(-8 * time.Hour)
	latitude := 40.7128
	longitude := -74.0060

	deps.mockDB.ExpectQuery("SELECT (.+) FROM attendance_records WHERE user_id").
		WithArgs(userID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "user_id", "shift_id", "check_in_at", "check_out_at", "duration_seconds",
			"overtime_seconds", "status", "check_in_lat", "check_in_lng", "check_out_lat", "check_out_lng",
			"client_check_in_at", "client_check_out_at", "is_late", "is_early_leave", "created_at", "updated_at",
		}).AddRow(
			attendanceID, userID, nil, checkInTime, nil, nil,
			0, "present", "40.7128", "-74.0060", nil, nil, nil, nil, false, false, time.Now(), time.Now(),
		))

	deps.mockDB.ExpectExec("UPDATE attendance_records SET check_out_at").WillReturnResult(sqlmock.NewResult(1, 1))

	deps.mockDB.ExpectQuery("SELECT (.+) FROM attendance_records WHERE id").
		WithArgs(attendanceID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "user_id", "shift_id", "check_in_at", "check_out_at", "duration_seconds",
			"overtime_seconds", "status", "check_in_lat", "check_in_lng", "check_out_lat", "check_out_lng",
			"client_check_in_at", "client_check_out_at", "is_late", "is_early_leave", "created_at", "updated_at",
		}).AddRow(
			attendanceID, userID, nil, checkInTime, time.Now(), 28800,
			0, "present", "40.7128", "-74.0060", "40.7128", "-74.0060", nil, nil, false, false, time.Now(), time.Now(),
		))

	ctx := context.Background()
	result, err := deps.service.CheckOut(ctx, userID, CheckOutRequest{
		Latitude:  &latitude,
		Longitude: &longitude,
	})

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.NotNil(t, result.CheckOutLatitude)
	assert.NotNil(t, result.CheckOutLongitude)
}

// ============================================================================
// CLIENT TIMESTAMP TESTS
// ============================================================================

func TestService_CheckIn_ClientTimestamp(t *testing.T) {
	deps, cleanup := setupServiceTest(t)
	defer cleanup()

	userID := uint64(1)
	lockKey := fmt.Sprintf("checkin_lock_%d", userID)

	t.Run("ValidClientTimestamp", func(t *testing.T) {
		clientTime := time.Now().Add(-1 * time.Minute) // 1 minute in the past

		deps.mockDB.ExpectExec("SELECT GET_LOCK").WithArgs(lockKey).WillReturnResult(sqlmock.NewResult(1, 1))
		deps.mockDB.ExpectQuery("SELECT (.+) FROM attendance_records WHERE user_id").WithArgs(userID).WillReturnError(sql.ErrNoRows)
		deps.mockDB.ExpectQuery("SELECT (.+) FROM employee_shifts").WillReturnError(sql.ErrNoRows)
		deps.mockDB.ExpectExec("INSERT INTO attendance_records").WillReturnResult(sqlmock.NewResult(1, 1))
		deps.mockDB.ExpectQuery("SELECT (.+) FROM attendance_records WHERE id").WillReturnRows(
			sqlmock.NewRows([]string{
				"id", "user_id", "shift_id", "check_in_at", "check_out_at", "duration_seconds",
				"overtime_seconds", "status", "check_in_lat", "check_in_lng", "check_out_lat", "check_out_lng",
				"client_check_in_at", "client_check_out_at", "is_late", "is_early_leave", "created_at", "updated_at",
			}).AddRow(1, userID, nil, time.Now(), nil, nil, 0, "present", nil, nil, nil, nil, clientTime, nil, false, false, time.Now(), time.Now()),
		)
		deps.mockDB.ExpectExec("SELECT RELEASE_LOCK").WithArgs(lockKey).WillReturnResult(sqlmock.NewResult(1, 1))

		ctx := context.Background()
		result, err := deps.service.CheckIn(ctx, userID, CheckInRequest{
			ClientTimestamp: &clientTime,
		})

		assert.NoError(t, err)
		assert.NotNil(t, result)
	})

	t.Run("ClientTimestampTooFarInPast", func(t *testing.T) {
		clientTime := time.Now().Add(-10 * time.Minute) // 10 minutes - exceeds 5 min tolerance

		ctx := context.Background()
		_, err := deps.service.CheckIn(ctx, userID, CheckInRequest{
			ClientTimestamp: &clientTime,
		})

		assert.Error(t, err)
		assert.Equal(t, ErrTimeSkewTooLarge, err)
	})

	t.Run("ClientTimestampTooFarInFuture", func(t *testing.T) {
		clientTime := time.Now().Add(10 * time.Minute) // 10 minutes in future

		ctx := context.Background()
		_, err := deps.service.CheckIn(ctx, userID, CheckInRequest{
			ClientTimestamp: &clientTime,
		})

		assert.Error(t, err)
		assert.Equal(t, ErrTimeSkewTooLarge, err)
	})
}

func TestService_CheckOut_ClientTimestamp(t *testing.T) {
	deps, cleanup := setupServiceTest(t)
	defer cleanup()

	userID := uint64(1)
	attendanceID := uint64(1)
	checkInTime := time.Now().Add(-8 * time.Hour)

	t.Run("ValidClientTimestamp", func(t *testing.T) {
		clientTime := time.Now().Add(-1 * time.Minute)

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

		deps.mockDB.ExpectExec("UPDATE attendance_records SET check_out_at").WillReturnResult(sqlmock.NewResult(1, 1))
		deps.mockDB.ExpectQuery("SELECT (.+) FROM attendance_records WHERE id").
			WithArgs(attendanceID).
			WillReturnRows(sqlmock.NewRows([]string{
				"id", "user_id", "shift_id", "check_in_at", "check_out_at", "duration_seconds",
				"overtime_seconds", "status", "check_in_lat", "check_in_lng", "check_out_lat", "check_out_lng",
				"client_check_in_at", "client_check_out_at", "is_late", "is_early_leave", "created_at", "updated_at",
			}).AddRow(
				attendanceID, userID, nil, checkInTime, time.Now(), 28800,
				0, "present", nil, nil, nil, nil, nil, clientTime, false, false, time.Now(), time.Now(),
			))

		ctx := context.Background()
		result, err := deps.service.CheckOut(ctx, userID, CheckOutRequest{
			ClientTimestamp: &clientTime,
		})

		assert.NoError(t, err)
		assert.NotNil(t, result)
	})
}

// ============================================================================
// SHIFT CALCULATION EDGE CASES
// ============================================================================

func TestService_CalculateShiftDuration_EdgeCases(t *testing.T) {
	deps, cleanup := setupServiceTest(t)
	defer cleanup()

	t.Run("NoBreak", func(t *testing.T) {
		start := time.Date(2024, 1, 1, 9, 0, 0, 0, time.UTC)
		end := time.Date(2024, 1, 1, 17, 0, 0, 0, time.UTC)
		duration := deps.service.calculateShiftDuration(start, end, 0)
		assert.Equal(t, uint32(28800), duration) // 8 hours
	})

	t.Run("LongBreak", func(t *testing.T) {
		start := time.Date(2024, 1, 1, 9, 0, 0, 0, time.UTC)
		end := time.Date(2024, 1, 1, 18, 0, 0, 0, time.UTC)
		duration := deps.service.calculateShiftDuration(start, end, 120) // 2 hour break
		assert.Equal(t, uint32(25200), duration)                         // 7 hours
	})

	t.Run("ShortShift", func(t *testing.T) {
		start := time.Date(2024, 1, 1, 9, 0, 0, 0, time.UTC)
		end := time.Date(2024, 1, 1, 13, 0, 0, 0, time.UTC)
		duration := deps.service.calculateShiftDuration(start, end, 30)
		assert.Equal(t, uint32(12600), duration) // 3.5 hours
	})
}

// ============================================================================
// LEAVE BALANCE EDGE CASES
// ============================================================================

func TestService_GetLeaveBalance_InvalidLeaveType(t *testing.T) {
	deps, cleanup := setupServiceTest(t)
	defer cleanup()

	userID := uint64(1)
	ctx := context.Background()

	_, err := deps.service.GetLeaveBalance(ctx, userID, "invalid_type")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid leave type")
}

func TestService_GetLeaveBalance_MultipleTypes(t *testing.T) {
	deps, cleanup := setupServiceTest(t)
	defer cleanup()

	userID := uint64(1)
	ctx := context.Background()

	leaveTypes := []string{"sick", "vacation", "personal"}

	for _, lt := range leaveTypes {
		deps.mockDB.ExpectQuery("SELECT (.+) FROM leave_accruals").
			WillReturnRows(sqlmock.NewRows([]string{
				"id", "user_id", "leave_type", "accrued_days", "used_days", "carryover_days", "year",
			}).AddRow(1, userID, lt, "10.00", "2.00", "1.00", 2024))

		balance, err := deps.service.GetLeaveBalance(ctx, userID, lt)
		assert.NoError(t, err)
		assert.Equal(t, lt, balance.LeaveType)
		assert.Equal(t, 9.0, balance.AvailableDays) // 10 + 1 - 2
	}
}

// ============================================================================
// BUSINESS DAYS CALCULATION EDGE CASES
// ============================================================================

func TestCalculateBusinessDays_ComplexScenarios(t *testing.T) {
	tests := []struct {
		name     string
		start    time.Time
		end      time.Time
		expected float64
	}{
		{
			name:     "PartialFirstDay",
			start:    time.Date(2024, 1, 1, 13, 0, 0, 0, time.UTC), // 1 PM
			end:      time.Date(2024, 1, 1, 17, 0, 0, 0, time.UTC), // 5 PM
			expected: 0.5,
		},
		{
			name:     "PartialLastDay",
			start:    time.Date(2024, 1, 1, 9, 0, 0, 0, time.UTC),
			end:      time.Date(2024, 1, 2, 13, 0, 0, 0, time.UTC),
			expected: 1.5,
		},
		{
			name:     "MultipleWeeksWithWeekends",
			start:    time.Date(2024, 1, 1, 9, 0, 0, 0, time.UTC),   // Monday
			end:      time.Date(2024, 1, 15, 17, 0, 0, 0, time.UTC), // Next Monday (2 weeks)
			expected: 11.0,                                          // 2 weeks = 10 business days + 1 for inclusive
		},
		{
			name:     "ZeroHoursSameDay",
			start:    time.Date(2024, 1, 1, 9, 0, 0, 0, time.UTC),
			end:      time.Date(2024, 1, 1, 9, 0, 0, 0, time.UTC),
			expected: 0.5, // Minimum 0.5 days
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := calculateBusinessDays(tt.start, tt.end)
			assert.InDelta(t, tt.expected, result, 0.5, "Business days calculation mismatch")
		})
	}
}

// ============================================================================
// CONCURRENT OPERATIONS TESTS
// ============================================================================

func TestService_CheckIn_ConcurrentSessions(t *testing.T) {
	deps, cleanup := setupServiceTest(t)
	defer cleanup()

	userID := uint64(1)
	lockKey := fmt.Sprintf("checkin_lock_%d", userID)

	// First check-in succeeds
	deps.mockDB.ExpectExec("SELECT GET_LOCK").WithArgs(lockKey).WillReturnResult(sqlmock.NewResult(1, 1))
	deps.mockDB.ExpectQuery("SELECT (.+) FROM attendance_records WHERE user_id").WithArgs(userID).WillReturnError(sql.ErrNoRows)
	deps.mockDB.ExpectQuery("SELECT (.+) FROM employee_shifts").WillReturnError(sql.ErrNoRows)
	deps.mockDB.ExpectExec("INSERT INTO attendance_records").WillReturnResult(sqlmock.NewResult(1, 1))
	deps.mockDB.ExpectQuery("SELECT (.+) FROM attendance_records WHERE id").WillReturnRows(
		sqlmock.NewRows([]string{
			"id", "user_id", "shift_id", "check_in_at", "check_out_at", "duration_seconds",
			"overtime_seconds", "status", "check_in_lat", "check_in_lng", "check_out_lat", "check_out_lng",
			"client_check_in_at", "client_check_out_at", "is_late", "is_early_leave", "created_at", "updated_at",
		}).AddRow(1, userID, nil, time.Now(), nil, nil, 0, "present", nil, nil, nil, nil, nil, nil, false, false, time.Now(), time.Now()),
	)
	deps.mockDB.ExpectExec("SELECT RELEASE_LOCK").WithArgs(lockKey).WillReturnResult(sqlmock.NewResult(1, 1))

	ctx := context.Background()
	_, err := deps.service.CheckIn(ctx, userID, CheckInRequest{})
	assert.NoError(t, err)

	// Second check-in fails (session already open)
	deps.mockDB.ExpectExec("SELECT GET_LOCK").WithArgs(lockKey).WillReturnResult(sqlmock.NewResult(1, 1))
	deps.mockDB.ExpectQuery("SELECT (.+) FROM attendance_records WHERE user_id").
		WithArgs(userID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "user_id", "shift_id", "check_in_at", "check_out_at", "duration_seconds",
			"overtime_seconds", "status", "check_in_lat", "check_in_lng", "check_out_lat", "check_out_lng",
			"client_check_in_at", "client_check_out_at", "is_late", "is_early_leave", "created_at", "updated_at",
		}).AddRow(1, userID, nil, time.Now(), nil, nil, 0, "present", nil, nil, nil, nil, nil, nil, false, false, time.Now(), time.Now()))
	deps.mockDB.ExpectExec("SELECT RELEASE_LOCK").WithArgs(lockKey).WillReturnResult(sqlmock.NewResult(1, 1))

	_, err = deps.service.CheckIn(ctx, userID, CheckInRequest{})
	assert.Error(t, err)
	assert.Equal(t, ErrOpenSessionExists, err)
}

// ============================================================================
// TIME OFF REQUEST EDGE CASES
// ============================================================================

func TestService_RequestTimeOff_AllLeaveTypes(t *testing.T) {
	deps, cleanup := setupServiceTest(t)
	defer cleanup()

	userID := uint64(1)
	ctx := context.Background()

	leaveTypes := []sqlc.TimeOffRequestsLeaveType{
		sqlc.TimeOffRequestsLeaveTypeSick,
		sqlc.TimeOffRequestsLeaveTypeVacation,
		sqlc.TimeOffRequestsLeaveTypePersonal,
		sqlc.TimeOffRequestsLeaveTypeUnpaid,
	}

	for _, lt := range leaveTypes {
		deps.mockDB.ExpectExec("INSERT INTO time_off_requests").
			WillReturnResult(sqlmock.NewResult(1, 1))

		req := TimeOffRequest{
			LeaveType: lt,
			StartDate: "2024-01-01",
			EndDate:   "2024-01-02",
			Reason:    "Need time off for various reasons that meet minimum length",
		}

		_, err := deps.service.RequestTimeOff(ctx, userID, req)
		assert.NoError(t, err)
	}
}

// ============================================================================
// APPROVAL/REJECTION EDGE CASES
// ============================================================================

func TestService_ApproveTimeOff_EdgeCases(t *testing.T) {
	deps, cleanup := setupServiceTest(t)
	defer cleanup()

	requestID := uint64(1)
	adminID := uint64(2)
	ctx := context.Background()

	t.Run("ApproveAlreadyApproved", func(t *testing.T) {
		deps.mockDB.ExpectQuery("SELECT (.+) FROM time_off_requests WHERE id").
			WithArgs(requestID).
			WillReturnRows(sqlmock.NewRows([]string{
				"id", "user_id", "leave_type", "start_date", "end_date", "days_count", "reason",
				"status", "reviewed_by", "reviewed_at", "review_note", "created_at", "updated_at",
			}).AddRow(
				requestID, uint64(1), "sick", time.Now(), time.Now().AddDate(0, 0, 1),
				"1.00", "sick", "approved", adminID, time.Now(), "Already approved", time.Now(), time.Now(),
			))

		err := deps.service.ApproveTimeOff(ctx, requestID, adminID, "Trying to approve again")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Only pending requests")
	})

	t.Run("ApproveRejected", func(t *testing.T) {
		deps.mockDB.ExpectQuery("SELECT (.+) FROM time_off_requests WHERE id").
			WithArgs(requestID).
			WillReturnRows(sqlmock.NewRows([]string{
				"id", "user_id", "leave_type", "start_date", "end_date", "days_count", "reason",
				"status", "reviewed_by", "reviewed_at", "review_note", "created_at", "updated_at",
			}).AddRow(
				requestID, uint64(1), "sick", time.Now(), time.Now().AddDate(0, 0, 1),
				"1.00", "sick", "rejected", adminID, time.Now(), "Already rejected", time.Now(), time.Now(),
			))

		err := deps.service.ApproveTimeOff(ctx, requestID, adminID, "Trying to approve rejected")
		assert.Error(t, err)
	})
}

func TestService_RejectTimeOff_EdgeCases(t *testing.T) {
	deps, cleanup := setupServiceTest(t)
	defer cleanup()

	requestID := uint64(1)
	adminID := uint64(2)
	ctx := context.Background()

	t.Run("RejectAlreadyRejected", func(t *testing.T) {
		deps.mockDB.ExpectQuery("SELECT (.+) FROM time_off_requests WHERE id").
			WithArgs(requestID).
			WillReturnRows(sqlmock.NewRows([]string{
				"id", "user_id", "leave_type", "start_date", "end_date", "days_count", "reason",
				"status", "reviewed_by", "reviewed_at", "review_note", "created_at", "updated_at",
			}).AddRow(
				requestID, uint64(1), "sick", time.Now(), time.Now().AddDate(0, 0, 1),
				"1.00", "sick", "rejected", adminID, time.Now(), "Already rejected", time.Now(), time.Now(),
			))

		err := deps.service.RejectTimeOff(ctx, requestID, adminID, "Trying to reject again")
		assert.Error(t, err)
	})

	t.Run("RejectApproved", func(t *testing.T) {
		deps.mockDB.ExpectQuery("SELECT (.+) FROM time_off_requests WHERE id").
			WithArgs(requestID).
			WillReturnRows(sqlmock.NewRows([]string{
				"id", "user_id", "leave_type", "start_date", "end_date", "days_count", "reason",
				"status", "reviewed_by", "reviewed_at", "review_note", "created_at", "updated_at",
			}).AddRow(
				requestID, uint64(1), "sick", time.Now(), time.Now().AddDate(0, 0, 1),
				"1.00", "sick", "approved", adminID, time.Now(), "Already approved", time.Now(), time.Now(),
			))

		err := deps.service.RejectTimeOff(ctx, requestID, adminID, "Trying to reject approved")
		assert.Error(t, err)
	})

	t.Run("RejectNotFound", func(t *testing.T) {
		deps.mockDB.ExpectQuery("SELECT (.+) FROM time_off_requests WHERE id").
			WithArgs(uint64(999)).
			WillReturnError(sql.ErrNoRows)

		err := deps.service.RejectTimeOff(ctx, 999, adminID, "Not found")
		assert.Error(t, err)
	})
}

// ============================================================================
// EXPORT AND REPORTING EDGE CASES
// ============================================================================

func TestService_ExportTimesheetForPeriod_EdgeCases(t *testing.T) {
	deps, cleanup := setupServiceTest(t)
	defer cleanup()

	employeeID := uint64(1)
	startDate := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	endDate := time.Date(2024, 1, 31, 23, 59, 59, 0, time.UTC)
	ctx := context.Background()

	t.Run("NoRecords", func(t *testing.T) {
		deps.mockDB.ExpectQuery("SELECT (.+) FROM attendance_records ar JOIN users").
			WillReturnRows(sqlmock.NewRows([]string{
				"id", "user_id", "email", "first_name", "last_name", "work_date",
				"check_in_at", "check_out_at", "duration_seconds", "overtime_seconds",
				"shift_id", "shift_name", "status", "is_late", "is_early_leave",
			}))

		result, err := deps.service.ExportTimesheetForPeriod(ctx, employeeID, startDate, endDate)
		assert.NoError(t, err)
		assert.Empty(t, result)
	})

	t.Run("DatabaseError", func(t *testing.T) {
		deps.mockDB.ExpectQuery("SELECT (.+) FROM attendance_records ar JOIN users").
			WillReturnError(fmt.Errorf("database connection failed"))

		_, err := deps.service.ExportTimesheetForPeriod(ctx, employeeID, startDate, endDate)
		assert.Error(t, err)
	})
}

func TestService_DailySummary_EmptyResults(t *testing.T) {
	deps, cleanup := setupServiceTest(t)
	defer cleanup()

	date := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	ctx := context.Background()

	deps.mockDB.ExpectQuery("SELECT DATE\\(check_in_at\\)").
		WillReturnRows(sqlmock.NewRows([]string{
			"date", "total_attendance", "present_count", "on_leave_count",
			"absent_count", "late_count", "total_seconds", "total_overtime_seconds",
		}))

	summary, err := deps.service.DailySummary(ctx, date)
	assert.NoError(t, err)
	assert.NotNil(t, summary)
	assert.Equal(t, 0, summary.TotalAttendance)
	assert.Equal(t, date.Format("2006-01-02"), summary.Date)
}

// ============================================================================
// VALIDATION TESTS FOR ALL DTOs
// ============================================================================

func TestDTOValidation(t *testing.T) {
	v := validator.New()

	t.Run("CheckInRequest_ValidLatLng", func(t *testing.T) {
		lat := 45.0
		lng := -75.0
		req := CheckInRequest{
			Latitude:  &lat,
			Longitude: &lng,
		}
		err := v.Validate(req)
		assert.NoError(t, err)
	})

	t.Run("CheckInRequest_InvalidLatitude", func(t *testing.T) {
		lat := 91.0 // Invalid
		req := CheckInRequest{Latitude: &lat}
		err := v.Validate(req)
		assert.Error(t, err)
	})

	t.Run("CheckInRequest_InvalidLongitude", func(t *testing.T) {
		lng := 181.0 // Invalid
		req := CheckInRequest{Longitude: &lng}
		err := v.Validate(req)
		assert.Error(t, err)
	})
}

// ============================================================================
// ERROR TYPES COMPREHENSIVE TESTS
// ============================================================================

func TestAllErrorTypes(t *testing.T) {
	allErrors := []error{
		ErrOpenSessionExists,
		ErrNoOpenSession,
		ErrSessionNotFound,
		ErrAlreadyCheckedOut,
		ErrTimeSkewTooLarge,
		ErrCheckOutBeforeIn,
		ErrInvalidDateRange,
		ErrFutureDate,
		ErrGeofenceViolation,
		ErrLocationRequired,
		ErrShiftNotFound,
		ErrNoShiftAssigned,
		ErrShiftOverlap,
		ErrInvalidShiftTime,
		ErrTimeOffNotFound,
		ErrTimeOffAlreadyReviewed,
		ErrInsufficientLeaveBalance,
		ErrTimeOffOverlap,
		ErrUnauthorizedShiftEdit,
		ErrUnauthorizedApproval,
		ErrCannotApproveOwnRequest,
		ErrHolidayNotFound,
		ErrHolidayExists,
		ErrInvalidReportPeriod,
		ErrNoDataForPeriod,
	}

	for _, err := range allErrors {
		assert.NotNil(t, err)
		assert.NotEmpty(t, err.Error())

		// Test WrapAttendanceError
		wrapped := WrapAttendanceError(err, "Additional context")
		assert.NotNil(t, wrapped)
		assert.Contains(t, wrapped.Error(), "Additional context")
	}
}

func TestValidationError_Construction(t *testing.T) {
	err := ValidationError("email", "Invalid email format")
	assert.NotNil(t, err)
	assert.Equal(t, "Validation failed", err.Message)

	details, ok := err.Details.(map[string]string)
	assert.True(t, ok)
	assert.Equal(t, "Invalid email format", details["email"])
}

// ============================================================================
// SCHEDULER COMPREHENSIVE TESTS
// ============================================================================

func TestScheduler_ErrorScenarios(t *testing.T) {
	scheduler, mock, cleanup := setupSchedulerTest(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	t.Run("AutoCheckout_DatabaseError", func(t *testing.T) {
		mock.ExpectExec("UPDATE attendance_records SET check_out_at").
			WillReturnError(fmt.Errorf("database error"))

		go scheduler.StartAutoCheckoutJob(ctx, 50*time.Millisecond)
		time.Sleep(75 * time.Millisecond)
		// Should not panic despite error
	})
}

func TestScheduler_GracefulShutdown(t *testing.T) {
	scheduler, _, cleanup := setupSchedulerTest(t)
	defer cleanup()

	ctx, cancel := context.WithCancel(context.Background())

	go scheduler.StartAutoCheckoutJob(ctx, 1*time.Second)
	go scheduler.StartAccrualJob(ctx)

	// Cancel immediately
	cancel()

	// Wait a bit to ensure goroutines exit
	time.Sleep(50 * time.Millisecond)
	// Should not panic or hang
}

// ============================================================================
// LIST ATTENDANCE WITH ALL FILTER COMBINATIONS
// ============================================================================

func TestService_ListAttendance_AllFilterCombinations(t *testing.T) {
	deps, cleanup := setupServiceTest(t)
	defer cleanup()

	userID := uint64(1)
	shiftID := uint64(1)
	from := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(2024, 1, 31, 23, 59, 59, 0, time.UTC)
	ctx := context.Background()

	testCases := []struct {
		name    string
		request ListAttendanceRequest
	}{
		{
			name:    "NoFilters",
			request: ListAttendanceRequest{Limit: 20, Page: 1},
		},
		{
			name:    "UserIDOnly",
			request: ListAttendanceRequest{UserID: &userID, Limit: 20, Page: 1},
		},
		{
			name:    "DateRangeOnly",
			request: ListAttendanceRequest{From: &from, To: &to, Limit: 20, Page: 1},
		},
		{
			name:    "StatusOnly",
			request: ListAttendanceRequest{Status: "present", Limit: 20, Page: 1},
		},
		{
			name:    "ShiftIDOnly",
			request: ListAttendanceRequest{ShiftID: &shiftID, Limit: 20, Page: 1},
		},
		{
			name: "AllFilters",
			request: ListAttendanceRequest{
				UserID:  &userID,
				From:    &from,
				To:      &to,
				Status:  "present",
				ShiftID: &shiftID,
				Limit:   20,
				Page:    1,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			deps.mockDB.ExpectQuery("SELECT COUNT").
				WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

			deps.mockDB.ExpectQuery("SELECT (.+) FROM attendance_records").
				WillReturnRows(sqlmock.NewRows([]string{
					"id", "user_id", "shift_id", "check_in_at", "check_out_at", "duration_seconds",
					"overtime_seconds", "status", "is_late", "is_early_leave", "created_at", "updated_at",
				}).AddRow(
					1, userID, shiftID, from, nil, nil, 0, "present", false, false, from, from,
				))

			result, err := deps.service.ListAttendance(ctx, tc.request)
			assert.NoError(t, err)
			assert.NotNil(t, result)
		})
	}
}

// ============================================================================
// PAGINATION EDGE CASES
// ============================================================================

func TestService_ListAttendance_PaginationEdges(t *testing.T) {
	deps, cleanup := setupServiceTest(t)
	defer cleanup()
	ctx := context.Background()

	t.Run("ZeroLimit", func(t *testing.T) {
		deps.mockDB.ExpectQuery("SELECT COUNT").
			WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(100))
		deps.mockDB.ExpectQuery("SELECT (.+) FROM attendance_records").
			WillReturnRows(sqlmock.NewRows([]string{
				"id", "user_id", "shift_id", "check_in_at", "check_out_at", "duration_seconds",
				"overtime_seconds", "status", "is_late", "is_early_leave", "created_at", "updated_at",
			}))

		req := ListAttendanceRequest{Limit: 0, Page: 1} // Should default to 20
		result, err := deps.service.ListAttendance(ctx, req)

		assert.NoError(t, err)
		assert.Equal(t, 20, result.Limit)
	})

	t.Run("ZeroPage", func(t *testing.T) {
		deps.mockDB.ExpectQuery("SELECT COUNT").
			WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(100))
		deps.mockDB.ExpectQuery("SELECT (.+) FROM attendance_records").
			WillReturnRows(sqlmock.NewRows([]string{
				"id", "user_id", "shift_id", "check_in_at", "check_out_at", "duration_seconds",
				"overtime_seconds", "status", "is_late", "is_early_leave", "created_at", "updated_at",
			}))

		req := ListAttendanceRequest{Limit: 20, Page: 0} // Should default to 1
		result, err := deps.service.ListAttendance(ctx, req)

		assert.NoError(t, err)
		assert.Equal(t, 1, result.Page)
	})

	t.Run("LargePageNumber", func(t *testing.T) {
		deps.mockDB.ExpectQuery("SELECT COUNT").
			WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(100))
		deps.mockDB.ExpectQuery("SELECT (.+) FROM attendance_records").
			WillReturnRows(sqlmock.NewRows([]string{
				"id", "user_id", "shift_id", "check_in_at", "check_out_at", "duration_seconds",
				"overtime_seconds", "status", "is_late", "is_early_leave", "created_at", "updated_at",
			}))

		req := ListAttendanceRequest{Limit: 20, Page: 1000}
		result, err := deps.service.ListAttendance(ctx, req)

		assert.NoError(t, err)
		assert.Equal(t, 1000, result.Page)
	})
}
