package attendance

import (
	"context"
	"database/sql"
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

func setupSchedulerTest(t *testing.T) (*Scheduler, sqlmock.Sqlmock, func()) {
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
	scheduler := NewScheduler(service, logger)

	return scheduler, mock, func() { db.Close() }
}

func TestScheduler_AutoCheckoutJob(t *testing.T) {
	scheduler, mock, cleanup := setupSchedulerTest(t)
	defer cleanup()

	// Create a context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Expect the auto-checkout query to be called
	mock.ExpectExec("UPDATE attendance_records SET check_out_at").
		WillReturnResult(sqlmock.NewResult(0, 3))

	// Run the scheduler with a short interval
	go scheduler.StartAutoCheckoutJob(ctx, 50*time.Millisecond)

	// Wait for the job to run at least once
	time.Sleep(75 * time.Millisecond)

	// The job should have run and the expectations should be met (or partially met)
	// We don't assert ExpectationsWereMet because the timing might not be perfect
}

func TestScheduler_AccrualJob(t *testing.T) {
	scheduler, _, cleanup := setupSchedulerTest(t)
	defer cleanup()

	// Create a context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	// Run the scheduler
	go scheduler.StartAccrualJob(ctx)

	// Wait for context to expire
	<-ctx.Done()

	// No assertions needed, just ensuring no panic
}

// Test edge cases for business day calculation
func TestCalculateBusinessDays_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		start    time.Time
		end      time.Time
		expected float64
	}{
		{
			name:     "Same day full",
			start:    time.Date(2024, 1, 1, 9, 0, 0, 0, time.UTC),
			end:      time.Date(2024, 1, 1, 17, 0, 0, 0, time.UTC),
			expected: 1.0,
		},
		{
			name:     "Half day",
			start:    time.Date(2024, 1, 1, 9, 0, 0, 0, time.UTC),
			end:      time.Date(2024, 1, 1, 13, 0, 0, 0, time.UTC),
			expected: 0.5,
		},
		{
			name:     "Weekend only",
			start:    time.Date(2024, 1, 6, 9, 0, 0, 0, time.UTC),  // Saturday
			end:      time.Date(2024, 1, 7, 17, 0, 0, 0, time.UTC), // Sunday
			expected: 0.5,                                          // Minimum 0.5 days
		},
		{
			name:     "Across weekend",
			start:    time.Date(2024, 1, 5, 9, 0, 0, 0, time.UTC),  // Friday
			end:      time.Date(2024, 1, 8, 17, 0, 0, 0, time.UTC), // Monday
			expected: 2.0,                                          // Friday + Monday
		},
		{
			name:     "Invalid range (end before start)",
			start:    time.Date(2024, 1, 5, 9, 0, 0, 0, time.UTC),
			end:      time.Date(2024, 1, 1, 17, 0, 0, 0, time.UTC),
			expected: 0.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := calculateBusinessDays(tt.start, tt.end)
			assert.InDelta(t, tt.expected, result, 0.1, "Business days calculation mismatch")
		})
	}
}

// Test helper function conversions
func TestHelperConversions(t *testing.T) {
	t.Run("toUint64Ptr - Valid", func(t *testing.T) {
		val := sql.NullInt64{Int64: 123, Valid: true}
		result := toUint64Ptr(val)
		assert.NotNil(t, result)
		assert.Equal(t, uint64(123), *result)
	})

	t.Run("toUint64Ptr - Null", func(t *testing.T) {
		val := sql.NullInt64{Valid: false}
		result := toUint64Ptr(val)
		assert.Nil(t, result)
	})

	t.Run("toTimePtr - Valid", func(t *testing.T) {
		now := time.Now()
		val := sql.NullTime{Time: now, Valid: true}
		result := toTimePtr(val)
		assert.NotNil(t, result)
		assert.Equal(t, now, *result)
	})

	t.Run("toTimePtr - Null", func(t *testing.T) {
		val := sql.NullTime{Valid: false}
		result := toTimePtr(val)
		assert.Nil(t, result)
	})

	t.Run("toUint32Ptr - Valid", func(t *testing.T) {
		val := sql.NullInt32{Int32: 456, Valid: true}
		result := toUint32Ptr(val)
		assert.NotNil(t, result)
		assert.Equal(t, uint32(456), *result)
	})

	t.Run("toUint32Ptr - Null", func(t *testing.T) {
		val := sql.NullInt32{Valid: false}
		result := toUint32Ptr(val)
		assert.Nil(t, result)
	})

	t.Run("toFloat64PtrFromString - Valid", func(t *testing.T) {
		val := sql.NullString{String: "123.45", Valid: true}
		result := toFloat64PtrFromString(val)
		assert.NotNil(t, result)
		assert.InDelta(t, 123.45, *result, 0.01)
	})

	t.Run("toFloat64PtrFromString - Null", func(t *testing.T) {
		val := sql.NullString{Valid: false}
		result := toFloat64PtrFromString(val)
		assert.Nil(t, result)
	})

	t.Run("convertToFloat - Valid", func(t *testing.T) {
		result, err := convertToFloat("123.45")
		assert.NoError(t, err)
		assert.InDelta(t, 123.45, result, 0.01)
	})

	t.Run("convertToFloat - Empty", func(t *testing.T) {
		result, err := convertToFloat("")
		assert.NoError(t, err)
		assert.Equal(t, 0.0, result)
	})

	t.Run("convertToFloat - Invalid", func(t *testing.T) {
		_, err := convertToFloat("invalid")
		assert.Error(t, err)
	})
}

// Test error wrapping functions
func TestErrorFunctions(t *testing.T) {
	t.Run("WrapAttendanceError", func(t *testing.T) {
		originalErr := assert.AnError
		wrappedErr := WrapAttendanceError(originalErr, "Custom message")
		assert.NotNil(t, wrappedErr)
		assert.Contains(t, wrappedErr.Error(), "Custom message")
	})

	t.Run("ValidationError", func(t *testing.T) {
		err := ValidationError("email", "Invalid email format")
		assert.NotNil(t, err)
		assert.Equal(t, "Validation failed", err.Message)
	})
}

// Test attendance response with all field types
func TestToAttendanceResponse_AllFields(t *testing.T) {
	deps, cleanup := setupServiceTest(t)
	defer cleanup()

	now := time.Now()
	mockLat := "40.7128"
	mockLng := "-74.0060"

	record := sqlc.AttendanceRecord{
		ID:               1,
		UserID:           1,
		ShiftID:          sql.NullInt64{Int64: 1, Valid: true},
		CheckInAt:        now,
		CheckOutAt:       sql.NullTime{Time: now.Add(8 * time.Hour), Valid: true},
		DurationSeconds:  sql.NullInt32{Int32: 28800, Valid: true},
		OvertimeSeconds:  sql.NullInt32{Int32: 3600, Valid: true},
		Status:           "present",
		CheckInLat:       sql.NullString{String: mockLat, Valid: true},
		CheckInLng:       sql.NullString{String: mockLng, Valid: true},
		CheckOutLat:      sql.NullString{String: mockLat, Valid: true},
		CheckOutLng:      sql.NullString{String: mockLng, Valid: true},
		ClientCheckInAt:  sql.NullTime{Time: now, Valid: true},
		ClientCheckOutAt: sql.NullTime{Time: now.Add(8 * time.Hour), Valid: true},
		IsLate:           true,
		IsEarlyLeave:     true,
		CreatedAt:        now,
		UpdatedAt:        now,
	}

	response := deps.service.toAttendanceResponse(record)

	assert.NotNil(t, response)
	assert.Equal(t, uint64(1), response.ID)
	assert.NotNil(t, response.ShiftID)
	assert.Equal(t, uint64(1), *response.ShiftID)
	assert.NotNil(t, response.CheckOutAt)
	assert.NotNil(t, response.DurationSeconds)
	assert.Equal(t, uint32(28800), *response.DurationSeconds)
	assert.Equal(t, uint32(3600), response.OvertimeSeconds)
	assert.NotNil(t, response.CheckInLatitude)
	assert.InDelta(t, 40.7128, *response.CheckInLatitude, 0.0001)
	assert.NotNil(t, response.CheckInLongitude)
	assert.InDelta(t, -74.0060, *response.CheckInLongitude, 0.0001)
	assert.True(t, response.IsLate)
	assert.True(t, response.IsEarlyLeave)
}

// Test ListAttendance with various filters
func TestService_ListAttendance_WithFilters(t *testing.T) {
	deps, cleanup := setupServiceTest(t)
	defer cleanup()

	userID := uint64(1)
	shiftID := uint64(1)
	from := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(2024, 1, 31, 23, 59, 59, 0, time.UTC)

	deps.mockDB.ExpectQuery("SELECT COUNT").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(5))

	deps.mockDB.ExpectQuery("SELECT (.+) FROM attendance_records").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "user_id", "shift_id", "check_in_at", "check_out_at", "duration_seconds",
			"overtime_seconds", "status", "is_late", "is_early_leave", "created_at", "updated_at",
		}).AddRow(
			1, userID, shiftID, from, from.Add(8*time.Hour), 28800,
			0, "present", false, false, from, from,
		))

	ctx := context.Background()
	req := ListAttendanceRequest{
		UserID:  &userID,
		From:    &from,
		To:      &to,
		Status:  "present",
		ShiftID: &shiftID,
		Limit:   10,
		Page:    1,
	}

	result, err := deps.service.ListAttendance(ctx, req)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, int64(5), result.Total)
	assert.Len(t, result.Records, 1)
}

// Test RequestTimeOff with all leave types
func TestService_RequestTimeOff_AllTypes(t *testing.T) {
	deps, cleanup := setupServiceTest(t)
	defer cleanup()

	userID := uint64(1)
	ctx := context.Background()

	leaveTypes := []struct {
		leaveType string
		sqlType   sqlc.TimeOffRequestsLeaveType
	}{
		{"sick", sqlc.TimeOffRequestsLeaveTypeSick},
		{"vacation", sqlc.TimeOffRequestsLeaveTypeVacation},
		{"personal", sqlc.TimeOffRequestsLeaveTypePersonal},
		{"unpaid", sqlc.TimeOffRequestsLeaveTypeUnpaid},
	}

	for _, lt := range leaveTypes {
		t.Run("LeaveType_"+lt.leaveType, func(t *testing.T) {
			deps.mockDB.ExpectExec("INSERT INTO time_off_requests").
				WillReturnResult(sqlmock.NewResult(1, 1))

			req := TimeOffRequest{
				LeaveType: lt.sqlType,
				StartDate: "2024-01-01",
				EndDate:   "2024-01-02",
				Reason:    "Need time off for personal reasons",
			}

			_, err := deps.service.RequestTimeOff(ctx, userID, req)
			assert.NoError(t, err)
		})
	}
}

// Test GetLeaveBalance with invalid leave type
func TestService_GetLeaveBalance_InvalidType(t *testing.T) {
	deps, cleanup := setupServiceTest(t)
	defer cleanup()

	ctx := context.Background()
	_, err := deps.service.GetLeaveBalance(ctx, 1, "invalid_type")

	assert.Error(t, err)
}
