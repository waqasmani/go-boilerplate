package attendance

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/waqasmani/go-boilerplate/internal/shared/validator"
)

// ============================================================================
// 1. COMPREHENSIVE DTO VALIDATION TESTS
// ============================================================================

func TestDTOValidation_Coverage(t *testing.T) {
	v := validator.New()

	t.Run("ManualAttendanceRequest_Validation", func(t *testing.T) {
		tests := []struct {
			name    string
			req     ManualAttendanceRequest
			wantErr bool
		}{
			{
				name: "Valid",
				req: ManualAttendanceRequest{
					UserID:     1,
					CheckInAt:  time.Now().Add(-2 * time.Hour),
					CheckOutAt: time.Now(),
					Reason:     "Forgot badge at home",
				},
				wantErr: false,
			},
			{
				name: "MissingUserID",
				req: ManualAttendanceRequest{
					CheckInAt:  time.Now().Add(-2 * time.Hour),
					CheckOutAt: time.Now(),
					Reason:     "Forgot badge",
				},
				wantErr: true,
			},
			{
				name: "CheckOutBeforeCheckIn",
				req: ManualAttendanceRequest{
					UserID:     1,
					CheckInAt:  time.Now(),
					CheckOutAt: time.Now().Add(-1 * time.Hour),
					Reason:     "Invalid times",
				},
				wantErr: true, // caught by gtfield=CheckInAt
			},
			{
				name: "ShortReason",
				req: ManualAttendanceRequest{
					UserID:     1,
					CheckInAt:  time.Now().Add(-2 * time.Hour),
					CheckOutAt: time.Now(),
					Reason:     "short",
				},
				wantErr: true, // min=10
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				err := v.Validate(tt.req)
				if tt.wantErr {
					assert.Error(t, err)
				} else {
					assert.NoError(t, err)
				}
			})
		}
	})

	t.Run("TimeOffRequest_Validation", func(t *testing.T) {
		tests := []struct {
			name    string
			req     TimeOffRequest
			wantErr bool
		}{
			{
				name: "Valid",
				req: TimeOffRequest{
					LeaveType: "sick",
					StartDate: "2024-01-01",
					EndDate:   "2024-01-02",
					Reason:    "Feeling unwell and need rest",
				},
				wantErr: false,
			},
			{
				name: "InvalidLeaveType",
				req: TimeOffRequest{
					LeaveType: "gaming_break",
					StartDate: "2024-01-01",
					EndDate:   "2024-01-02",
					Reason:    "Playing games",
				},
				wantErr: true, // oneof=...
			},
			{
				name: "InvalidDateFormat",
				req: TimeOffRequest{
					LeaveType: "sick",
					StartDate: "01-01-2024", // Wrong format
					EndDate:   "2024-01-02",
					Reason:    "Sick leave",
				},
				wantErr: true, // datetime=2006-01-02
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				err := v.Validate(tt.req)
				if tt.wantErr {
					assert.Error(t, err)
				} else {
					assert.NoError(t, err)
				}
			})
		}
	})

	t.Run("ShiftRequest_Validation", func(t *testing.T) {
		tests := []struct {
			name    string
			req     ShiftRequest
			wantErr bool
		}{
			{
				name: "Valid",
				req: ShiftRequest{
					Name:         "Morning Shift",
					StartTime:    "09:00",
					EndTime:      "17:00",
					BreakMinutes: 60,
				},
				wantErr: false,
			},
			{
				name: "InvalidTimeFormat",
				req: ShiftRequest{
					Name:         "Bad Time",
					StartTime:    "9am",
					EndTime:      "5pm",
					BreakMinutes: 60,
				},
				wantErr: true, // datetime=15:04
			},
			{
				name: "NegativeBreak",
				req: ShiftRequest{
					Name:         "Negative Break",
					StartTime:    "09:00",
					EndTime:      "17:00",
					BreakMinutes: 9999, // max=180
				},
				wantErr: true,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				err := v.Validate(tt.req)
				if tt.wantErr {
					assert.Error(t, err)
				} else {
					assert.NoError(t, err)
				}
			})
		}
	})

}

// ============================================================================
// 2. HANDLER BINDING & MALFORMED JSON TESTS
// ============================================================================

func TestHandler_BindingErrors_Coverage(t *testing.T) {
	deps, cleanup := setupTest(t)
	defer cleanup()
	router := setupRouter(deps)

	userID := uint64(1)
	userToken, _ := deps.jwtService.GenerateAccessToken(context.Background(), userID, "test@test.com", "user")
	managerToken, _ := deps.jwtService.GenerateAccessToken(context.Background(), userID, "manager@test.com", "manager")

	tests := []struct {
		name       string
		method     string
		url        string
		body       string // Raw string to simulate malformed JSON
		wantStatus int
		token      string
	}{
		{
			name:       "CheckIn_MalformedJSON",
			method:     "POST",
			url:        "/api/v1/attendance/check-in",
			body:       `{"latitude": 40.7128, "longitude": }`, // Syntax error
			wantStatus: http.StatusBadRequest,
			token:      userToken,
		},
		{
			name:       "CheckIn_TypeMismatch",
			method:     "POST",
			url:        "/api/v1/attendance/check-in",
			body:       `{"latitude": "invalid_string"}`, // Type mismatch
			wantStatus: http.StatusBadRequest,
			token:      userToken,
		},
		{
			name:       "ManualAttendance_MalformedJSON",
			method:     "PUT",
			url:        "/api/v1/attendance/1/manual",
			body:       `{ "user_id": 1, "reason": `, // Incomplete
			wantStatus: http.StatusBadRequest,
			token:      managerToken, // Needs manager role to pass auth middleware
		},
		{
			name:       "RequestTimeOff_EmptyBody",
			method:     "POST",
			url:        "/api/v1/attendance/time-off",
			body:       ``,
			wantStatus: http.StatusBadRequest,
			token:      userToken,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest(tt.method, tt.url, bytes.NewBufferString(tt.body))
			req.Header.Set("Authorization", "Bearer "+tt.token)
			req.Header.Set("Content-Type", "application/json")

			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.wantStatus, w.Code)
		})
	}

}

// ============================================================================
// 3. SERVICE RESILIENCE & FALLBACK TESTS
// ============================================================================

func TestService_CheckIn_Resilience(t *testing.T) {
	deps, cleanup := setupServiceTest(t)
	defer cleanup()

	userID := uint64(1)
	lockKey := "checkin_lock_1"

	t.Run("ShiftFetchFailure_ShouldStillSucceed", func(t *testing.T) {
		// 1. Acquire Lock
		deps.mockDB.ExpectExec("SELECT GET_LOCK").WithArgs(lockKey).WillReturnResult(sqlmock.NewResult(1, 1))

		// 2. Check open session (No rows = ok)
		deps.mockDB.ExpectQuery("SELECT (.+) FROM attendance_records WHERE user_id").
			WithArgs(userID).
			WillReturnError(sql.ErrNoRows) // Using sqlc.ErrNoRows or standard sql.ErrNoRows depending on import

		// 3. Shift Fetch Fails (DB Error) - Resilience Test
		// The service code `if err == nil` implies it swallows errors here.
		// We expect the flow to continue, just without a ShiftID.
		deps.mockDB.ExpectQuery("SELECT (.+) FROM employee_shifts").
			WillReturnError(errors.New("db connection glitch"))

		// 4. Create Attendance (ShiftID should be NULL)
		deps.mockDB.ExpectExec("INSERT INTO attendance_records").
			WithArgs(userID, nil, sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), false, "present").
			WillReturnResult(sqlmock.NewResult(1, 1))

		// 5. Fetch Created Record
		deps.mockDB.ExpectQuery("SELECT (.+) FROM attendance_records WHERE id").
			WillReturnRows(sqlmock.NewRows([]string{
				"id", "user_id", "shift_id", "check_in_at", "check_out_at", "duration_seconds",
				"overtime_seconds", "status", "check_in_lat", "check_in_lng", "check_out_lat", "check_out_lng",
				"client_check_in_at", "client_check_out_at", "is_late", "is_early_leave", "created_at", "updated_at",
			}).AddRow(1, userID, nil, time.Now(), nil, nil, 0, "present", nil, nil, nil, nil, nil, nil, false, false, time.Now(), time.Now()))

		// 6. Release Lock
		deps.mockDB.ExpectExec("SELECT RELEASE_LOCK").WithArgs(lockKey).WillReturnResult(sqlmock.NewResult(1, 1))

		// Execute
		ctx := context.Background()
		resp, err := deps.service.CheckIn(ctx, userID, CheckInRequest{})

		assert.NoError(t, err)
		assert.NotNil(t, resp)
		assert.Nil(t, resp.ShiftID, "ShiftID should be nil due to fetch failure")
	})

}

func TestService_CheckOut_Resilience(t *testing.T) {
	deps, cleanup := setupServiceTest(t)
	defer cleanup()

	userID := uint64(1)
	attendanceID := uint64(100)
	shiftID := uint64(5)

	t.Run("ShiftLookupFailure_ShouldSkipOvertime", func(t *testing.T) {
		// 1. Find Open Session (Has a ShiftID assigned)
		deps.mockDB.ExpectQuery("SELECT (.+) FROM attendance_records WHERE user_id").
			WithArgs(userID).
			WillReturnRows(sqlmock.NewRows([]string{
				"id", "user_id", "shift_id", "check_in_at", "check_out_at", "duration_seconds",
				"overtime_seconds", "status", "check_in_lat", "check_in_lng", "check_out_lat", "check_out_lng",
				"client_check_in_at", "client_check_out_at", "is_late", "is_early_leave", "created_at", "updated_at",
			}).AddRow(
				attendanceID, userID, shiftID, time.Now().Add(-9*time.Hour), nil, nil,
				0, "present", nil, nil, nil, nil, nil, nil, false, false, time.Now(), time.Now(),
			))

		// 2. Fetch Shift Details Fails
		// Service should catch this and proceed with 0 overtime
		deps.mockDB.ExpectQuery("SELECT (.+) FROM shifts WHERE id").
			WithArgs(shiftID).
			WillReturnError(errors.New("shift service unavailable"))

		// 3. Update Attendance (Overtime should be 0, not calculated)
		deps.mockDB.ExpectExec("UPDATE attendance_records SET check_out_at").
			WithArgs(
				sqlmock.AnyArg(), // check_out_at
				sqlmock.AnyArg(), // duration
				0,                // overtime_seconds MUST be 0
				sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
				false,        // is_early_leave (default false on error)
				attendanceID, // id
			).
			WillReturnResult(sqlmock.NewResult(1, 1))

		// 4. Fetch Updated
		deps.mockDB.ExpectQuery("SELECT (.+) FROM attendance_records WHERE id").
			WillReturnRows(sqlmock.NewRows([]string{
				"id", "user_id", "shift_id", "check_in_at", "check_out_at", "duration_seconds",
				"overtime_seconds", "status", "check_in_lat", "check_in_lng", "check_out_lat", "check_out_lng",
				"client_check_in_at", "client_check_out_at", "is_late", "is_early_leave", "created_at", "updated_at",
			}).AddRow(
				attendanceID, userID, shiftID, time.Now().Add(-9*time.Hour), time.Now(), 32400,
				0, "present", nil, nil, nil, nil, nil, nil, false, false, time.Now(), time.Now(),
			))

		// Execute
		ctx := context.Background()
		resp, err := deps.service.CheckOut(ctx, userID, CheckOutRequest{})

		assert.NoError(t, err)
		assert.NotNil(t, resp)
		assert.Equal(t, uint32(0), resp.OvertimeSeconds)
	})

}
