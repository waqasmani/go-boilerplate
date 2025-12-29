package attendance

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/waqasmani/go-boilerplate/internal/infrastructure/middleware"
)

func TestRouteRegistration(t *testing.T) {
	deps, cleanup := setupTest(t)
	defer cleanup()

	router := gin.New()
	authMiddleware := middleware.NewAuthMiddleware(deps.jwtService)

	RegisterRoutes(router, deps.handler, authMiddleware)

	// Check that routes are registered
	routes := router.Routes()

	expectedRoutes := map[string]bool{
		"POST:/api/v1/attendance/check-in":              false,
		"POST:/api/v1/attendance/check-out":             false,
		"GET:/api/v1/attendance":                        false,
		"GET:/api/v1/attendance/:id":                    false,
		"GET:/api/v1/attendance/leave-balance":          false,
		"POST:/api/v1/attendance/time-off":              false,
		"PUT:/api/v1/attendance/:id/manual":             false,
		"PATCH:/api/v1/attendance/time-off/:id/approve": false,
		"PATCH:/api/v1/attendance/time-off/:id/reject":  false,
		"GET:/api/v1/reports/daily-summary":             false,
		"GET:/api/v1/reports/employee/:id/export":       false,
	}

	for _, route := range routes {
		key := route.Method + ":" + route.Path
		if _, exists := expectedRoutes[key]; exists {
			expectedRoutes[key] = true
		}
	}

	for route, found := range expectedRoutes {
		assert.True(t, found, "Route %s should be registered", route)
	}
}

func TestHandler_CheckIn_ValidationErrors(t *testing.T) {
	deps, cleanup := setupTest(t)
	defer cleanup()
	router := setupRouter(deps)

	userID := uint64(1)

	t.Run("InvalidLatitude", func(t *testing.T) {
		accessToken, _ := deps.jwtService.GenerateAccessToken(context.Background(), userID, "test@test.com", "user")

		invalidLat := 91.0 // Invalid latitude (must be -90 to 90)
		reqBody := CheckInRequest{
			Latitude: &invalidLat,
		}
		body, _ := json.Marshal(reqBody)
		req, _ := http.NewRequest("POST", "/api/v1/attendance/check-in", bytes.NewBuffer(body))
		req.Header.Set("Authorization", "Bearer "+accessToken)
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestHandler_ManualAttendance(t *testing.T) {
	deps, cleanup := setupTest(t)
	defer cleanup()
	router := setupRouter(deps)

	managerID := uint64(2)
	attendanceID := uint64(1)

	t.Run("Success", func(t *testing.T) {
		accessToken, _ := deps.jwtService.GenerateAccessToken(context.Background(), managerID, "manager@test.com", "manager")

		deps.mockDB.ExpectExec("UPDATE attendance_records SET check_in_at").
			WillReturnResult(sqlmock.NewResult(1, 1))

		deps.mockDB.ExpectExec("INSERT INTO attendance_notes").
			WillReturnResult(sqlmock.NewResult(1, 1))

		deps.mockDB.ExpectQuery("SELECT (.+) FROM attendance_records WHERE id").
			WithArgs(attendanceID).
			WillReturnRows(sqlmock.NewRows([]string{
				"id", "user_id", "shift_id", "check_in_at", "check_out_at", "duration_seconds",
				"overtime_seconds", "status", "check_in_lat", "check_in_lng", "check_out_lat", "check_out_lng",
				"client_check_in_at", "client_check_out_at", "is_late", "is_early_leave", "created_at", "updated_at",
			}).AddRow(
				attendanceID, uint64(1), nil, time.Now(), time.Now().Add(8*time.Hour), 28800,
				0, "manual", nil, nil, nil, nil, nil, nil, false, false, time.Now(), time.Now(),
			))

		reqBody := ManualAttendanceRequest{
			UserID:     uint64(1),
			CheckInAt:  time.Now().Add(-8 * time.Hour),
			CheckOutAt: time.Now(),
			Reason:     "System glitch during check-in",
		}
		body, _ := json.Marshal(reqBody)
		req, _ := http.NewRequest("PUT", "/api/v1/attendance/1/manual", bytes.NewBuffer(body))
		req.Header.Set("Authorization", "Bearer "+accessToken)
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("InvalidID", func(t *testing.T) {
		accessToken, _ := deps.jwtService.GenerateAccessToken(context.Background(), managerID, "manager@test.com", "manager")

		reqBody := ManualAttendanceRequest{
			UserID:     uint64(1),
			CheckInAt:  time.Now().Add(-8 * time.Hour),
			CheckOutAt: time.Now(),
			Reason:     "System glitch during check-in",
		}
		body, _ := json.Marshal(reqBody)
		req, _ := http.NewRequest("PUT", "/api/v1/attendance/invalid/manual", bytes.NewBuffer(body))
		req.Header.Set("Authorization", "Bearer "+accessToken)
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("ValidationError", func(t *testing.T) {
		accessToken, _ := deps.jwtService.GenerateAccessToken(context.Background(), managerID, "manager@test.com", "manager")

		reqBody := ManualAttendanceRequest{
			UserID:     uint64(1),
			CheckInAt:  time.Now(),
			CheckOutAt: time.Now().Add(-8 * time.Hour), // Invalid: checkout before checkin
			Reason:     "short",                        // Too short
		}
		body, _ := json.Marshal(reqBody)
		req, _ := http.NewRequest("PUT", "/api/v1/attendance/1/manual", bytes.NewBuffer(body))
		req.Header.Set("Authorization", "Bearer "+accessToken)
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestHandler_GetAttendance_Unauthorized(t *testing.T) {
	deps, cleanup := setupTest(t)
	defer cleanup()
	router := setupRouter(deps)

	userID := uint64(1)
	otherUserID := uint64(2)
	attendanceID := uint64(1)

	t.Run("UserAccessingOthersRecord", func(t *testing.T) {
		accessToken, _ := deps.jwtService.GenerateAccessToken(context.Background(), otherUserID, "other@test.com", "user")

		deps.mockDB.ExpectQuery("SELECT (.+) FROM attendance_records WHERE id").
			WithArgs(attendanceID).
			WillReturnRows(sqlmock.NewRows([]string{
				"id", "user_id", "shift_id", "check_in_at", "check_out_at", "duration_seconds",
				"overtime_seconds", "status", "check_in_lat", "check_in_lng", "check_out_lat", "check_out_lng",
				"client_check_in_at", "client_check_out_at", "is_late", "is_early_leave", "created_at", "updated_at",
			}).AddRow(
				attendanceID, userID, nil, time.Now(), nil, nil,
				0, "present", nil, nil, nil, nil, nil, nil, false, false, time.Now(), time.Now(),
			))

		req, _ := http.NewRequest("GET", "/api/v1/attendance/1", nil)
		req.Header.Set("Authorization", "Bearer "+accessToken)

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("InvalidAttendanceID", func(t *testing.T) {
		accessToken, _ := deps.jwtService.GenerateAccessToken(context.Background(), userID, "test@test.com", "user")

		req, _ := http.NewRequest("GET", "/api/v1/attendance/invalid", nil)
		req.Header.Set("Authorization", "Bearer "+accessToken)

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestHandler_ListAttendance_QueryErrors(t *testing.T) {
	deps, cleanup := setupTest(t)
	defer cleanup()
	router := setupRouter(deps)

	userID := uint64(1)

	t.Run("InvalidQueryParams", func(t *testing.T) {
		accessToken, _ := deps.jwtService.GenerateAccessToken(context.Background(), userID, "test@test.com", "user")

		req, _ := http.NewRequest("GET", "/api/v1/attendance?limit=-1&page=0", nil)
		req.Header.Set("Authorization", "Bearer "+accessToken)

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestHandler_RequestTimeOff_ValidationErrors(t *testing.T) {
	deps, cleanup := setupTest(t)
	defer cleanup()
	router := setupRouter(deps)

	userID := uint64(1)

	t.Run("MissingRequiredFields", func(t *testing.T) {
		accessToken, _ := deps.jwtService.GenerateAccessToken(context.Background(), userID, "test@test.com", "user")

		reqBody := TimeOffRequest{
			LeaveType: "sick",
			// Missing StartDate, EndDate, Reason
		}
		body, _ := json.Marshal(reqBody)
		req, _ := http.NewRequest("POST", "/api/v1/attendance/time-off", bytes.NewBuffer(body))
		req.Header.Set("Authorization", "Bearer "+accessToken)
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("InvalidLeaveType", func(t *testing.T) {
		accessToken, _ := deps.jwtService.GenerateAccessToken(context.Background(), userID, "test@test.com", "user")

		reqBody := TimeOffRequest{
			LeaveType: "invalid_type",
			StartDate: "2024-01-01",
			EndDate:   "2024-01-02",
			Reason:    "Need time off for personal reasons",
		}
		body, _ := json.Marshal(reqBody)
		req, _ := http.NewRequest("POST", "/api/v1/attendance/time-off", bytes.NewBuffer(body))
		req.Header.Set("Authorization", "Bearer "+accessToken)
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestHandler_RejectTimeOff(t *testing.T) {
	deps, cleanup := setupTest(t)
	defer cleanup()
	router := setupRouter(deps)

	managerID := uint64(2)
	requestID := uint64(1)

	t.Run("Success", func(t *testing.T) {
		accessToken, _ := deps.jwtService.GenerateAccessToken(context.Background(), managerID, "manager@test.com", "manager")

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

		reqBody := ReviewTimeOffRequest{ReviewNote: "Insufficient staffing coverage"}
		body, _ := json.Marshal(reqBody)
		req, _ := http.NewRequest("PATCH", "/api/v1/attendance/time-off/1/reject", bytes.NewBuffer(body))
		req.Header.Set("Authorization", "Bearer "+accessToken)
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("InvalidID", func(t *testing.T) {
		accessToken, _ := deps.jwtService.GenerateAccessToken(context.Background(), managerID, "manager@test.com", "manager")

		reqBody := ReviewTimeOffRequest{ReviewNote: "Rejected"}
		body, _ := json.Marshal(reqBody)
		req, _ := http.NewRequest("PATCH", "/api/v1/attendance/time-off/invalid/reject", bytes.NewBuffer(body))
		req.Header.Set("Authorization", "Bearer "+accessToken)
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestHandler_ApproveTimeOff_InvalidID(t *testing.T) {
	deps, cleanup := setupTest(t)
	defer cleanup()
	router := setupRouter(deps)

	managerID := uint64(2)

	t.Run("InvalidID", func(t *testing.T) {
		accessToken, _ := deps.jwtService.GenerateAccessToken(context.Background(), managerID, "manager@test.com", "manager")

		reqBody := ReviewTimeOffRequest{ReviewNote: "Approved"}
		body, _ := json.Marshal(reqBody)
		req, _ := http.NewRequest("PATCH", "/api/v1/attendance/time-off/invalid/approve", bytes.NewBuffer(body))
		req.Header.Set("Authorization", "Bearer "+accessToken)
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestHandler_DailySummary_InvalidDate(t *testing.T) {
	deps, cleanup := setupTest(t)
	defer cleanup()
	router := setupRouter(deps)

	managerID := uint64(2)

	t.Run("InvalidDateFormat", func(t *testing.T) {
		accessToken, _ := deps.jwtService.GenerateAccessToken(context.Background(), managerID, "manager@test.com", "manager")

		req, _ := http.NewRequest("GET", "/api/v1/reports/daily-summary?date=invalid-date", nil)
		req.Header.Set("Authorization", "Bearer "+accessToken)

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestHandler_ExportEmployee_EdgeCases(t *testing.T) {
	deps, cleanup := setupTest(t)
	defer cleanup()
	router := setupRouter(deps)

	managerID := uint64(2)

	t.Run("MissingDates", func(t *testing.T) {
		accessToken, _ := deps.jwtService.GenerateAccessToken(context.Background(), managerID, "manager@test.com", "admin")

		req, _ := http.NewRequest("GET", "/api/v1/reports/employee/1/export", nil)
		req.Header.Set("Authorization", "Bearer "+accessToken)

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("InvalidStartDate", func(t *testing.T) {
		accessToken, _ := deps.jwtService.GenerateAccessToken(context.Background(), managerID, "manager@test.com", "admin")

		req, _ := http.NewRequest("GET", "/api/v1/reports/employee/1/export?start_date=invalid&end_date=2024-01-31", nil)
		req.Header.Set("Authorization", "Bearer "+accessToken)

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("InvalidEndDate", func(t *testing.T) {
		accessToken, _ := deps.jwtService.GenerateAccessToken(context.Background(), managerID, "manager@test.com", "admin")

		req, _ := http.NewRequest("GET", "/api/v1/reports/employee/1/export?start_date=2024-01-01&end_date=invalid", nil)
		req.Header.Set("Authorization", "Bearer "+accessToken)

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("InvalidEmployeeID", func(t *testing.T) {
		accessToken, _ := deps.jwtService.GenerateAccessToken(context.Background(), managerID, "manager@test.com", "admin")

		req, _ := http.NewRequest("GET", "/api/v1/reports/employee/invalid/export?start_date=2024-01-01&end_date=2024-01-31", nil)
		req.Header.Set("Authorization", "Bearer "+accessToken)

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestHandler_GetLeaveBalance_AllTypes(t *testing.T) {
	deps, cleanup := setupTest(t)
	defer cleanup()
	router := setupRouter(deps)

	userID := uint64(1)

	t.Run("WithoutLeaveType", func(t *testing.T) {
		accessToken, _ := deps.jwtService.GenerateAccessToken(context.Background(), userID, "test@test.com", "user")

		// Expect multiple queries for different leave types
		deps.mockDB.ExpectQuery("SELECT (.+) FROM leave_accruals").
			WillReturnRows(sqlmock.NewRows([]string{
				"id", "user_id", "leave_type", "accrued_days", "used_days", "carryover_days", "year",
			}).AddRow(1, userID, "sick", "10.00", "2.00", "0.00", 2024))

		deps.mockDB.ExpectQuery("SELECT (.+) FROM leave_accruals").
			WillReturnRows(sqlmock.NewRows([]string{
				"id", "user_id", "leave_type", "accrued_days", "used_days", "carryover_days", "year",
			}).AddRow(2, userID, "vacation", "15.00", "5.00", "0.00", 2024))

		deps.mockDB.ExpectQuery("SELECT (.+) FROM leave_accruals").
			WillReturnError(sql.ErrNoRows) // Personal leave not found

		req, _ := http.NewRequest("GET", "/api/v1/attendance/leave-balance", nil)
		req.Header.Set("Authorization", "Bearer "+accessToken)

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})
}

func TestErrorConstants(t *testing.T) {
	// Test that all error constants are properly defined
	errors := []error{
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

	for _, err := range errors {
		assert.NotNil(t, err)
		assert.NotEmpty(t, err.Error())
	}
}
