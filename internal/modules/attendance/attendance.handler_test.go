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
	"github.com/stretchr/testify/require"
	"github.com/waqasmani/go-boilerplate/internal/config"
	"github.com/waqasmani/go-boilerplate/internal/infrastructure/middleware"
	"github.com/waqasmani/go-boilerplate/internal/infrastructure/observability"
	"github.com/waqasmani/go-boilerplate/internal/infrastructure/security"
	"github.com/waqasmani/go-boilerplate/internal/infrastructure/sqlc"
	"github.com/waqasmani/go-boilerplate/internal/shared/validator"
)

type attendanceDeps struct {
	mockDB      sqlmock.Sqlmock
	handler     *Handler
	service     *Service
	cfg         *config.Config
	queries     *sqlc.Queries
	jwtService  *security.JWTService
	logger      *observability.Logger
	auditLogger *observability.AuditLogger
	validator   *validator.Validator
}

func setupTest(t *testing.T) (*attendanceDeps, func()) {
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
	jwtService := security.NewJWTService(&cfg.JWT)
	queries := sqlc.New(db)

	service := NewService(queries, auditLogger, validatorInstance, logger, cfg)
	handler := NewHandler(service)

	deps := &attendanceDeps{
		mockDB:      mock,
		handler:     handler,
		service:     service,
		cfg:         cfg,
		queries:     queries,
		jwtService:  jwtService,
		logger:      logger,
		auditLogger: auditLogger,
		validator:   validatorInstance,
	}

	return deps, func() { db.Close() }
}

func setupRouter(deps *attendanceDeps) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(middleware.ErrorHandlingMiddleware(deps.logger, nil))
	authMiddleware := middleware.NewAuthMiddleware(deps.jwtService)
	RegisterRoutes(r, deps.handler, authMiddleware)
	return r
}

func TestHandler_CheckOut(t *testing.T) {
	deps, cleanup := setupTest(t)
	defer cleanup()
	router := setupRouter(deps)

	userID := uint64(1)
	attendanceID := uint64(1)
	checkInTime := time.Now().Add(-8 * time.Hour)

	t.Run("Success", func(t *testing.T) {
		accessToken, _ := deps.jwtService.GenerateAccessToken(context.Background(), userID, "test@test.com", "user")

		// Expectations
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
			WillReturnRows(sqlmock.NewRows([]string{
				"id", "user_id", "shift_id", "check_in_at", "check_out_at", "duration_seconds",
				"overtime_seconds", "status", "check_in_lat", "check_in_lng", "check_out_lat", "check_out_lng",
				"client_check_in_at", "client_check_out_at", "is_late", "is_early_leave", "created_at", "updated_at",
			}).AddRow(
				attendanceID, userID, nil, checkInTime, time.Now(), 28800,
				0, "present", nil, nil, nil, nil, nil, nil, false, false, time.Now(), time.Now(),
			))

		reqBody := CheckOutRequest{}
		body, _ := json.Marshal(reqBody)
		req, _ := http.NewRequest("POST", "/api/v1/attendance/check-out", bytes.NewBuffer(body))
		req.Header.Set("Authorization", "Bearer "+accessToken)
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.NoError(t, deps.mockDB.ExpectationsWereMet())
	})

	t.Run("NoOpenSession", func(t *testing.T) {
		accessToken, _ := deps.jwtService.GenerateAccessToken(context.Background(), userID, "test@test.com", "user")

		deps.mockDB.ExpectQuery("SELECT (.+) FROM attendance_records WHERE user_id").
			WithArgs(userID).
			WillReturnError(sql.ErrNoRows)

		reqBody := CheckOutRequest{}
		body, _ := json.Marshal(reqBody)
		req, _ := http.NewRequest("POST", "/api/v1/attendance/check-out", bytes.NewBuffer(body))
		req.Header.Set("Authorization", "Bearer "+accessToken)
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestHandler_ListAttendance(t *testing.T) {
	deps, cleanup := setupTest(t)
	defer cleanup()
	router := setupRouter(deps)

	userID := uint64(1)

	t.Run("Success", func(t *testing.T) {
		accessToken, _ := deps.jwtService.GenerateAccessToken(context.Background(), userID, "test@test.com", "user")

		deps.mockDB.ExpectQuery("SELECT COUNT").
			WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

		deps.mockDB.ExpectQuery("SELECT (.+) FROM attendance_records").
			WillReturnRows(sqlmock.NewRows([]string{
				"id", "user_id", "shift_id", "check_in_at", "check_out_at", "duration_seconds",
				"overtime_seconds", "status", "is_late", "is_early_leave", "created_at", "updated_at",
			}).AddRow(
				1, userID, nil, time.Now(), nil, nil, 0, "present", false, false, time.Now(), time.Now(),
			))

		req, _ := http.NewRequest("GET", "/api/v1/attendance?limit=20&page=1", nil)
		req.Header.Set("Authorization", "Bearer "+accessToken)

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.NoError(t, deps.mockDB.ExpectationsWereMet())
	})
}

func TestHandler_GetAttendance(t *testing.T) {
	deps, cleanup := setupTest(t)
	defer cleanup()
	router := setupRouter(deps)

	userID := uint64(1)
	attendanceID := uint64(1)

	t.Run("Success", func(t *testing.T) {
		accessToken, _ := deps.jwtService.GenerateAccessToken(context.Background(), userID, "test@test.com", "user")

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

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("NotFound", func(t *testing.T) {
		accessToken, _ := deps.jwtService.GenerateAccessToken(context.Background(), userID, "test@test.com", "user")

		deps.mockDB.ExpectQuery("SELECT (.+) FROM attendance_records WHERE id").
			WithArgs(uint64(999)).
			WillReturnError(sql.ErrNoRows)

		req, _ := http.NewRequest("GET", "/api/v1/attendance/999", nil)
		req.Header.Set("Authorization", "Bearer "+accessToken)

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

func TestHandler_GetLeaveBalance(t *testing.T) {
	deps, cleanup := setupTest(t)
	defer cleanup()
	router := setupRouter(deps)

	userID := uint64(1)

	t.Run("Success", func(t *testing.T) {
		accessToken, _ := deps.jwtService.GenerateAccessToken(context.Background(), userID, "test@test.com", "user")

		deps.mockDB.ExpectQuery("SELECT (.+) FROM leave_accruals").
			WillReturnRows(sqlmock.NewRows([]string{
				"id", "user_id", "leave_type", "accrued_days", "used_days", "carryover_days", "year",
			}).AddRow(1, userID, "sick", "10.00", "2.00", "0.00", 2024))

		req, _ := http.NewRequest("GET", "/api/v1/attendance/leave-balance?leave_type=sick", nil)
		req.Header.Set("Authorization", "Bearer "+accessToken)

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})
}

func TestHandler_RequestTimeOff(t *testing.T) {
	deps, cleanup := setupTest(t)
	defer cleanup()
	router := setupRouter(deps)

	userID := uint64(1)

	t.Run("Success", func(t *testing.T) {
		accessToken, _ := deps.jwtService.GenerateAccessToken(context.Background(), userID, "test@test.com", "user")

		deps.mockDB.ExpectExec("INSERT INTO time_off_requests").
			WillReturnResult(sqlmock.NewResult(1, 1))

		reqBody := TimeOffRequest{
			LeaveType: "sick",
			StartDate: "2024-01-01",
			EndDate:   "2024-01-02",
			Reason:    "Medical appointment needed",
		}
		body, _ := json.Marshal(reqBody)
		req, _ := http.NewRequest("POST", "/api/v1/attendance/time-off", bytes.NewBuffer(body))
		req.Header.Set("Authorization", "Bearer "+accessToken)
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
	})
}

func TestHandler_ApproveTimeOff(t *testing.T) {
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

		deps.mockDB.ExpectExec("UPDATE time_off_requests SET status = 'approved'").
			WillReturnResult(sqlmock.NewResult(1, 1))

		reqBody := ReviewTimeOffRequest{ReviewNote: "Approved for medical reasons"}
		body, _ := json.Marshal(reqBody)
		req, _ := http.NewRequest("PATCH", "/api/v1/attendance/time-off/1/approve", bytes.NewBuffer(body))
		req.Header.Set("Authorization", "Bearer "+accessToken)
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})
}

func TestHandler_DailySummary(t *testing.T) {
	deps, cleanup := setupTest(t)
	defer cleanup()
	router := setupRouter(deps)

	managerID := uint64(2)

	t.Run("Success", func(t *testing.T) {
		accessToken, _ := deps.jwtService.GenerateAccessToken(context.Background(), managerID, "manager@test.com", "manager")

		deps.mockDB.ExpectQuery("SELECT DATE\\(check_in_at\\)").
			WillReturnRows(sqlmock.NewRows([]string{
				"date", "total_attendance", "present_count", "on_leave_count",
				"absent_count", "late_count", "total_seconds", "total_overtime_seconds",
			}).AddRow(time.Now(), 10, 8, 1, 1, 2, 28800, 0))

		req, _ := http.NewRequest("GET", "/api/v1/reports/daily-summary?date=2024-01-01", nil)
		req.Header.Set("Authorization", "Bearer "+accessToken)

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("MissingDate", func(t *testing.T) {
		accessToken, _ := deps.jwtService.GenerateAccessToken(context.Background(), managerID, "manager@test.com", "manager")

		req, _ := http.NewRequest("GET", "/api/v1/reports/daily-summary", nil)
		req.Header.Set("Authorization", "Bearer "+accessToken)

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestHandler_ExportEmployee(t *testing.T) {
	deps, cleanup := setupTest(t)
	defer cleanup()
	router := setupRouter(deps)

	employeeID := uint64(1)
	managerID := uint64(2)

	t.Run("Success", func(t *testing.T) {
		// Manager exporting their own data (or use admin role)
		accessToken, _ := deps.jwtService.GenerateAccessToken(context.Background(), managerID, "manager@test.com", "admin")

		deps.mockDB.ExpectQuery("SELECT (.+) FROM attendance_records ar JOIN users").
			WillReturnRows(sqlmock.NewRows([]string{
				"id", "user_id", "email", "first_name", "last_name", "work_date",
				"check_in_at", "check_out_at", "duration_seconds", "overtime_seconds",
				"shift_id", "shift_name", "status", "is_late", "is_early_leave",
			}).AddRow(
				1, employeeID, "emp@test.com", "John", "Doe", time.Now(),
				time.Now(), time.Now(), 28800, 0, nil, nil, "present", false, false,
			))

		req, _ := http.NewRequest("GET", "/api/v1/reports/employee/1/export?start_date=2024-01-01&end_date=2024-01-31", nil)
		req.Header.Set("Authorization", "Bearer "+accessToken)

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Header().Get("Content-Type"), "text/csv")
	})

	t.Run("InvalidDateRange", func(t *testing.T) {
		accessToken, _ := deps.jwtService.GenerateAccessToken(context.Background(), managerID, "manager@test.com", "manager")

		req, _ := http.NewRequest("GET", "/api/v1/reports/employee/1/export?start_date=2024-01-31&end_date=2024-01-01", nil)
		req.Header.Set("Authorization", "Bearer "+accessToken)

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}
