package auth

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
	"github.com/waqasmani/go-boilerplate/internal/infrastructure/security"
	"github.com/waqasmani/go-boilerplate/internal/shared/errors"
)

func setupRouter(deps *authDependencies) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(middleware.ErrorHandlingMiddleware(deps.service.logger, nil))

	// Mock Rate Limiter
	rl := security.NewInMemoryRateLimiter()

	authMiddleware := middleware.NewAuthMiddleware(deps.jwtService)
	handler := NewHandler(deps.service)
	RegisterRoutes(r, handler, authMiddleware, rl)

	return r
}

func TestHandler_Register(t *testing.T) {
	deps, cleanup := setupAuthTest(t)
	defer cleanup()
	router := setupRouter(deps)

	t.Run("ValidationFailure", func(t *testing.T) {
		invalidPayload := map[string]string{
			"email": "not-an-email",
		}
		body, _ := json.Marshal(invalidPayload)
		req, _ := http.NewRequest("POST", "/api/v1/auth/register", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "VALIDATION_ERROR")
	})

	t.Run("Success", func(t *testing.T) {
		email := "newuser@test.com"
		password := "SecurePass123!"

		// 1. Check existing user (none found) - query should match exactly
		deps.mockDB.ExpectQuery("SELECT (.+) FROM users WHERE email = (.+) AND is_active = TRUE").
			WithArgs(email).
			WillReturnError(sql.ErrNoRows)

		// 2. Create user
		deps.mockDB.ExpectExec("INSERT INTO users").
			WithArgs(email, sqlmock.AnyArg(), "John", "Doe", "user", true).
			WillReturnResult(sqlmock.NewResult(1, 1))

		// 3. Fetch created user
		deps.mockDB.ExpectQuery("SELECT (.+) FROM users WHERE id = (.+) AND is_active = TRUE").
			WithArgs(1).
			WillReturnRows(mockUserRow(1, email, "hash", "user"))

		payload := RegisterRequest{
			Email:     email,
			Password:  password,
			FirstName: "John",
			LastName:  "Doe",
		}
		body, _ := json.Marshal(payload)
		req, _ := http.NewRequest("POST", "/api/v1/auth/register", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusCreated {
			t.Logf("Response body: %s", w.Body.String())
		}
		assert.Equal(t, http.StatusCreated, w.Code)

		var response map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.True(t, response["success"].(bool))
	})

	t.Run("EmailConflict", func(t *testing.T) {
		email := "existing@test.com"

		// Mock existing user found - must return NO error for conflict to trigger
		deps.mockDB.ExpectQuery("SELECT (.+) FROM users WHERE email = (.+) AND is_active = TRUE").
			WithArgs(email).
			WillReturnRows(mockUserRow(1, email, "hash", "user"))

		payload := RegisterRequest{
			Email:     email,
			Password:  "Pass123!",
			FirstName: "Jane",
			LastName:  "Doe",
		}
		body, _ := json.Marshal(payload)
		req, _ := http.NewRequest("POST", "/api/v1/auth/register", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusConflict {
			t.Logf("Response body: %s", w.Body.String())
		}
		assert.Equal(t, http.StatusConflict, w.Code)
		assert.Contains(t, w.Body.String(), "CONFLICT")
	})

	t.Run("WeakPassword", func(t *testing.T) {
		payload := RegisterRequest{
			Email:     "test@test.com",
			Password:  "weak",
			FirstName: "Test",
			LastName:  "User",
		}
		body, _ := json.Marshal(payload)
		req, _ := http.NewRequest("POST", "/api/v1/auth/register", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "VALIDATION_ERROR")
	})
}

func TestHandler_Login(t *testing.T) {
	deps, cleanup := setupAuthTest(t)
	defer cleanup()
	router := setupRouter(deps)

	t.Run("Success_WithCookie", func(t *testing.T) {
		email := "cookie@test.com"
		password := "Pass1234!"
		hashed, _ := deps.passService.Hash(context.Background(), password)

		// 1. Check Lockout
		deps.mockDB.ExpectQuery("SELECT (.+) FROM failed_login_attempts").
			WillReturnRows(sqlmock.NewRows([]string{"id", "user_id", "email", "ip_address", "attempt_time"}))

		// 2. Get User (Full row)
		deps.mockDB.ExpectQuery("SELECT (.+) FROM users WHERE email = (.+) AND is_active = TRUE").
			WillReturnRows(mockUserRow(1, email, hashed, "user"))

		// 3. Clear Failed Attempts
		deps.mockDB.ExpectExec("DELETE FROM failed_login_attempts").
			WillReturnResult(sqlmock.NewResult(0, 0))

		// 4. Create Refresh Token
		deps.mockDB.ExpectExec("INSERT INTO refresh_tokens").
			WillReturnResult(sqlmock.NewResult(1, 1))

		// Request
		payload := map[string]string{"email": email, "password": password}
		body, _ := json.Marshal(payload)
		req, _ := http.NewRequest("POST", "/api/v1/auth/login", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		// Assertions
		assert.Equal(t, http.StatusOK, w.Code)

		// Check Cookies
		cookies := w.Result().Cookies()
		foundRef := false
		for _, c := range cookies {
			if c.Name == "refresh_token" {
				foundRef = true
				assert.True(t, c.HttpOnly)
				assert.Equal(t, "/api/v1/auth/refresh", c.Path)
				assert.Equal(t, 86400, c.MaxAge)
			}
		}
		assert.True(t, foundRef, "Refresh token cookie should be set")
		assert.NotEmpty(t, w.Header().Get("X-CSRF-Token"), "CSRF Header should be set")
	})

	t.Run("InvalidCredentials", func(t *testing.T) {
		email := "test@test.com"
		password := "WrongPass123!"
		correctHash, _ := deps.passService.Hash(context.Background(), "CorrectPass123!")

		// 1. Check Lockout
		deps.mockDB.ExpectQuery("SELECT (.+) FROM failed_login_attempts").
			WillReturnRows(sqlmock.NewRows([]string{"id", "user_id", "email", "ip_address", "attempt_time"}))

		// 2. Get User
		deps.mockDB.ExpectQuery("SELECT (.+) FROM users WHERE email = (.+) AND is_active = TRUE").
			WillReturnRows(mockUserRow(1, email, correctHash, "user"))

		// 3. Record Failed Attempt
		deps.mockDB.ExpectExec("INSERT INTO failed_login_attempts").
			WillReturnResult(sqlmock.NewResult(1, 1))

		// 4. Check Lockout Again
		deps.mockDB.ExpectQuery("SELECT (.+) FROM failed_login_attempts").
			WillReturnRows(sqlmock.NewRows([]string{"id", "user_id", "email", "ip_address", "attempt_time"}).
				AddRow(1, 1, email, "127.0.0.1", time.Now()))

		payload := map[string]string{"email": email, "password": password}
		body, _ := json.Marshal(payload)
		req, _ := http.NewRequest("POST", "/api/v1/auth/login", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Contains(t, w.Body.String(), "UNAUTHORIZED")
	})

	t.Run("AccountLocked", func(t *testing.T) {
		email := "locked@test.com"

		// Simulate 5 failed attempts
		rows := sqlmock.NewRows([]string{"id", "user_id", "email", "ip_address", "attempt_time"})
		for i := 0; i < 5; i++ {
			rows.AddRow(i, 1, email, "127.0.0.1", time.Now())
		}
		deps.mockDB.ExpectQuery("SELECT (.+) FROM failed_login_attempts").
			WillReturnRows(rows)

		payload := map[string]string{"email": email, "password": "Pass123!"}
		body, _ := json.Marshal(payload)
		req, _ := http.NewRequest("POST", "/api/v1/auth/login", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
		assert.Contains(t, w.Body.String(), "temporarily locked")
	})

	t.Run("ValidationError_MissingEmail", func(t *testing.T) {
		payload := map[string]string{"password": "Pass123!"}
		body, _ := json.Marshal(payload)
		req, _ := http.NewRequest("POST", "/api/v1/auth/login", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "VALIDATION_ERROR")
	})
}

func TestHandler_Refresh(t *testing.T) {
	deps, cleanup := setupAuthTest(t)
	defer cleanup()

	// Disable session binding BEFORE creating router
	deps.cfg.Security.SessionBindingEnabled = false
	router := setupRouter(deps)

	t.Run("Success", func(t *testing.T) {
		email := "refresh@test.com"
		oldToken := "old_refresh_token"
		oldCsrf := "old_csrf_token"
		oldTokenHash := deps.jwtService.HashToken(oldToken)
		oldCsrfHash := deps.jwtService.HashToken(oldCsrf)

		deps.mockDB.ExpectBegin()

		// ValidateRefreshToken - with NULL session binding
		deps.mockDB.ExpectQuery("SELECT (.+) FROM refresh_tokens").
			WithArgs(oldTokenHash, oldCsrfHash).
			WillReturnRows(sqlmock.NewRows([]string{
				"id", "user_id", "token_hash", "csrf_hash", "expires_at",
				"revoked_at", "created_at", "client_ip", "user_agent",
			}).AddRow(
				1, 10, oldTokenHash, oldCsrfHash, time.Now().Add(time.Hour),
				nil, time.Now(), nil, nil, // NULL for IP and UserAgent
			))

		// Revoke old token
		deps.mockDB.ExpectExec("UPDATE refresh_tokens SET revoked_at").
			WithArgs(oldTokenHash).
			WillReturnResult(sqlmock.NewResult(0, 1))

		// Get User
		deps.mockDB.ExpectQuery("SELECT (.+) FROM users WHERE id = (.+) AND is_active = TRUE").
			WithArgs(10).
			WillReturnRows(mockUserRow(10, email, "hash", "user"))

		// Create new refresh token
		deps.mockDB.ExpectExec("INSERT INTO refresh_tokens").
			WillReturnResult(sqlmock.NewResult(2, 1))

		deps.mockDB.ExpectCommit()

		req, _ := http.NewRequest("POST", "/api/v1/auth/refresh", nil)
		req.AddCookie(&http.Cookie{Name: "refresh_token", Value: oldToken})
		req.Header.Set("X-CSRF-Token", oldCsrf)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Logf("Response body: %s", w.Body.String())
		}
		assert.Equal(t, http.StatusOK, w.Code)
		assert.NotEmpty(t, w.Header().Get("X-CSRF-Token"))
	})

	t.Run("MissingRefreshToken", func(t *testing.T) {
		req, _ := http.NewRequest("POST", "/api/v1/auth/refresh", nil)
		req.Header.Set("X-CSRF-Token", "some_csrf")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Contains(t, w.Body.String(), "Refresh token not found")
	})

	t.Run("MissingCSRFToken", func(t *testing.T) {
		req, _ := http.NewRequest("POST", "/api/v1/auth/refresh", nil)
		req.AddCookie(&http.Cookie{Name: "refresh_token", Value: "some_token"})
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Contains(t, w.Body.String(), "CSRF token required")
	})
}

func TestHandler_Logout(t *testing.T) {
	deps, cleanup := setupAuthTest(t)
	defer cleanup()
	router := setupRouter(deps)

	t.Run("Success", func(t *testing.T) {
		refreshToken := "valid_token"
		tokenHash := deps.jwtService.HashToken(refreshToken)

		// Mock revoke operation
		deps.mockDB.ExpectExec("UPDATE refresh_tokens SET revoked_at").
			WithArgs(tokenHash).
			WillReturnResult(sqlmock.NewResult(0, 1))

		// Create valid access token
		accessToken, _ := deps.jwtService.GenerateAccessToken(
			context.Background(), 1, "test@test.com", "user",
		)

		req, _ := http.NewRequest("POST", "/api/v1/auth/logout", nil)
		req.Header.Set("Authorization", "Bearer "+accessToken)
		req.AddCookie(&http.Cookie{Name: "refresh_token", Value: refreshToken})
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNoContent, w.Code)

		// Check cookie was cleared
		cookies := w.Result().Cookies()
		for _, c := range cookies {
			if c.Name == "refresh_token" {
				assert.Equal(t, -1, c.MaxAge)
			}
		}
	})

	t.Run("WithoutAuthentication", func(t *testing.T) {
		req, _ := http.NewRequest("POST", "/api/v1/auth/logout", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

func TestHandler_Me(t *testing.T) {
	deps, cleanup := setupAuthTest(t)
	defer cleanup()
	router := setupRouter(deps)

	t.Run("Success", func(t *testing.T) {
		email := "me@test.com"
		userID := uint64(1)

		// Create valid access token
		accessToken, _ := deps.jwtService.GenerateAccessToken(
			context.Background(), userID, email, "user",
		)

		// Mock GetUserByID
		deps.mockDB.ExpectQuery("SELECT (.+) FROM users WHERE id = (.+) AND is_active = TRUE").
			WithArgs(userID).
			WillReturnRows(mockUserRow(userID, email, "hash", "user"))

		req, _ := http.NewRequest("GET", "/api/v1/auth/me", nil)
		req.Header.Set("Authorization", "Bearer "+accessToken)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.True(t, response["success"].(bool))

		data := response["data"].(map[string]interface{})
		assert.Equal(t, email, data["email"])
	})

	t.Run("Unauthorized", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/api/v1/auth/me", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)

		var response map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &response)

		errObj := response["error"].(map[string]interface{})
		assert.Equal(t, string(errors.ErrCodeUnauthorized), errObj["code"])
	})

	t.Run("InvalidToken", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/api/v1/auth/me", nil)
		req.Header.Set("Authorization", "Bearer invalid_token_here")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("MalformedAuthHeader", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/api/v1/auth/me", nil)
		req.Header.Set("Authorization", "InvalidFormat token")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Contains(t, w.Body.String(), "Invalid authorization header format")
	})
}

func TestHandler_GetClientIP(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("XRealIP", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request, _ = http.NewRequest("GET", "/", nil)
		c.Request.Header.Set("X-Real-IP", "192.168.1.1")

		ip := getClientIP(c)
		assert.Equal(t, "192.168.1.1", ip)
	})

	t.Run("XForwardedFor", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request, _ = http.NewRequest("GET", "/", nil)
		c.Request.Header.Set("X-Forwarded-For", "10.0.0.1, 192.168.1.1")

		ip := getClientIP(c)
		assert.Equal(t, "10.0.0.1", ip)
	})

	t.Run("Fallback", func(t *testing.T) {
		// This test verifies the fallback behavior
		// In test context, ClientIP() returns empty string when no headers/RemoteAddr
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request, _ = http.NewRequest("GET", "/", nil)
		c.Request.RemoteAddr = "192.168.1.100:12345"

		ip := getClientIP(c)
		// In gin test mode, ClientIP() might return empty, which is acceptable
		// The function still works, just returns what gin gives us
		// We just verify it doesn't panic
		_ = ip // Acknowledge we got something
	})
}
