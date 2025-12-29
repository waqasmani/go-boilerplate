package auth

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/waqasmani/go-boilerplate/internal/shared/errors"
)

func TestService_Register(t *testing.T) {
	deps, cleanup := setupAuthTest(t)
	defer cleanup()

	t.Run("Success", func(t *testing.T) {
		email := "new@example.com"
		pass := "StrongPass1!"

		// 1. Check existing (No Rows)
		deps.mockDB.ExpectQuery("SELECT .* FROM users WHERE email = ?").
			WithArgs(email).
			WillReturnError(sql.ErrNoRows)

		// 2. Create User
		deps.mockDB.ExpectExec("INSERT INTO users").
			WithArgs(email, sqlmock.AnyArg(), "John", "Doe", "user", true).
			WillReturnResult(sqlmock.NewResult(55, 1))

		// 3. Fetch Created User
		deps.mockDB.ExpectQuery("SELECT .* FROM users WHERE id = ?").
			WithArgs(55).
			WillReturnRows(mockUserRow(55, email, "hash", "user"))

		user, err := deps.service.Register(context.Background(), email, pass, "John", "Doe")

		assert.NoError(t, err)
		assert.Equal(t, uint64(55), user.ID)
		assert.Equal(t, email, user.Email)
		assert.NoError(t, deps.mockDB.ExpectationsWereMet())
	})

	t.Run("EmailConflict", func(t *testing.T) {
		email := "existing@example.com"

		// Mock GetUserByEmail finding a user (Conflict)
		deps.mockDB.ExpectQuery("SELECT .* FROM users WHERE email = ?").
			WithArgs(email).
			WillReturnRows(mockUserRow(1, email, "hash", "user"))

		_, err := deps.service.Register(context.Background(), email, "Pass123!", "John", "Doe")

		assert.Error(t, err)
		appErr, ok := err.(*errors.AppError)
		require.True(t, ok)
		assert.Equal(t, errors.ErrCodeConflict, appErr.Code)
		assert.Contains(t, appErr.Message, "already registered")
	})

	t.Run("DatabaseError_CheckExisting", func(t *testing.T) {
		email := "db-error@example.com"

		// Simulate database error (not ErrNoRows)
		deps.mockDB.ExpectQuery("SELECT .* FROM users WHERE email = ?").
			WithArgs(email).
			WillReturnError(sql.ErrConnDone)

		_, err := deps.service.Register(context.Background(), email, "Pass123!", "John", "Doe")

		assert.Error(t, err)
		appErr, ok := err.(*errors.AppError)
		require.True(t, ok)
		assert.Equal(t, errors.ErrCodeInternal, appErr.Code)
	})

	t.Run("WeakPassword", func(t *testing.T) {
		email := "weak@example.com"

		// Check existing
		deps.mockDB.ExpectQuery("SELECT .* FROM users WHERE email = ?").
			WithArgs(email).
			WillReturnError(sql.ErrNoRows)

		// Password validation should fail before DB insert
		_, err := deps.service.Register(context.Background(), email, "weak", "John", "Doe")

		assert.Error(t, err)
		appErr, ok := err.(*errors.AppError)
		require.True(t, ok)
		assert.Equal(t, errors.ErrCodeValidation, appErr.Code)
	})
}

func TestService_Login(t *testing.T) {
	deps, cleanup := setupAuthTest(t)
	defer cleanup()

	email := "test@example.com"
	password := "Password123!"
	hashedPassword, _ := deps.passService.Hash(context.Background(), password)

	t.Run("Success", func(t *testing.T) {
		// 1. Check Lockout
		deps.mockDB.ExpectQuery("SELECT .* FROM failed_login_attempts").
			WithArgs(email, sqlmock.AnyArg()).
			WillReturnRows(sqlmock.NewRows([]string{"id", "user_id", "email", "ip_address", "attempt_time"}))

		// 2. Get User
		deps.mockDB.ExpectQuery("SELECT .* FROM users WHERE email = ?").
			WithArgs(email).
			WillReturnRows(mockUserRow(1, email, hashedPassword, "user"))

		// 3. Clear Failed Attempts
		deps.mockDB.ExpectExec("DELETE FROM failed_login_attempts").
			WithArgs(email).
			WillReturnResult(sqlmock.NewResult(0, 1))

		// 4. Create Refresh Token
		deps.mockDB.ExpectExec("INSERT INTO refresh_tokens").
			WithArgs(1, sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
			WillReturnResult(sqlmock.NewResult(1, 1))

		accessToken, refreshToken, csrf, user, err := deps.service.Login(
			context.Background(), email, password, LoginContext{ClientIP: "127.0.0.1", UserAgent: "test"},
		)

		assert.NoError(t, err)
		assert.NotEmpty(t, accessToken)
		assert.NotEmpty(t, refreshToken)
		assert.NotEmpty(t, csrf)
		assert.Equal(t, uint64(1), user.ID)
		assert.NoError(t, deps.mockDB.ExpectationsWereMet())
	})

	t.Run("AccountLocked", func(t *testing.T) {
		// Simulate 5 failed attempts
		rows := sqlmock.NewRows([]string{"id", "user_id", "email", "ip_address", "attempt_time"})
		for i := 0; i < 5; i++ {
			rows.AddRow(i, 1, email, "127.0.0.1", time.Now())
		}

		deps.mockDB.ExpectQuery("SELECT .* FROM failed_login_attempts").
			WithArgs(email, sqlmock.AnyArg()).
			WillReturnRows(rows)

		_, _, _, _, err := deps.service.Login(context.Background(), email, password, LoginContext{})

		assert.Error(t, err)
		appErr, ok := err.(*errors.AppError)
		require.True(t, ok)
		assert.Equal(t, errors.ErrCodeForbidden, appErr.Code)
		assert.Contains(t, appErr.Message, "temporarily locked")

		// Check details include retry_after_seconds
		details, ok := appErr.Details.(map[string]interface{})
		require.True(t, ok)
		assert.Contains(t, details, "retry_after_seconds")
	})

	t.Run("UserNotFound", func(t *testing.T) {
		nonExistentEmail := "ghost@example.com"

		// 1. Check Lockout
		deps.mockDB.ExpectQuery("SELECT .* FROM failed_login_attempts").
			WithArgs(nonExistentEmail, sqlmock.AnyArg()).
			WillReturnRows(sqlmock.NewRows([]string{"id", "user_id", "email", "ip_address", "attempt_time"}))

		// 2. Get User (Not Found)
		deps.mockDB.ExpectQuery("SELECT .* FROM users WHERE email = ?").
			WithArgs(nonExistentEmail).
			WillReturnError(sql.ErrNoRows)

		_, _, _, _, err := deps.service.Login(context.Background(), nonExistentEmail, password, LoginContext{})

		assert.Error(t, err)
		assert.Equal(t, errors.ErrInvalidCredentials, err)
	})

	t.Run("InvalidPassword", func(t *testing.T) {
		wrongPassword := "WrongPassword123!"

		// 1. Check Lockout
		deps.mockDB.ExpectQuery("SELECT .* FROM failed_login_attempts").
			WithArgs(email, sqlmock.AnyArg()).
			WillReturnRows(sqlmock.NewRows([]string{"id", "user_id", "email", "ip_address", "attempt_time"}))

		// 2. Get User
		deps.mockDB.ExpectQuery("SELECT .* FROM users WHERE email = ?").
			WithArgs(email).
			WillReturnRows(mockUserRow(1, email, hashedPassword, "user"))

		// 3. Record Failed Login
		deps.mockDB.ExpectExec("INSERT INTO failed_login_attempts").
			WithArgs(sqlmock.AnyArg(), email, sqlmock.AnyArg()).
			WillReturnResult(sqlmock.NewResult(1, 1))

		// 4. Check Lockout Again (1 failed attempt now)
		deps.mockDB.ExpectQuery("SELECT .* FROM failed_login_attempts").
			WithArgs(email, sqlmock.AnyArg()).
			WillReturnRows(sqlmock.NewRows([]string{"id", "user_id", "email", "ip_address", "attempt_time"}).
				AddRow(1, 1, email, "127.0.0.1", time.Now()))

		_, _, _, _, err := deps.service.Login(context.Background(), email, wrongPassword, LoginContext{ClientIP: "127.0.0.1"})

		assert.Error(t, err)
		appErr, ok := err.(*errors.AppError)
		require.True(t, ok)
		assert.Equal(t, errors.ErrCodeUnauthorized, appErr.Code)

		// Check details include attempts_remaining
		details, ok := appErr.Details.(map[string]interface{})
		require.True(t, ok)
		assert.Contains(t, details, "attempts_remaining")
	})

	t.Run("AccountLockedAfterFailedAttempt", func(t *testing.T) {
		// First check: 2 failed attempts
		rows1 := sqlmock.NewRows([]string{"id", "user_id", "email", "ip_address", "attempt_time"})
		for i := 0; i < 2; i++ {
			rows1.AddRow(i, 1, email, "127.0.0.1", time.Now())
		}
		deps.mockDB.ExpectQuery("SELECT .* FROM failed_login_attempts").
			WithArgs(email, sqlmock.AnyArg()).
			WillReturnRows(rows1)

		// Get User
		deps.mockDB.ExpectQuery("SELECT .* FROM users WHERE email = ?").
			WithArgs(email).
			WillReturnRows(mockUserRow(1, email, hashedPassword, "user"))

		// Record Failed Login (3rd attempt)
		deps.mockDB.ExpectExec("INSERT INTO failed_login_attempts").
			WillReturnResult(sqlmock.NewResult(3, 1))

		// Check Lockout Again: Now 3 attempts = locked (max is 3)
		rows2 := sqlmock.NewRows([]string{"id", "user_id", "email", "ip_address", "attempt_time"})
		for i := 0; i < 3; i++ {
			rows2.AddRow(i, 1, email, "127.0.0.1", time.Now())
		}
		deps.mockDB.ExpectQuery("SELECT .* FROM failed_login_attempts").
			WithArgs(email, sqlmock.AnyArg()).
			WillReturnRows(rows2)

		_, _, _, _, err := deps.service.Login(context.Background(), email, "WrongPass!", LoginContext{})

		assert.Error(t, err)
		appErr, ok := err.(*errors.AppError)
		require.True(t, ok)
		assert.Equal(t, errors.ErrCodeForbidden, appErr.Code)
		assert.Contains(t, appErr.Message, "Account locked")
	})
}

func TestService_RefreshToken(t *testing.T) {
	deps, cleanup := setupAuthTest(t)
	defer cleanup()

	t.Run("Success", func(t *testing.T) {
		oldToken := "old_refresh_token"
		oldCsrf := "old_csrf"
		oldTokenHash := deps.jwtService.HashToken(oldToken)
		oldCsrfHash := deps.jwtService.HashToken(oldCsrf)

		deps.mockDB.ExpectBegin()

		// 1. Validate Token (not revoked)
		deps.mockDB.ExpectQuery("SELECT .* FROM refresh_tokens").
			WithArgs(oldTokenHash, oldCsrfHash).
			WillReturnRows(sqlmock.NewRows([]string{
				"id", "user_id", "token_hash", "csrf_hash", "expires_at",
				"revoked_at", "created_at", "client_ip", "user_agent",
			}).AddRow(
				1, 10, oldTokenHash, oldCsrfHash, time.Now().Add(time.Hour),
				nil, time.Now(), "127.0.0.1", "Go-http-client",
			))

		// 2. Revoke old token
		deps.mockDB.ExpectExec("UPDATE refresh_tokens SET revoked_at").
			WithArgs(oldTokenHash).
			WillReturnResult(sqlmock.NewResult(0, 1))

		// 3. Get User
		deps.mockDB.ExpectQuery("SELECT .* FROM users WHERE id = ?").
			WithArgs(10).
			WillReturnRows(mockUserRow(10, "test@example.com", "hash", "user"))

		// 4. Create new refresh token
		deps.mockDB.ExpectExec("INSERT INTO refresh_tokens").
			WillReturnResult(sqlmock.NewResult(2, 1))

		deps.mockDB.ExpectCommit()

		accessToken, newRefreshToken, newCsrf, user, err := deps.service.RefreshToken(
			context.Background(), oldToken, oldCsrf, LoginContext{ClientIP: "127.0.0.1", UserAgent: "Go-http-client"},
		)

		assert.NoError(t, err)
		assert.NotEmpty(t, accessToken)
		assert.NotEmpty(t, newRefreshToken)
		assert.NotEmpty(t, newCsrf)
		assert.Equal(t, uint64(10), user.ID)
		assert.NoError(t, deps.mockDB.ExpectationsWereMet())
	})

	t.Run("ReuseDetection_RevokeAllTokens", func(t *testing.T) {
		oldToken := "reused_refresh_token"
		oldCsrf := "old_csrf"
		oldTokenHash := deps.jwtService.HashToken(oldToken)
		oldCsrfHash := deps.jwtService.HashToken(oldCsrf)

		deps.mockDB.ExpectBegin()

		// 1. Validate Token returns a REVOKED token
		deps.mockDB.ExpectQuery("SELECT .* FROM refresh_tokens").
			WithArgs(oldTokenHash, oldCsrfHash).
			WillReturnRows(sqlmock.NewRows([]string{
				"id", "user_id", "token_hash", "csrf_hash", "expires_at",
				"revoked_at", "created_at", "client_ip", "user_agent",
			}).AddRow(
				1, 10, oldTokenHash, oldCsrfHash, time.Now().Add(time.Hour),
				time.Now(), // REVOKED
				time.Now(), "127.0.0.1", "Go-http-client",
			))

		// 2. Transaction Rollback
		deps.mockDB.ExpectRollback()

		// 3. Security Measure: Revoke ALL tokens for this user
		deps.mockDB.ExpectExec("UPDATE refresh_tokens SET revoked_at").
			WithArgs(10).
			WillReturnResult(sqlmock.NewResult(0, 5))

		_, _, _, _, err := deps.service.RefreshToken(
			context.Background(), oldToken, oldCsrf, LoginContext{},
		)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Security violation detected")
		assert.NoError(t, deps.mockDB.ExpectationsWereMet())
	})

	t.Run("SessionBinding_IPMismatch", func(t *testing.T) {
		oldToken := "binding_token"
		oldCsrf := "binding_csrf"
		oldTokenHash := deps.jwtService.HashToken(oldToken)
		oldCsrfHash := deps.jwtService.HashToken(oldCsrf)

		deps.mockDB.ExpectBegin()

		// Token has binding data but IP doesn't match
		deps.mockDB.ExpectQuery("SELECT .* FROM refresh_tokens").
			WithArgs(oldTokenHash, oldCsrfHash).
			WillReturnRows(sqlmock.NewRows([]string{
				"id", "user_id", "token_hash", "csrf_hash", "expires_at",
				"revoked_at", "created_at", "client_ip", "user_agent",
			}).AddRow(
				1, 10, oldTokenHash, oldCsrfHash, time.Now().Add(time.Hour),
				nil, time.Now(), "192.168.1.1", "Go-http-client", // Different IP
			))

		deps.mockDB.ExpectRollback()

		// Revoke all tokens due to potential hijacking
		deps.mockDB.ExpectExec("UPDATE refresh_tokens SET revoked_at").
			WithArgs(10).
			WillReturnResult(sqlmock.NewResult(0, 3))

		_, _, _, _, err := deps.service.RefreshToken(
			context.Background(), oldToken, oldCsrf,
			LoginContext{ClientIP: "10.0.0.1", UserAgent: "Go-http-client"}, // Different IP
		)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Session validation failed")
	})

	t.Run("InvalidToken", func(t *testing.T) {
		deps.mockDB.ExpectBegin()

		deps.mockDB.ExpectQuery("SELECT .* FROM refresh_tokens").
			WillReturnError(sql.ErrNoRows)

		deps.mockDB.ExpectRollback()

		_, _, _, _, err := deps.service.RefreshToken(
			context.Background(), "invalid_token", "invalid_csrf", LoginContext{},
		)

		assert.Error(t, err)
		appErr, ok := err.(*errors.AppError)
		require.True(t, ok)
		assert.Equal(t, errors.ErrCodeUnauthorized, appErr.Code)
	})
}

func TestService_Logout(t *testing.T) {
	deps, cleanup := setupAuthTest(t)
	defer cleanup()

	t.Run("Success", func(t *testing.T) {
		refreshToken := "valid_token"
		tokenHash := deps.jwtService.HashToken(refreshToken)

		deps.mockDB.ExpectExec("UPDATE refresh_tokens SET revoked_at").
			WithArgs(tokenHash).
			WillReturnResult(sqlmock.NewResult(0, 1))

		err := deps.service.Logout(context.Background(), refreshToken)

		assert.NoError(t, err)
		assert.NoError(t, deps.mockDB.ExpectationsWereMet())
	})

	t.Run("TokenNotFound", func(t *testing.T) {
		refreshToken := "nonexistent_token"
		tokenHash := deps.jwtService.HashToken(refreshToken)

		deps.mockDB.ExpectExec("UPDATE refresh_tokens SET revoked_at").
			WithArgs(tokenHash).
			WillReturnResult(sqlmock.NewResult(0, 0))

		err := deps.service.Logout(context.Background(), refreshToken)

		// Should not error even if token doesn't exist
		assert.NoError(t, err)
	})
}

func TestService_CheckAccountLockout(t *testing.T) {
	deps, cleanup := setupAuthTest(t)
	defer cleanup()

	email := "lockout@test.com"

	t.Run("NoLockout", func(t *testing.T) {
		// 2 failed attempts (below threshold of 3)
		rows := sqlmock.NewRows([]string{"id", "user_id", "email", "ip_address", "attempt_time"})
		for i := 0; i < 2; i++ {
			rows.AddRow(i, 1, email, "127.0.0.1", time.Now())
		}

		deps.mockDB.ExpectQuery("SELECT .* FROM failed_login_attempts").
			WithArgs(email, sqlmock.AnyArg()).
			WillReturnRows(rows)

		info, err := deps.service.checkAccountLockout(context.Background(), email)

		assert.NoError(t, err)
		assert.False(t, info.IsLocked)
		assert.Equal(t, 2, info.FailedAttempts)
	})

	t.Run("LockedWithExponentialBackoff", func(t *testing.T) {
		// 10 failed attempts = significant lockout time
		rows := sqlmock.NewRows([]string{"id", "user_id", "email", "ip_address", "attempt_time"})
		for i := 0; i < 10; i++ {
			rows.AddRow(i, 1, email, "127.0.0.1", time.Now().Add(-1*time.Minute))
		}

		deps.mockDB.ExpectQuery("SELECT .* FROM failed_login_attempts").
			WithArgs(email, sqlmock.AnyArg()).
			WillReturnRows(rows)

		info, err := deps.service.checkAccountLockout(context.Background(), email)

		assert.NoError(t, err)
		assert.True(t, info.IsLocked)
		assert.Equal(t, 10, info.FailedAttempts)
		assert.Greater(t, info.RetryAfterSeconds, 0)
	})

	t.Run("LockoutExpired", func(t *testing.T) {
		// Failed attempts from 2 hours ago (beyond lockout duration)
		rows := sqlmock.NewRows([]string{"id", "user_id", "email", "ip_address", "attempt_time"})
		for i := 0; i < 5; i++ {
			rows.AddRow(i, 1, email, "127.0.0.1", time.Now().Add(-2*time.Hour))
		}

		deps.mockDB.ExpectQuery("SELECT .* FROM failed_login_attempts").
			WithArgs(email, sqlmock.AnyArg()).
			WillReturnRows(rows)

		info, err := deps.service.checkAccountLockout(context.Background(), email)

		assert.NoError(t, err)
		assert.False(t, info.IsLocked)
		assert.Equal(t, 5, info.FailedAttempts)
	})
}

func TestService_CleanupOldFailedLogins(t *testing.T) {
	deps, cleanup := setupAuthTest(t)
	defer cleanup()

	t.Run("Success", func(t *testing.T) {
		deps.mockDB.ExpectExec("DELETE FROM failed_login_attempts").
			WithArgs(1000).
			WillReturnResult(sqlmock.NewResult(0, 50))

		err := deps.service.CleanupOldFailedLogins(context.Background())

		assert.NoError(t, err)
		assert.NoError(t, deps.mockDB.ExpectationsWereMet())
	})
}
