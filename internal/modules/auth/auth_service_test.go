package auth

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/waqasmani/go-boilerplate/internal/config"
	"github.com/waqasmani/go-boilerplate/internal/infrastructure/security"
	"github.com/waqasmani/go-boilerplate/internal/infrastructure/sqlc"
	"github.com/waqasmani/go-boilerplate/internal/modules/users"
)

// setupAuthServiceHelper creates a service instance with mocked DB
func setupAuthServiceHelper(t *testing.T) (*AuthService, sqlmock.Sqlmock, *security.JWTService, *security.PasswordService) {
	db, mock, err := sqlmock.New()
	assert.NoError(t, err)
	queries := sqlc.New(db)
	repo := sqlc.NewRepository(db)
	jwtCfg := &config.JWTConfig{
		AccessSecret:  "valid_secret_at_least_32_characters_long",
		RefreshSecret: "valid_secret_at_least_32_characters_long",
		AccessExpiry:  time.Minute,
		RefreshExpiry: time.Hour,
	}
	jwtService := security.NewJWTService(jwtCfg)
	passService := security.NewPasswordService(4) // Low cost for tests
	service := NewAuthService(queries, repo, jwtService, passService)
	return service, mock, jwtService, passService
}

func TestAuthService_Login(t *testing.T) {
	service, mock, _, passService := setupAuthServiceHelper(t)
	defer func() {
		assert.NoError(t, mock.ExpectationsWereMet())
	}()
	ctx := context.Background()
	email := "test@example.com"
	rawPass := "SecurePass123!" // Use a password that meets all requirements
	hashedPass, _ := passService.Hash(ctx, rawPass)
	req := LoginRequest{Email: email, Password: rawPass}

	// Columns expected by GetUserByEmail:
	// id, email, password_hash, first_name, last_name, role, is_active, created_at, updated_at
	columns := []string{"id", "email", "password_hash", "first_name", "last_name", "role", "is_active", "created_at", "updated_at"}

	// 1. User Not Found
	mock.ExpectQuery("SELECT .* FROM users WHERE email = ?").
		WithArgs(email).
		WillReturnError(sql.ErrNoRows)
	_, _, err := service.Login(ctx, req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid credentials")

	// 2. DB Error
	mock.ExpectQuery("SELECT .* FROM users WHERE email = ?").
		WithArgs(email).
		WillReturnError(errors.New("db boom"))
	_, _, err = service.Login(ctx, req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Failed to find user")

	// 3. User Inactive
	mock.ExpectQuery("SELECT .* FROM users WHERE email = ?").
		WithArgs(email).
		WillReturnRows(sqlmock.NewRows(columns).
			AddRow(1, email, hashedPass, "F", "L", "user", false, time.Now(), time.Now())) // is_active = false
	_, _, err = service.Login(ctx, req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Account is inactive")

	// 4. Password Mismatch
	mock.ExpectQuery("SELECT .* FROM users WHERE email = ?").
		WithArgs(email).
		WillReturnRows(sqlmock.NewRows(columns).
			AddRow(1, email, hashedPass, "F", "L", "user", true, time.Now(), time.Now()))
	_, _, err = service.Login(ctx, LoginRequest{Email: email, Password: "wrong"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid credentials")

	// 5. Success
	mock.ExpectQuery("SELECT .* FROM users WHERE email = ?").
		WithArgs(email).
		WillReturnRows(sqlmock.NewRows(columns).
			AddRow(1, email, hashedPass, "F", "L", "user", true, time.Now(), time.Now()))
	mock.ExpectExec("INSERT INTO refresh_tokens").
		WithArgs(1, sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))
	tokens, uid, err := service.Login(ctx, req)
	assert.NoError(t, err)
	assert.Equal(t, uint64(1), uid)
	assert.NotEmpty(t, tokens.AccessToken)
}

func TestAuthService_RefreshTokens(t *testing.T) {
	service, mock, jwtService, _ := setupAuthServiceHelper(t)
	defer func() {
		assert.NoError(t, mock.ExpectationsWereMet())
	}()
	ctx := context.Background()
	validToken, _ := jwtService.GenerateRefreshToken(ctx, 1, "test@example.com")

	// Refresh Token Columns
	rtColumns := []string{"id", "user_id", "token_hash", "expires_at", "revoked_at", "created_at"}

	// User Columns
	userColumns := []string{"id", "email", "password_hash", "first_name", "last_name", "role", "is_active", "created_at", "updated_at"}

	// 1. Invalid JWT Format
	_, _, err := service.RefreshTokens(ctx, "invalid.token")
	assert.Error(t, err)

	// 2. Token Not Found in DB (Revoked or garbage)
	mock.ExpectBegin()
	mock.ExpectQuery("SELECT .* FROM refresh_tokens").
		WithArgs(sqlmock.AnyArg()).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()
	_, _, err = service.RefreshTokens(ctx, validToken)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid token")

	// 3. Token Expired in DB
	mock.ExpectBegin()
	mock.ExpectQuery("SELECT .* FROM refresh_tokens").
		WithArgs(sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows(rtColumns).
			AddRow(1, 1, "hash", time.Now().Add(-time.Hour), nil, time.Now()))
	mock.ExpectRollback()
	_, _, err = service.RefreshTokens(ctx, validToken)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Token expired")

	// 4. User Mismatch (Token hijacking attempt)
	mock.ExpectBegin()
	mock.ExpectQuery("SELECT .* FROM refresh_tokens").
		WithArgs(sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows(rtColumns).
			AddRow(1, 999, "hash", time.Now().Add(time.Hour), nil, time.Now())) // ID mismatch
	mock.ExpectRollback()
	_, _, err = service.RefreshTokens(ctx, validToken)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid token")

	// 5. User fetch error
	mock.ExpectBegin()
	mock.ExpectQuery("SELECT .* FROM refresh_tokens").
		WithArgs(sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows(rtColumns).
			AddRow(1, 1, "hash", time.Now().Add(time.Hour), nil, time.Now()))
	mock.ExpectQuery("SELECT .* FROM users WHERE id = ?").
		WithArgs(1).
		WillReturnError(errors.New("db error"))
	mock.ExpectRollback()
	_, _, err = service.RefreshTokens(ctx, validToken)
	assert.Error(t, err)

	// 6. Success
	mock.ExpectBegin()
	mock.ExpectQuery("SELECT .* FROM refresh_tokens").
		WithArgs(sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows(rtColumns).
			AddRow(1, 1, "hash", time.Now().Add(time.Hour), nil, time.Now()))
	mock.ExpectQuery("SELECT .* FROM users WHERE id = ?").
		WithArgs(1).
		WillReturnRows(sqlmock.NewRows(userColumns).
			AddRow(1, "test@example.com", "hash", "F", "L", "user", true, time.Now(), time.Now()))
	mock.ExpectExec("UPDATE refresh_tokens SET revoked_at").
		WithArgs(sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("INSERT INTO refresh_tokens").
		WithArgs(1, sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(2, 1))
	mock.ExpectCommit()
	tokens, _, err := service.RefreshTokens(ctx, validToken)
	assert.NoError(t, err)
	assert.NotEmpty(t, tokens.AccessToken)
}

func TestAuthService_Logout(t *testing.T) {
	service, mock, _, _ := setupAuthServiceHelper(t)
	defer func() {
		assert.NoError(t, mock.ExpectationsWereMet())
	}()
	ctx := context.Background()
	token := "some-token"
	tokenHash := service.passwordService.HashToken(token)

	// 1. Success
	mock.ExpectExec("UPDATE refresh_tokens SET revoked_at").
		WithArgs(tokenHash).
		WillReturnResult(sqlmock.NewResult(1, 1))
	err := service.Logout(ctx, token)
	assert.NoError(t, err)

	// 2. DB Error
	mock.ExpectExec("UPDATE refresh_tokens SET revoked_at").
		WithArgs(tokenHash).
		WillReturnError(errors.New("db fail"))
	err = service.Logout(ctx, token)
	assert.Error(t, err)
}

// TestAuthService_Register tests the successful registration of a new user.
func TestAuthService_Register(t *testing.T) {
	service, mock, _, passService := setupAuthServiceHelper(t)
	defer func() {
		assert.NoError(t, mock.ExpectationsWereMet())
	}()

	ctx := context.Background()
	email := "newuser@example.com"
	password := "SecurePass123!"
	firstName := "John"
	lastName := "Doe"
	req := users.CreateUserRequest{
		Email:     email,
		Password:  password,
		FirstName: firstName,
		LastName:  lastName,
		// Role is intentionally omitted or set to "user". The service should force it to "user".
	}

	// Mock: Check if user already exists (should return sql.ErrNoRows)
	mock.ExpectQuery("SELECT (.+) FROM users WHERE email = ?").
		WithArgs(email).
		WillReturnError(sql.ErrNoRows)

	// Mock: Insert new user. The SQLC query CreateUser uses 'execresult', so we use ExpectExec.
	// We use AnyArg() for the password hash because bcrypt generates a different hash each time.
	// The role should be forced to "user" by the service logic before the DB call.
	mock.ExpectExec("INSERT INTO users (.+)").
		WithArgs(email, sqlmock.AnyArg(), firstName, lastName, "user", true). // Use AnyArg() for the hash
		WillReturnResult(sqlmock.NewResult(1, 1))                             // Affected rows = 1

	// Mock: Fetch the created user by email to return the full user object.
	// This matches the subsequent call made by the service.
	userColumns := []string{"id", "email", "password_hash", "first_name", "last_name", "role", "is_active", "created_at", "updated_at"}
	// Generate the hash that will be returned by the SELECT query. It can be different from the one sent to INSERT.
	hashedPass, _ := passService.Hash(ctx, password)
	mock.ExpectQuery(`SELECT (.+) FROM users WHERE id = \? AND is_active = TRUE LIMIT 1`).
		WithArgs(1). // ID of newly created user
		WillReturnRows(sqlmock.NewRows(userColumns).
			AddRow(1, email, hashedPass, firstName, lastName, "user", true, time.Now(), time.Now()))

	// Execute the function
	user, err := service.Register(ctx, req)

	// Assertions
	assert.NoError(t, err)
	assert.NotNil(t, user)
	assert.Equal(t, email, user.Email)
	assert.Equal(t, firstName, user.FirstName)
	assert.Equal(t, lastName, user.LastName)
	// The role should be forced to "user" regardless of any input value.
	assert.Equal(t, "user", user.Role)
}

// TestAuthService_Register_DuplicateUser tests the scenario where a user tries to register with an existing email.
func TestAuthService_Register_DuplicateUser(t *testing.T) {
	service, mock, _, _ := setupAuthServiceHelper(t)
	defer func() {
		assert.NoError(t, mock.ExpectationsWereMet())
	}()

	ctx := context.Background()
	email := "existing@example.com"
	password := "SomePassword123!"
	req := users.CreateUserRequest{
		Email:     email,
		Password:  password,
		FirstName: "Jane",
		LastName:  "Doe",
		Role:      "admin", // This should be ignored anyway for registration
	}

	// Mock: Check if user already exists (should find a user).
	// This should happen first and return the existing user, causing an error.
	userColumns := []string{"id", "email", "password_hash", "first_name", "last_name", "role", "is_active", "created_at", "updated_at"}
	mock.ExpectQuery("SELECT (.+) FROM users WHERE email = ?").
		WithArgs(email).
		WillReturnRows(sqlmock.NewRows(userColumns).
			AddRow(1, email, "hashed_pass", "Existing", "User", "user", true, time.Now(), time.Now()))

	// Execute the function
	user, err := service.Register(ctx, req)

	// Assertions
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
	assert.Nil(t, user)
}

// TestAuthService_Register_DBErrorOnCreate tests the scenario where the user check passes,
// but the database insertion fails.
func TestAuthService_Register_DBErrorOnCreate(t *testing.T) {
	service, mock, _, _ := setupAuthServiceHelper(t)
	defer func() {
		assert.NoError(t, mock.ExpectationsWereMet())
	}()

	ctx := context.Background()
	email := "newuser@example.com"
	password := "SecurePass123!"
	req := users.CreateUserRequest{
		Email:     email,
		Password:  password,
		FirstName: "John",
		LastName:  "Doe",
	}

	// Mock: Check if user already exists (should return sql.ErrNoRows, meaning user does not exist)
	mock.ExpectQuery("SELECT (.+) FROM users WHERE email = ?").
		WithArgs(email).
		WillReturnError(sql.ErrNoRows)

	// Mock: Insert new user, but it fails. Use AnyArg() for the password hash.
	mock.ExpectExec("INSERT INTO users (.+)").
		WithArgs(email, sqlmock.AnyArg(), "John", "Doe", "user", true). // Use AnyArg() for the hash
		WillReturnError(errors.New("database error"))

	// Execute the function
	user, err := service.Register(ctx, req)

	// Assertions
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "database error")
	assert.Nil(t, user)
}
