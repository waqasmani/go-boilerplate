package users

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/waqasmani/go-boilerplate/internal/infrastructure/security"
	"github.com/waqasmani/go-boilerplate/internal/infrastructure/sqlc"
)

func setupUserServiceHelper(t *testing.T) (*UsersService, sqlmock.Sqlmock) {
	db, mock, err := sqlmock.New()
	assert.NoError(t, err)
	queries := sqlc.New(db)
	repo := sqlc.NewRepository(db)
	passService := security.NewPasswordService(4)
	service := NewUsersService(queries, passService, repo)
	return service, mock
}

func TestUsersService_CreateUser(t *testing.T) {
	service, mock := setupUserServiceHelper(t)
	defer mock.ExpectationsWereMet()
	ctx := context.Background()
	req := CreateUserRequest{
		Email: "new@example.com", Password: "SecurePass123!", FirstName: "F", LastName: "L", Role: "user",
	}

	userColumns := []string{"id", "email", "password_hash", "first_name", "last_name", "role", "is_active", "created_at", "updated_at"}

	mock.ExpectQuery("SELECT .* FROM users WHERE email = ?").
		WithArgs(req.Email).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectExec("INSERT INTO users").WillReturnResult(sqlmock.NewResult(10, 1))
	mock.ExpectQuery("SELECT .* FROM users WHERE id = ?").WithArgs(10).
		WillReturnRows(sqlmock.NewRows(userColumns).
			AddRow(10, req.Email, "hash", "F", "L", "user", true, time.Now(), time.Now()))
	res, err := service.CreateUser(ctx, req)
	assert.NoError(t, err)
	assert.Equal(t, uint64(10), res.ID)
}

func TestUsersService_UpdateUser(t *testing.T) {
	service, mock := setupUserServiceHelper(t)
	defer mock.ExpectationsWereMet()
	ctx := context.Background()

	userColumns := []string{"id", "email", "password_hash", "first_name", "last_name", "role", "is_active", "created_at", "updated_at"}

	mock.ExpectBegin()
	mock.ExpectQuery("SELECT .* FROM users WHERE id = ?").
		WithArgs(1).
		WillReturnRows(sqlmock.NewRows(userColumns).
			AddRow(1, "e", "h", "Old", "Old", "user", true, time.Now(), time.Now()))
	mock.ExpectExec("UPDATE users").
		WithArgs("A", "B", 1).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("SELECT .* FROM users WHERE id = ?").
		WithArgs(1).
		WillReturnRows(sqlmock.NewRows(userColumns).
			AddRow(1, "e", "h", "A", "B", "user", true, time.Now(), time.Now()))
	mock.ExpectCommit()
	res, err := service.UpdateUser(ctx, 1, UpdateUserRequest{FirstName: "A", LastName: "B"})
	assert.NoError(t, err)
	assert.Equal(t, "A", res.FirstName)
}

func TestUsersService_ChangePassword(t *testing.T) {
	service, mock := setupUserServiceHelper(t)
	defer mock.ExpectationsWereMet()
	ctx := context.Background()

	userColumns := []string{"id", "email", "password_hash", "first_name", "last_name", "role", "is_active", "created_at", "updated_at"}

	mock.ExpectQuery("SELECT .* FROM users WHERE id = ?").WillReturnError(sql.ErrNoRows)
	err := service.ChangePassword(ctx, 1, ChangePasswordRequest{})
	assert.Error(t, err)

	passSvc := security.NewPasswordService(4)
	oldHash, _ := passSvc.Hash(ctx, "OldPass123!")
	mock.ExpectQuery("SELECT .* FROM users WHERE id = ?").
		WithArgs(1).
		WillReturnRows(sqlmock.NewRows(userColumns).
			AddRow(1, "e", oldHash, "F", "L", "user", true, time.Now(), time.Now()))
	mock.ExpectExec("UPDATE users").
		WithArgs(sqlmock.AnyArg(), 1).
		WillReturnResult(sqlmock.NewResult(0, 1))
	err = service.ChangePassword(ctx, 1, ChangePasswordRequest{CurrentPassword: "OldPass123!", NewPassword: "NewSecurePass123!"})
	assert.NoError(t, err)
}
