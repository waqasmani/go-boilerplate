package users

import (
	"time"

	"github.com/waqasmani/go-boilerplate/internal/infrastructure/security"
	"github.com/waqasmani/go-boilerplate/internal/infrastructure/sqlc"
)

type UsersService struct {
	queries         sqlc.Querier
	passwordService *security.PasswordService
	repo            *sqlc.Repository
}

type CreateUserRequest struct {
	Email     string `json:"email" validate:"required,email"`
	Password  string `json:"password" validate:"required,min=8"`
	FirstName string `json:"first_name" validate:"required,min=2,max=100"`
	LastName  string `json:"last_name" validate:"required,min=2,max=100"`
	Role      string `json:"role" validate:"required,oneof=user admin"`
	IsActive  bool   `json:"is_active"`
}

type UpdateUserRequest struct {
	FirstName string `json:"first_name" validate:"required,min=2,max=100"`
	LastName  string `json:"last_name" validate:"required,min=2,max=100"`
}

type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password" validate:"required,min=8"`
	NewPassword     string `json:"new_password" validate:"required,min=8"`
}

type UserResponse struct {
	ID        uint64    `json:"id"`
	Email     string    `json:"email"`
	FirstName string    `json:"first_name"`
	LastName  string    `json:"last_name"`
	Role      string    `json:"role"`
	IsActive  bool      `json:"is_active"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}
