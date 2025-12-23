package auth

import (
	"github.com/waqasmani/go-boilerplate/internal/infrastructure/security"
	"github.com/waqasmani/go-boilerplate/internal/infrastructure/sqlc"
)

type AuthService struct {
	queries         sqlc.Querier
	jwtService      *security.JWTService
	passwordService *security.PasswordService
	repo            *sqlc.Repository
}

type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=8"`
}

type Tokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}
