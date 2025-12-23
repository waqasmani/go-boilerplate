package auth

import (
	"context"
	"database/sql"
	"time"

	"github.com/waqasmani/go-boilerplate/internal/infrastructure/security"
	"github.com/waqasmani/go-boilerplate/internal/infrastructure/sqlc"
	"github.com/waqasmani/go-boilerplate/internal/modules/users"
	"github.com/waqasmani/go-boilerplate/internal/shared/errors"
)

func NewAuthService(queries sqlc.Querier, repo *sqlc.Repository, jwtService *security.JWTService, passwordService *security.PasswordService) *AuthService {
	return &AuthService{
		queries:         queries,
		repo:            repo,
		jwtService:      jwtService,
		passwordService: passwordService,
	}
}

func (s *AuthService) Login(ctx context.Context, req LoginRequest) (*Tokens, uint64, error) {
	user, err := s.queries.GetUserByEmail(ctx, req.Email)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, 0, errors.ErrInvalidCredentials
		}
		return nil, 0, errors.Wrap(err, errors.ErrCodeInternal, "Failed to find user")
	}

	if !user.IsActive {
		return nil, 0, errors.Wrap(errors.ErrUnauthorized, errors.ErrCodeUnauthorized, "Account is inactive")
	}

	if err := s.passwordService.Compare(ctx, user.PasswordHash, req.Password); err != nil {
		return nil, 0, errors.ErrInvalidCredentials
	}

	accessToken, err := s.jwtService.GenerateAccessToken(ctx, user.ID, user.Email, user.Role)
	if err != nil {
		return nil, 0, errors.Wrap(err, errors.ErrCodeInternal, "Failed to generate access token")
	}

	refreshToken, err := s.jwtService.GenerateRefreshToken(ctx, user.ID, user.Email)
	if err != nil {
		return nil, 0, errors.Wrap(err, errors.ErrCodeInternal, "Failed to generate refresh token")
	}

	tokenHash := s.passwordService.HashToken(refreshToken)

	expiresAt := time.Now().Add(s.jwtService.GetRefreshExpiry())
	err = s.queries.CreateRefreshToken(ctx, sqlc.CreateRefreshTokenParams{
		UserID:    user.ID,
		TokenHash: tokenHash,
		ExpiresAt: expiresAt,
	})
	if err != nil {
		return nil, 0, errors.Wrap(err, errors.ErrCodeInternal, "Failed to store refresh token")
	}

	return &Tokens{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, user.ID, nil
}

func (s *AuthService) Register(ctx context.Context, req users.CreateUserRequest) (*users.UserResponse, error) {
	// Check if user already exists
	_, err := s.queries.GetUserByEmail(ctx, req.Email)
	if err == nil {
		return nil, errors.ErrConflict
	}
	if err != sql.ErrNoRows {
		return nil, errors.Wrap(err, errors.ErrCodeInternal, "Failed to check user existence")
	}

	// Hash the password
	passwordHash, err := s.passwordService.Hash(ctx, req.Password)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeInternal, "Failed to hash password")
	}

	// Create the user with default role "user"
	result, err := s.queries.CreateUser(ctx, sqlc.CreateUserParams{
		Email:        req.Email,
		PasswordHash: passwordHash,
		FirstName:    req.FirstName,
		LastName:     req.LastName,
		Role:         "user", // Default role for new registrations
		IsActive:     true,
	})
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeInternal, "Failed to create user")
	}

	// Get the newly created user ID
	userID, err := result.LastInsertId()
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeInternal, "Failed to get user ID")
	}

	// Fetch the created user
	user, err := s.queries.GetUserByID(ctx, uint64(userID))
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeInternal, "Failed to fetch created user")
	}

	// Return user response without sensitive information
	return &users.UserResponse{
		ID:        user.ID,
		Email:     user.Email,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		Role:      user.Role,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	}, nil
}

func (s *AuthService) RefreshTokens(ctx context.Context, refreshToken string) (*Tokens, uint64, error) {
	claims, err := s.jwtService.ValidateRefreshToken(ctx, refreshToken)
	if err != nil {
		return nil, 0, err
	}

	tokenHash := s.passwordService.HashToken(refreshToken)
	var tokens *Tokens
	var userID uint64
	// Use transaction to prevent concurrent token usage
	err = s.repo.WithTransaction(ctx, func(q *sqlc.Queries) error {
		tokenRecord, err := q.GetRefreshToken(ctx, tokenHash)
		if err != nil {
			if err == sql.ErrNoRows {
				return errors.ErrInvalidToken
			}
			return errors.Wrap(err, errors.ErrCodeInternal, "Failed to get refresh token from database")
		}

		if tokenRecord.ExpiresAt.Before(time.Now()) {
			return errors.ErrExpiredToken
		}

		if tokenRecord.UserID != claims.UserID {
			return errors.ErrInvalidToken
		}

		user, err := q.GetUserByID(ctx, claims.UserID)
		if err != nil {
			if err == sql.ErrNoRows {
				return errors.Wrap(errors.ErrUnauthorized, errors.ErrCodeUnauthorized, "User not found")
			}
			return errors.Wrap(err, errors.ErrCodeInternal, "Failed to fetch user")
		}

		if !user.IsActive {
			return errors.Wrap(errors.ErrUnauthorized, errors.ErrCodeUnauthorized, "Account is inactive")
		}

		// Revoke the token within the same transaction
		if err := q.RevokeRefreshToken(ctx, tokenHash); err != nil {
			return errors.Wrap(err, errors.ErrCodeInternal, "Failed to revoke refresh token")
		}

		accessToken, err := s.jwtService.GenerateAccessToken(ctx, user.ID, user.Email, user.Role)
		if err != nil {
			return errors.Wrap(err, errors.ErrCodeInternal, "Failed to generate access token")
		}

		newRefreshToken, err := s.jwtService.GenerateRefreshToken(ctx, user.ID, user.Email)
		if err != nil {
			return errors.Wrap(err, errors.ErrCodeInternal, "Failed to generate refresh token")
		}

		newTokenHash := s.passwordService.HashToken(newRefreshToken)
		expiresAt := time.Now().Add(s.jwtService.GetRefreshExpiry())

		if err := q.CreateRefreshToken(ctx, sqlc.CreateRefreshTokenParams{
			UserID:    user.ID,
			TokenHash: newTokenHash,
			ExpiresAt: expiresAt,
		}); err != nil {
			return errors.Wrap(err, errors.ErrCodeInternal, "Failed to store new refresh token")
		}

		tokens = &Tokens{
			AccessToken:  accessToken,
			RefreshToken: newRefreshToken,
		}
		userID = user.ID
		return nil
	})

	if err != nil {
		return nil, 0, err
	}

	return tokens, userID, nil
}

func (s *AuthService) Logout(ctx context.Context, refreshToken string) error {
	tokenHash := s.passwordService.HashToken(refreshToken)

	if err := s.queries.RevokeRefreshToken(ctx, tokenHash); err != nil {
		return errors.Wrap(err, errors.ErrCodeInternal, "Failed to revoke refresh token")
	}

	return nil
}
