package users

import (
	"context"
	"database/sql"
	"log"
	"time"

	dberrors "github.com/waqasmani/go-boilerplate/internal/infrastructure/database/errors"
	"github.com/waqasmani/go-boilerplate/internal/infrastructure/observability"
	"github.com/waqasmani/go-boilerplate/internal/infrastructure/security"
	"github.com/waqasmani/go-boilerplate/internal/infrastructure/sqlc"
	apperrors "github.com/waqasmani/go-boilerplate/internal/shared/errors"
	"github.com/waqasmani/go-boilerplate/internal/shared/validator"
)

type Service struct {
	queries         *sqlc.Queries
	repo            *sqlc.Repository
	passwordService *security.PasswordService
	validator       *validator.Validator
	auditLogger     *observability.AuditLogger
	logger          *observability.Logger
}

func NewService(
	queries *sqlc.Queries,
	repo *sqlc.Repository,
	passwordService *security.PasswordService,
	validator *validator.Validator,
	auditLogger *observability.AuditLogger,
	logger *observability.Logger,
) *Service {
	return &Service{
		queries:         queries,
		repo:            repo,
		passwordService: passwordService,
		validator:       validator,
		auditLogger:     auditLogger,
		logger:          logger,
	}
}

func (s *Service) UpdateUser(ctx context.Context, userID uint64, firstName, lastName string) error {
	// Wrap the update in a retryable transaction
	return dberrors.RetryOperation(ctx, "update_user", func(attempt uint64) error {
		start := time.Now()
		defer func() {
			duration := time.Since(start)
			if duration > 100*time.Millisecond {
				// Log slow queries
				if s.logger != nil {
					s.logger.Warn(ctx, "Slow database operation",
						s.logger.Field("operation", "update_user"),
						s.logger.Field("duration_ms", int64(duration.Milliseconds())),
						s.logger.Field("attempt", int64(attempt)),
					)
				} else {
					log.Printf("Slow database operation: update_user took %dms on attempt %d", duration.Milliseconds(), attempt)
				}
			}
		}()

		err := s.queries.UpdateUser(ctx, sqlc.UpdateUserParams{
			ID:        userID,
			FirstName: firstName,
			LastName:  lastName,
		})
		if err != nil {
			return err
		}
		return nil
	}, dberrors.DefaultRetryConfig(), nil, nil)
}

func (s *Service) UpdatePassword(ctx context.Context, userID uint64, oldPassword, newPassword string) error {
	user, err := s.queries.GetUserByID(ctx, userID)
	if err != nil {
		if err == sql.ErrNoRows {
			return apperrors.ErrNotFound
		}
		return apperrors.Wrap(err, apperrors.ErrCodeInternal, "Failed to fetch user")
	}

	if err := s.passwordService.Compare(ctx, user.PasswordHash, oldPassword); err != nil {
		s.auditLogger.LogSecurityEvent(ctx, observability.SecurityEvent{
			Type:     "user",
			Action:   "password_change_failed",
			UserID:   userID,
			Resource: "user",
			Success:  false,
		})
		return apperrors.New(apperrors.ErrCodeUnauthorized, "Current password is incorrect")
	}

	newPasswordHash, err := s.passwordService.Hash(ctx, newPassword)
	if err != nil {
		return apperrors.Wrap(err, apperrors.ErrCodeValidation, "Invalid password")
	}

	err = s.repo.WithTransaction(ctx, func(q *sqlc.Queries) error {
		// Update the password
		err := q.UpdateUserPassword(ctx, sqlc.UpdateUserPasswordParams{
			ID:           userID,
			PasswordHash: newPasswordHash,
		})
		if err != nil {
			return err
		}

		// REFACTORED: Revoke all active sessions for this user
		// This prevents an attacker with a stolen refresh token from remaining logged in.
		return q.RevokeAllUserRefreshTokens(ctx, userID)
	})
	if err != nil {
		return apperrors.Wrap(err, apperrors.ErrCodeInternal, "Failed to update password")
	}

	s.auditLogger.LogSecurityEvent(ctx, observability.SecurityEvent{
		Type:     "user",
		Action:   "password_change",
		UserID:   userID,
		Resource: "user",
		Success:  true,
	})

	return nil
}

func (s *Service) CreateUser(ctx context.Context, email, password, firstName, lastName, role string) (*sqlc.User, error) {
	existingUser, err := s.queries.GetUserByEmail(ctx, email)
	if err == nil && existingUser.ID > 0 {
		return nil, apperrors.New(apperrors.ErrCodeConflict, "Email already registered")
	}

	if err != nil && err != sql.ErrNoRows {
		return nil, apperrors.Wrap(err, apperrors.ErrCodeInternal, "Failed to check existing user")
	}

	passwordHash, err := s.passwordService.Hash(ctx, password)
	if err != nil {
		return nil, apperrors.Wrap(err, apperrors.ErrCodeValidation, "Invalid password")
	}

	result, err := s.queries.CreateUser(ctx, sqlc.CreateUserParams{
		Email:        email,
		PasswordHash: passwordHash,
		FirstName:    firstName,
		LastName:     lastName,
		Role:         role,
		IsActive:     true,
	})
	if err != nil {
		return nil, apperrors.Wrap(err, apperrors.ErrCodeInternal, "Failed to create user")
	}

	userID, err := result.LastInsertId()
	if err != nil {
		return nil, apperrors.Wrap(err, apperrors.ErrCodeInternal, "Failed to get user ID")
	}

	user, err := s.queries.GetUserByID(ctx, uint64(userID))
	if err != nil {
		return nil, apperrors.Wrap(err, apperrors.ErrCodeInternal, "Failed to fetch created user")
	}

	s.auditLogger.LogSecurityEvent(ctx, observability.SecurityEvent{
		Type:     "user",
		Action:   "create",
		UserID:   user.ID,
		Resource: "user",
		Success:  true,
	})

	return &user, nil
}

func (s *Service) DeleteUser(ctx context.Context, userID uint64) error {
	_, err := s.queries.GetUserByID(ctx, userID)
	if err != nil {
		if err == sql.ErrNoRows {
			return apperrors.ErrNotFound
		}
		return apperrors.Wrap(err, apperrors.ErrCodeInternal, "Failed to fetch user")
	}

	err = s.queries.DeactivateUser(ctx, userID)
	if err != nil {
		return apperrors.Wrap(err, apperrors.ErrCodeInternal, "Failed to delete user")
	}

	s.auditLogger.LogSecurityEvent(ctx, observability.SecurityEvent{
		Type:     "user",
		Action:   "delete",
		UserID:   userID,
		Resource: "user",
		Success:  true,
	})

	return nil
}
