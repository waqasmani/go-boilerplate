package users

import (
	"context"
	"database/sql"

	"github.com/waqasmani/go-boilerplate/internal/infrastructure/security"
	"github.com/waqasmani/go-boilerplate/internal/infrastructure/sqlc"
	"github.com/waqasmani/go-boilerplate/internal/shared/errors"
)

func NewUsersService(queries sqlc.Querier, passwordService *security.PasswordService, repo *sqlc.Repository) *UsersService {
	return &UsersService{
		queries:         queries,
		passwordService: passwordService,
		repo:            repo,
	}
}

func (s *UsersService) CreateUser(ctx context.Context, req CreateUserRequest) (*UserResponse, error) {
	_, err := s.queries.GetUserByEmail(ctx, req.Email)
	if err == nil {
		return nil, errors.ErrConflict
	}

	if err != sql.ErrNoRows {
		return nil, errors.Wrap(err, errors.ErrCodeInternal, "Failed to check user existence")
	}

	passwordHash, err := s.passwordService.Hash(ctx, req.Password)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeInternal, "Failed to hash password")
	}

	result, err := s.queries.CreateUser(ctx, sqlc.CreateUserParams{
		Email:        req.Email,
		PasswordHash: passwordHash,
		FirstName:    req.FirstName,
		LastName:     req.LastName,
		Role:         req.Role,
		IsActive:     true,
	})
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeInternal, "Failed to create user")
	}

	userID, err := result.LastInsertId()
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeInternal, "Failed to create user")
	}
	user, err := s.queries.GetUserByID(ctx, uint64(userID))
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeInternal, "Failed to fetch created user")
	}

	return &UserResponse{
		ID:        user.ID,
		Email:     user.Email,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		Role:      user.Role,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	}, nil
}

func (s *UsersService) GetUserByID(ctx context.Context, userID uint64) (*UserResponse, error) {
	user, err := s.queries.GetUserByID(ctx, userID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.ErrNotFound
		}
		return nil, errors.Wrap(err, errors.ErrCodeInternal, "Failed to get user")
	}

	return &UserResponse{
		ID:        user.ID,
		Email:     user.Email,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		Role:      user.Role,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	}, nil
}

func (s *UsersService) UpdateUser(ctx context.Context, userID uint64, req UpdateUserRequest) (*UserResponse, error) {
	var updatedUser sqlc.User

	err := s.repo.WithTransaction(ctx, func(q *sqlc.Queries) error {
		_, err := q.GetUserByID(ctx, userID)
		if err != nil {
			if err == sql.ErrNoRows {
				return errors.ErrNotFound
			}
			return errors.Wrap(err, errors.ErrCodeInternal, "Failed to get user")
		}

		err = q.UpdateUser(ctx, sqlc.UpdateUserParams{
			FirstName: req.FirstName,
			LastName:  req.LastName,
			ID:        userID,
		})
		if err != nil {
			return errors.Wrap(err, errors.ErrCodeInternal, "Failed to update user")
		}

		updatedUser, err = q.GetUserByID(ctx, userID)
		if err != nil {
			return errors.Wrap(err, errors.ErrCodeInternal, "Failed to fetch updated user")
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return &UserResponse{
		ID:        updatedUser.ID,
		Email:     updatedUser.Email,
		FirstName: updatedUser.FirstName,
		LastName:  updatedUser.LastName,
		Role:      updatedUser.Role,
		CreatedAt: updatedUser.CreatedAt,
		UpdatedAt: updatedUser.UpdatedAt,
	}, nil
}

func (s *UsersService) ChangePassword(ctx context.Context, userID uint64, req ChangePasswordRequest) error {
	user, err := s.queries.GetUserByID(ctx, userID)
	if err != nil {
		if err == sql.ErrNoRows {
			return errors.ErrNotFound
		}
		return errors.Wrap(err, errors.ErrCodeInternal, "Failed to get user")
	}

	if err := s.passwordService.Compare(ctx, user.PasswordHash, req.CurrentPassword); err != nil {
		return errors.ErrInvalidCredentials
	}

	newPasswordHash, err := s.passwordService.Hash(ctx, req.NewPassword)
	if err != nil {
		return errors.Wrap(err, errors.ErrCodeInternal, "Failed to hash new password")
	}

	if err := s.queries.UpdateUserPassword(ctx, sqlc.UpdateUserPasswordParams{
		PasswordHash: newPasswordHash,
		ID:           userID,
	}); err != nil {
		return errors.Wrap(err, errors.ErrCodeInternal, "Failed to update password")
	}

	return nil
}

func (s *UsersService) DeactivateUser(ctx context.Context, userID uint64) error {
	_, err := s.queries.GetUserByID(ctx, userID)
	if err != nil {
		if err == sql.ErrNoRows {
			return errors.ErrNotFound
		}
		return errors.Wrap(err, errors.ErrCodeInternal, "Failed to get user")
	}

	if err := s.queries.DeactivateUser(ctx, userID); err != nil {
		return errors.Wrap(err, errors.ErrCodeInternal, "Failed to deactivate user")
	}

	return nil
}

type ListUsersParams struct {
	Page     int
	PageSize int
}

type ListUsersResponse struct {
	Users      []UserResponse `json:"users"`
	TotalCount int64          `json:"total_count"`
	Page       int            `json:"page"`
	PageSize   int            `json:"page_size"`
}

func (s *UsersService) ListUsers(ctx context.Context, params ListUsersParams) (*ListUsersResponse, error) {
	limit := int32(params.PageSize)
	offset := int32((params.Page - 1) * params.PageSize)

	users, err := s.queries.ListUsers(ctx, sqlc.ListUsersParams{
		Limit:  limit,
		Offset: offset,
	})
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeInternal, "Failed to list users")
	}

	totalCount, err := s.queries.CountUsers(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeInternal, "Failed to count users")
	}

	userResponses := make([]UserResponse, len(users))
	for i, user := range users {
		userResponses[i] = UserResponse{
			ID:        user.ID,
			Email:     user.Email,
			FirstName: user.FirstName,
			LastName:  user.LastName,
			Role:      user.Role,
			CreatedAt: user.CreatedAt,
			UpdatedAt: user.UpdatedAt,
		}
	}

	return &ListUsersResponse{
		Users:      userResponses,
		TotalCount: totalCount,
		Page:       params.Page,
		PageSize:   params.PageSize,
	}, nil
}
