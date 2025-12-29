package users

import (
	"database/sql"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/waqasmani/go-boilerplate/internal/infrastructure/middleware"
	"github.com/waqasmani/go-boilerplate/internal/infrastructure/sqlc"
	"github.com/waqasmani/go-boilerplate/internal/shared/errors"
	"github.com/waqasmani/go-boilerplate/internal/shared/utils"
	"github.com/waqasmani/go-boilerplate/internal/shared/validator"
)

type Handler struct {
	service *Service
}

func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
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

type UpdateUserRequest struct {
	FirstName string `json:"first_name" validate:"required"`
	LastName  string `json:"last_name" validate:"required"`
}

type UpdatePasswordRequest struct {
	OldPassword string `json:"old_password" validate:"required"`
	NewPassword string `json:"new_password" validate:"required,min=8"`
}

type CreateUserRequest struct {
	Email     string `json:"email" validate:"required,email"`
	Password  string `json:"password" validate:"required,min=8"`
	FirstName string `json:"first_name" validate:"required"`
	LastName  string `json:"last_name" validate:"required"`
	Role      string `json:"role" validate:"required,oneof=user admin"`
}

type ListUsersResponse struct {
	Users []UserResponse `json:"users"`
	Total int64          `json:"total"`
	Limit int            `json:"limit"`
	Page  int            `json:"page"`
}

// GetUser godoc
// @Summary Get user by ID
// @Description Get user details by ID
// @Tags Users
// @Accept json
// @Produce json
// @Param id path int true "User ID"
// @Success 200 {object} utils.Response{data=UserResponse}
// @Failure 401 {object} utils.Response
// @Failure 403 {object} utils.Response
// @Failure 404 {object} utils.Response
// @Security     Bearer
// @Router /users/{id} [get]
func (h *Handler) GetUser(c *gin.Context) {
	userID, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		utils.Error(c, errors.New(errors.ErrCodeBadRequest, "Invalid user ID"))
		return
	}

	// CRITICAL: Check authorization before fetching data
	if err := middleware.IsAdminOrOwner(c, userID); err != nil {
		utils.Error(c, err)
		return
	}

	user, err := h.service.queries.GetUserByID(c.Request.Context(), userID)
	if err != nil {
		if err == sql.ErrNoRows {
			utils.Error(c, errors.ErrNotFound)
			return
		}
		utils.Error(c, errors.Wrap(err, errors.ErrCodeInternal, "Failed to fetch user"))
		return
	}

	utils.Success(c, http.StatusOK, UserResponse{
		ID:        user.ID,
		Email:     user.Email,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		Role:      user.Role,
		IsActive:  user.IsActive,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	})
}

// UpdateUser godoc
// @Summary Update user profile
// @Description Update user's first and last name
// @Tags Users
// @Accept json
// @Produce json
// @Param id path int true "User ID"
// @Param body body UpdateUserRequest true "Updated user details"
// @Success 200 {object} utils.Response{data=UserResponse}
// @Failure 400 {object} utils.Response
// @Failure 401 {object} utils.Response
// @Failure 403 {object} utils.Response
// @Failure 404 {object} utils.Response
// @Security     Bearer
// @Router /users/{id} [put]
func (h *Handler) UpdateUser(c *gin.Context) {
	userID, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		utils.Error(c, errors.New(errors.ErrCodeBadRequest, "Invalid user ID"))
		return
	}

	// CRITICAL: Check authorization before processing update
	if err := middleware.IsAdminOrOwner(c, userID); err != nil {
		utils.Error(c, err)
		return
	}

	var req UpdateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.Error(c, errors.Wrap(err, errors.ErrCodeBadRequest, "Invalid request body"))
		return
	}

	if err := h.service.validator.Validate(req); err != nil {
		validationErrors := validator.TranslateValidationErrors(err)
		utils.Error(c, errors.WithDetails(errors.ErrCodeValidation, "Validation failed", validationErrors))
		return
	}

	if err := h.service.UpdateUser(c.Request.Context(), userID, req.FirstName, req.LastName); err != nil {
		utils.Error(c, err)
		return
	}
	user, err := h.service.queries.GetUserByID(c.Request.Context(), userID)
	if err != nil {
		utils.Error(c, errors.Wrap(err, errors.ErrCodeInternal, "Failed to fetch updated user"))
		return
	}

	utils.Success(c, http.StatusOK, UserResponse{
		ID:        user.ID,
		Email:     user.Email,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		Role:      user.Role,
		IsActive:  user.IsActive,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	})
}

// UpdatePassword godoc
// @Summary Update user password
// @Description Change user's password
// @Tags Users
// @Accept json
// @Produce json
// @Param id path int true "User ID"
// @Param body body UpdatePasswordRequest true "Password update details"
// @Success 200 {object} utils.Response{data=map[string]string}
// @Failure 400 {object} utils.Response
// @Failure 401 {object} utils.Response
// @Failure 403 {object} utils.Response
// @Failure 404 {object} utils.Response
// @Security     Bearer
// @Router /users/{id}/password [put]
func (h *Handler) UpdatePassword(c *gin.Context) {
	userID, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		utils.Error(c, errors.New(errors.ErrCodeBadRequest, "Invalid user ID"))
		return
	}

	// CRITICAL: Strict ownership check - even admins cannot change other users' passwords
	if err := middleware.RequireOwnership(c, userID); err != nil {
		utils.Error(c, err)
		return
	}

	var req UpdatePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.Error(c, errors.Wrap(err, errors.ErrCodeBadRequest, "Invalid request body"))
		return
	}

	if err := h.service.validator.Validate(req); err != nil {
		validationErrors := validator.TranslateValidationErrors(err)
		utils.Error(c, errors.WithDetails(errors.ErrCodeValidation, "Validation failed", validationErrors))
		return
	}

	if err := h.service.UpdatePassword(c.Request.Context(), userID, req.OldPassword, req.NewPassword); err != nil {
		utils.Error(c, err)
		return
	}

	utils.Success(c, http.StatusOK, gin.H{"message": "Password updated successfully"})
}

// ListUsers godoc
// @Summary List users
// @Description Get paginated list of users (admin only)
// @Tags Users
// @Accept json
// @Produce json
// @Param limit query int false "Page size" default(20) minimum(1) maximum(100)
// @Param page query int false "Page number" default(1) minimum(1)
// @Success 200 {object} utils.Response{data=ListUsersResponse}
// @Failure 401 {object} utils.Response
// @Failure 403 {object} utils.Response
// @Security     Bearer
// @Router /users [get]
func (h *Handler) ListUsers(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))

	// Validate pagination limits
	if limit < 1 {
		limit = 20
	}
	if limit > 100 {
		limit = 100 // Enforce max limit
	}
	if page < 1 {
		page = 1
	}

	offset := (page - 1) * limit

	users, err := h.service.queries.ListUsers(c.Request.Context(), sqlc.ListUsersParams{
		Limit:  int32(limit),
		Offset: int32(offset),
	})
	if err != nil {
		utils.Error(c, errors.Wrap(err, errors.ErrCodeInternal, "Failed to fetch users"))
		return
	}

	total, err := h.service.queries.CountUsers(c.Request.Context())
	if err != nil {
		utils.Error(c, errors.Wrap(err, errors.ErrCodeInternal, "Failed to count users"))
		return
	}

	userResponses := make([]UserResponse, len(users))
	for i, user := range users {
		userResponses[i] = UserResponse{
			ID:        user.ID,
			Email:     user.Email,
			FirstName: user.FirstName,
			LastName:  user.LastName,
			Role:      user.Role,
			IsActive:  user.IsActive,
			CreatedAt: user.CreatedAt,
			UpdatedAt: user.UpdatedAt,
		}
	}

	utils.Success(c, http.StatusOK, ListUsersResponse{
		Users: userResponses,
		Total: total,
		Limit: limit,
		Page:  page,
	})
}

// CreateUser godoc
// @Summary Create user
// @Description Create a new user (admin only)
// @Tags Users
// @Accept json
// @Produce json
// @Param body body CreateUserRequest true "User creation details"
// @Success 201 {object} utils.Response{data=UserResponse}
// @Failure 400 {object} utils.Response
// @Failure 401 {object} utils.Response
// @Failure 403 {object} utils.Response
// @Failure 409 {object} utils.Response
// @Security     Bearer
// @Router /users [post]
func (h *Handler) CreateUser(c *gin.Context) {
	var req CreateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.Error(c, errors.Wrap(err, errors.ErrCodeBadRequest, "Invalid request body"))
		return
	}

	if err := h.service.validator.Validate(req); err != nil {
		validationErrors := validator.TranslateValidationErrors(err)
		utils.Error(c, errors.WithDetails(errors.ErrCodeValidation, "Validation failed", validationErrors))
		return
	}

	user, err := h.service.CreateUser(c.Request.Context(), req.Email, req.Password, req.FirstName, req.LastName, req.Role)
	if err != nil {
		utils.Error(c, err)
		return
	}

	utils.Success(c, http.StatusCreated, UserResponse{
		ID:        user.ID,
		Email:     user.Email,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		Role:      user.Role,
		IsActive:  user.IsActive,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	})
}

// DeleteUser godoc
// @Summary Delete user
// @Description Soft delete a user (admin only)
// @Tags Users
// @Accept json
// @Produce json
// @Param id path int true "User ID"
// @Success 204
// @Failure 400 {object} utils.Response
// @Failure 401 {object} utils.Response
// @Failure 403 {object} utils.Response
// @Failure 404 {object} utils.Response
// @Security     Bearer
// @Router /users/{id} [delete]
func (h *Handler) DeleteUser(c *gin.Context) {
	userID, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		utils.Error(c, errors.New(errors.ErrCodeBadRequest, "Invalid user ID"))
		return
	}

	// CRITICAL: Prevent admins from deleting their own account
	authUserID, err := middleware.GetCurrentUserID(c)
	if err != nil {
		utils.Error(c, err)
		return
	}

	if authUserID == userID {
		utils.Error(c, errors.New(errors.ErrCodeBadRequest, "Cannot delete your own account"))
		return
	}

	if err := h.service.DeleteUser(c.Request.Context(), userID); err != nil {
		utils.Error(c, err)
		return
	}

	c.Status(http.StatusNoContent)
}
