package users

// @Summary List users
// @Description Get paginated list of users (admin only)
// @Tags users
// @Produce json
// @Security Bearer
// @Security X-CSRF-Token
// @Param page query int false "Page number" default(1)
// @Param page_size query int false "Items per page" default(10) maximum(100)
// @Success 200 {object} ListUsersResponse
// @Failure 401 {object} utils.Response
// @Failure 403 {object} utils.Response
// @Router /users/ [get]

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/waqasmani/go-boilerplate/internal/shared/errors"
	"github.com/waqasmani/go-boilerplate/internal/shared/utils"
	"github.com/waqasmani/go-boilerplate/internal/shared/validator"
)

type Handler struct {
	service *UsersService
	v       *validator.Validator
}

func NewHandler(service *UsersService, v *validator.Validator) *Handler {
	return &Handler{
		service: service,
		v:       v,
	}
}

// Middleware to get user ID from context (set by auth middleware)
func getUserIDFromContext(c *gin.Context) (uint64, error) {
	userID, exists := c.Get("user_id")
	if !exists {
		return 0, errors.ErrUnauthorized
	}

	id, ok := userID.(uint64)
	if !ok {
		return 0, errors.Wrap(errors.ErrUnauthorized, errors.ErrCodeInternal, "Invalid user ID type in context")
	}

	return id, nil
}

// @Summary Create user
// @Description Create a new user (admin only)
// @Tags users
// @Accept json
// @Produce json
// @Security Bearer
// @Security X-CSRF-Token
// @Param user body CreateUserRequest true "User creation details"
// @Success 201 {object} UserResponse
// @Failure 400 {object} utils.Response
// @Failure 401 {object} utils.Response
// @Failure 403 {object} utils.Response
// @Failure 409 {object} utils.Response
// @Router /users/ [post]
func (h *Handler) CreateUser(c *gin.Context) {
	var req struct {
		Email     string `json:"email" validate:"required,email"`
		Password  string `json:"password" validate:"required,min=8"`
		FirstName string `json:"first_name" validate:"required,min=2,max=100"`
		LastName  string `json:"last_name" validate:"required,min=2,max=100"`
		Role      string `json:"role" validate:"required,oneof=user admin"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.Error(c, errors.Wrap(err, errors.ErrCodeBadRequest, "Invalid request body"))
		return
	}

	if err := h.v.Validate(req); err != nil {
		utils.Error(c, errors.WithDetails(errors.ErrCodeValidation, "Validation failed", validator.TranslateValidationErrors(err)))
		return
	}

	user, err := h.service.CreateUser(c.Request.Context(), CreateUserRequest{
		Email:     req.Email,
		Password:  req.Password,
		FirstName: req.FirstName,
		LastName:  req.LastName,
		Role:      req.Role,
	})
	if err != nil {
		utils.Error(c, err)
		return
	}

	utils.Success(c, http.StatusCreated, user)
}

// @Summary Get user by ID
// @Description Get user profile by ID
// @Tags users
// @Produce json
// @Security Bearer
// @Param id path string true "User ID"
// @Success 200 {object} UserResponse
// @Failure 400 {object} utils.Response
// @Failure 401 {object} utils.Response
// @Failure 404 {object} utils.Response
// @Router /users/{id} [get]
func (h *Handler) GetUserByID(c *gin.Context) {
	userID, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		utils.Error(c, errors.Wrap(err, errors.ErrCodeBadRequest, "Invalid user ID"))
		return
	}

	user, err := h.service.GetUserByID(c.Request.Context(), userID)
	if err != nil {
		utils.Error(c, err)
		return
	}

	utils.Success(c, http.StatusOK, user)
}

// @Summary Update user
// @Description Update user profile (own profile or admin can update any)
// @Tags users
// @Accept json
// @Produce json
// @Security Bearer
// @Security X-CSRF-Token
// @Param id path string true "User ID"
// @Param user body UpdateUserRequest true "Updated user details"
// @Success 200 {object} UserResponse
// @Failure 400 {object} utils.Response
// @Failure 401 {object} utils.Response
// @Failure 403 {object} utils.Response
// @Failure 404 {object} utils.Response
// @Router /users/{id} [put]
func (h *Handler) UpdateUser(c *gin.Context) {
	// Get user ID from URL param
	userID, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		utils.Error(c, errors.Wrap(err, errors.ErrCodeBadRequest, "Invalid user ID"))
		return
	}

	// Get authenticated user ID from context
	authUserID, err := getUserIDFromContext(c)
	if err != nil {
		utils.Error(c, err)
		return
	}

	// Only allow users to update their own profile or admins to update any profile
	user, err := h.service.GetUserByID(c.Request.Context(), authUserID)
	if err != nil {
		utils.Error(c, err)
		return
	}

	if authUserID != userID && user.Role != "admin" {
		utils.Error(c, errors.ErrForbidden)
		return
	}

	var req struct {
		FirstName string `json:"first_name" validate:"required,min=2,max=100"`
		LastName  string `json:"last_name" validate:"required,min=2,max=100"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.Error(c, errors.Wrap(err, errors.ErrCodeBadRequest, "Invalid request body"))
		return
	}

	if err := h.v.Validate(req); err != nil {
		utils.Error(c, errors.WithDetails(errors.ErrCodeValidation, "Validation failed", validator.TranslateValidationErrors(err)))
		return
	}

	updatedUser, err := h.service.UpdateUser(c.Request.Context(), userID, UpdateUserRequest{
		FirstName: req.FirstName,
		LastName:  req.LastName,
	})
	if err != nil {
		utils.Error(c, err)
		return
	}

	utils.Success(c, http.StatusOK, updatedUser)
}

// @Summary Change password
// @Description Change user password
// @Tags users
// @Accept json
// @Produce json
// @Security Bearer
// @Security X-CSRF-Token
// @Param id path string true "User ID"
// @Param password body ChangePasswordRequest true "Password change details"
// @Success 200 {object} map[string]string
// @Failure 400 {object} utils.Response
// @Failure 401 {object} utils.Response
// @Failure 404 {object} utils.Response
// @Router /users/{id}/password [put]
func (h *Handler) ChangePassword(c *gin.Context) {
	// Get authenticated user ID from context
	userID, err := getUserIDFromContext(c)
	if err != nil {
		utils.Error(c, err)
		return
	}

	var req struct {
		CurrentPassword string `json:"current_password" validate:"required,min=8"`
		NewPassword     string `json:"new_password" validate:"required,min=8"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.Error(c, errors.Wrap(err, errors.ErrCodeBadRequest, "Invalid request body"))
		return
	}

	if err := h.v.Validate(req); err != nil {
		utils.Error(c, errors.WithDetails(errors.ErrCodeValidation, "Validation failed", validator.TranslateValidationErrors(err)))
		return
	}

	if err := h.service.ChangePassword(c.Request.Context(), userID, ChangePasswordRequest{
		CurrentPassword: req.CurrentPassword,
		NewPassword:     req.NewPassword,
	}); err != nil {
		utils.Error(c, err)
		return
	}

	utils.Success(c, http.StatusOK, gin.H{"message": "Password updated successfully"})
}

// @Summary Deactivate user
// @Description Deactivate user account (admin only)
// @Tags users
// @Security Bearer
// @Security X-CSRF-Token
// @Param id path string true "User ID"
// @Success 200 {object} map[string]string
// @Failure 400 {object} utils.Response
// @Failure 401 {object} utils.Response
// @Failure 403 {object} utils.Response
// @Failure 404 {object} utils.Response
// @Router /users/{id} [delete]
func (h *Handler) DeactivateUser(c *gin.Context) {
	// Get authenticated user ID from context
	authUserID, err := getUserIDFromContext(c)
	if err != nil {
		utils.Error(c, err)
		return
	}

	// Check if authenticated user is admin
	authUser, err := h.service.GetUserByID(c.Request.Context(), authUserID)
	if err != nil {
		utils.Error(c, err)
		return
	}

	if authUser.Role != "admin" {
		utils.Error(c, errors.ErrForbidden)
		return
	}

	// Get user ID from URL param
	userID, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		utils.Error(c, errors.Wrap(err, errors.ErrCodeBadRequest, "Invalid user ID"))
		return
	}

	if err := h.service.DeactivateUser(c.Request.Context(), userID); err != nil {
		utils.Error(c, err)
		return
	}

	utils.Success(c, http.StatusOK, gin.H{"message": "User deactivated successfully"})
}

// @Summary List users
// @Description Get paginated list of users (admin only)
// @Tags users
// @Produce json
// @Security Bearer
// @Security X-CSRF-Token
// @Param page query int false "Page number" default(1)
// @Param page_size query int false "Items per page" default(10) maximum(100)
// @Success 200 {object} ListUsersResponse
// @Failure 401 {object} utils.Response
// @Failure 403 {object} utils.Response
// @Router /users/ [get]
func (h *Handler) ListUsers(c *gin.Context) {
	// Get authenticated user ID from context
	authUserID, err := getUserIDFromContext(c)
	if err != nil {
		utils.Error(c, err)
		return
	}

	// Check if authenticated user is admin
	authUser, err := h.service.GetUserByID(c.Request.Context(), authUserID)
	if err != nil {
		utils.Error(c, err)
		return
	}

	if authUser.Role != "admin" {
		utils.Error(c, errors.ErrForbidden)
		return
	}

	// Parse pagination parameters
	page, err := strconv.Atoi(c.DefaultQuery("page", "1"))
	if err != nil || page < 1 {
		page = 1
	}

	pageSize, err := strconv.Atoi(c.DefaultQuery("page_size", "10"))
	if err != nil || pageSize < 1 || pageSize > 100 {
		pageSize = 10
	}

	users, err := h.service.ListUsers(c.Request.Context(), ListUsersParams{
		Page:     page,
		PageSize: pageSize,
	})
	if err != nil {
		utils.Error(c, err)
		return
	}

	utils.Success(c, http.StatusOK, users)
}
