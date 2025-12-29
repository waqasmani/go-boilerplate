package auth

import (
	"database/sql"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/waqasmani/go-boilerplate/internal/infrastructure/middleware"
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

type RegisterRequest struct {
	Email     string `json:"email" validate:"required,email"`
	Password  string `json:"password" validate:"required,min=8"`
	FirstName string `json:"first_name" validate:"required"`
	LastName  string `json:"last_name" validate:"required"`
}

type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

type UserResponse struct {
	ID        uint64    `json:"id"`
	Email     string    `json:"email"`
	FirstName string    `json:"first_name"`
	LastName  string    `json:"last_name"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"created_at"`
}

type AuthResponse struct {
	AccessToken string       `json:"access_token"`
	User        UserResponse `json:"user"`
}

// Register godoc
// @Summary Register a new user
// @Description Create a new user account
// @Tags Authentication
// @Accept json
// @Produce json
// @Param body body RegisterRequest true "User registration details"
// @Success 201 {object} utils.Response{data=UserResponse}
// @Failure 400 {object} utils.Response
// @Failure 409 {object} utils.Response
// @Router /auth/register [post]
func (h *Handler) Register(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.Error(c, errors.Wrap(err, errors.ErrCodeBadRequest, "Invalid request body"))
		return
	}

	if err := h.service.validator.Validate(req); err != nil {
		validationErrors := validator.TranslateValidationErrors(err)
		utils.Error(c, errors.WithDetails(errors.ErrCodeValidation, "Validation failed", validationErrors))
		return
	}

	user, err := h.service.Register(c.Request.Context(), req.Email, req.Password, req.FirstName, req.LastName)
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
		CreatedAt: user.CreatedAt,
	})
}

// Login godoc
// @Summary Login to get access token
// @Description Authenticate user and return access token
// @Tags Authentication
// @Accept json
// @Produce json
// @Param body body LoginRequest true "User credentials"
// @Success 200 {object} utils.Response{data=AuthResponse}
// @Failure 400 {object} utils.Response
// @Failure 401 {object} utils.Response
// @Router /auth/login [post]
func (h *Handler) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.Error(c, errors.Wrap(err, errors.ErrCodeBadRequest, "Invalid request body"))
		return
	}

	if err := h.service.validator.Validate(req); err != nil {
		validationErrors := validator.TranslateValidationErrors(err)
		utils.Error(c, errors.WithDetails(errors.ErrCodeValidation, "Validation failed", validationErrors))
		return
	}

	loginCtx := LoginContext{
		ClientIP:  getClientIP(c),
		UserAgent: c.Request.UserAgent(),
	}

	accessToken, refreshToken, csrfToken, user, err := h.service.Login(c.Request.Context(), req.Email, req.Password, loginCtx)
	if err != nil {
		utils.Error(c, err)
		return
	}

	isSecure := h.service.cfg.Server.Env == "production"
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(
		"refresh_token",
		refreshToken,
		int(h.service.jwtService.GetRefreshExpiry().Seconds()),
		"/api/v1/auth/refresh",
		"",
		isSecure,
		true,
	)

	c.Header("X-CSRF-Token", csrfToken)

	utils.Success(c, http.StatusOK, AuthResponse{
		AccessToken: accessToken,
		User: UserResponse{
			ID:        user.ID,
			Email:     user.Email,
			FirstName: user.FirstName,
			LastName:  user.LastName,
			Role:      user.Role,
			CreatedAt: user.CreatedAt,
		},
	})
}

// Refresh godoc
// @Summary Refresh access token
// @Description Get a new access token using refresh token
// @Tags Authentication
// @Accept json
// @Produce json
// @Success 200 {object} utils.Response{data=AuthResponse}
// @Failure 401 {object} utils.Response
// @Security     CsrfToken
// @Router /auth/refresh [post]
func (h *Handler) Refresh(c *gin.Context) {
	refreshToken, err := c.Cookie("refresh_token")
	if err != nil {
		utils.Error(c, errors.New(errors.ErrCodeUnauthorized, "Refresh token not found"))
		return
	}

	csrfToken := c.GetHeader("X-CSRF-Token")
	if csrfToken == "" {
		utils.Error(c, errors.New(errors.ErrCodeUnauthorized, "CSRF token required"))
		return
	}

	loginCtx := LoginContext{
		ClientIP:  getClientIP(c),
		UserAgent: c.Request.UserAgent(),
	}

	accessToken, newRefreshToken, newCsrfToken, user, err := h.service.RefreshToken(c.Request.Context(), refreshToken, csrfToken, loginCtx)
	if err != nil {
		utils.Error(c, err)
		return
	}

	isSecure := h.service.cfg.Server.Env == "production"
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(
		"refresh_token",
		newRefreshToken,
		int(h.service.jwtService.GetRefreshExpiry().Seconds()),
		"/api/v1/auth/refresh",
		"",
		isSecure,
		true,
	)

	c.Header("X-CSRF-Token", newCsrfToken)

	utils.Success(c, http.StatusOK, AuthResponse{
		AccessToken: accessToken,
		User: UserResponse{
			ID:        user.ID,
			Email:     user.Email,
			FirstName: user.FirstName,
			LastName:  user.LastName,
			Role:      user.Role,
			CreatedAt: user.CreatedAt,
		},
	})
}

// Logout godoc
// @Summary Logout user
// @Description Invalidate refresh token
// @Tags Authentication
// @Accept json
// @Produce json
// @Success 204
// @Failure 401 {object} utils.Response
// @Security     Bearer
// @Router /auth/logout [post]
func (h *Handler) Logout(c *gin.Context) {
	refreshToken, err := c.Cookie("refresh_token")
	if err == nil && refreshToken != "" {
		_ = h.service.Logout(c.Request.Context(), refreshToken)
	}

	c.SetCookie(
		"refresh_token",
		"",
		-1,
		"/api/v1/auth/refresh",
		"",
		h.service.cfg.Server.Env == "production",
		true,
	)

	c.Status(http.StatusNoContent)
}

// Me godoc
// @Summary Get current user
// @Description Get information about the currently authenticated user
// @Tags Authentication
// @Accept json
// @Produce json
// @Success 200 {object} utils.Response{data=UserResponse}
// @Failure 401 {object} utils.Response
// @Security     Bearer
// @Router /auth/me [get]
func (h *Handler) Me(c *gin.Context) {
	userID, err := middleware.GetCurrentUserID(c)
	if err != nil {
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
		CreatedAt: user.CreatedAt,
	})
}

func getClientIP(c *gin.Context) string {
	// Try to get real IP from proxy headers
	if ip := c.GetHeader("X-Real-IP"); ip != "" {
		return ip
	}
	if ip := c.GetHeader("X-Forwarded-For"); ip != "" {
		// X-Forwarded-For can contain multiple IPs, get the first one
		parts := strings.Split(ip, ",")
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}
	// Fallback to RemoteAddr
	return c.ClientIP()
}
