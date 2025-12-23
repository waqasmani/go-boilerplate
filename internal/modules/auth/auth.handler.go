package auth

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/waqasmani/go-boilerplate/internal/infrastructure/observability"
	"github.com/waqasmani/go-boilerplate/internal/infrastructure/security"
	"github.com/waqasmani/go-boilerplate/internal/modules/users"
	"github.com/waqasmani/go-boilerplate/internal/shared/errors"
	"github.com/waqasmani/go-boilerplate/internal/shared/utils"
	"github.com/waqasmani/go-boilerplate/internal/shared/validator"
)

type Handler struct {
	service      *AuthService
	v            *validator.Validator
	isProduction bool
	auditLogger  *observability.AuditLogger
	csrfManager  security.CSRFManager
	metrics      *observability.Metrics
}

func NewHandler(service *AuthService, v *validator.Validator, isProduction bool, auditLogger *observability.AuditLogger, csrfManager security.CSRFManager, metrics *observability.Metrics) *Handler {
	return &Handler{
		service:      service,
		v:            v,
		isProduction: isProduction,
		auditLogger:  auditLogger,
		csrfManager:  csrfManager,
		metrics:      metrics,
	}
}

type loginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=8"`
}

// @Summary User login
// @Description Authenticate user and get access and refresh tokens
// @Tags auth
// @Accept json
// @Produce json
// @Param request body loginRequest true "Login credentials"
// @Success 200 {object} map[string]string "Contains access_token and csrf_token"
// @Failure 400 {object} utils.Response
// @Failure 401 {object} utils.Response
// @Router /auth/login [post]
func (h *Handler) Login(c *gin.Context) {
	clientIP := c.ClientIP()
	h.metrics.AuthenticationAttempts.WithLabelValues("password").Inc()

	var req loginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.metrics.AuthenticationFailures.WithLabelValues("password", "invalid_request").Inc()
		utils.Error(c, errors.Wrap(err, errors.ErrCodeBadRequest, "Invalid request body"))
		return
	}

	if err := h.v.Validate(req); err != nil {
		h.metrics.AuthenticationFailures.WithLabelValues("password", "validation_failed").Inc()
		utils.Error(c, errors.WithDetails(errors.ErrCodeValidation, "Validation failed", validator.TranslateValidationErrors(err)))
		return
	}

	tokens, userID, err := h.service.Login(c.Request.Context(), LoginRequest(req))
	if err != nil {
		h.auditLogger.LogSecurityEvent(c.Request.Context(), observability.SecurityEvent{
			Type:      "authentication",
			Action:    "login_failed",
			UserID:    userID,
			Success:   false,
			IPAddress: clientIP,
		})
		h.metrics.AuthenticationFailures.WithLabelValues("password", "invalid_credentials").Inc()
		utils.Error(c, err)
		return
	}

	h.auditLogger.LogSecurityEvent(c.Request.Context(), observability.SecurityEvent{
		Type:      "authentication",
		Action:    "login_success",
		UserID:    userID,
		Success:   true,
		IPAddress: clientIP,
	})

	h.setRefreshTokenCookie(c, tokens.RefreshToken)

	csrfToken, err := h.csrfManager.Generate(userID)
	if err != nil {
		h.metrics.CSRFValidations.WithLabelValues("generation_failed").Inc()
		utils.Error(c, errors.Wrap(err, errors.ErrCodeInternal, "Failed to generate CSRF token"))
		return
	}

	h.metrics.CSRFValidations.WithLabelValues("generated").Inc()
	h.metrics.ActiveSessions.Inc()

	utils.Success(c, http.StatusOK, gin.H{
		"access_token": tokens.AccessToken,
		"csrf_token":   csrfToken,
	})
}

// @Summary User registration
// @Description Register a new user account
// @Tags auth
// @Accept json
// @Produce json
// @Param request body users.CreateUserRequest true "Registration details"
// @Success 201 {object} users.UserResponse
// @Failure 400 {object} utils.Response
// @Failure 409 {object} utils.Response
// @Router /auth/register [post]
// @Summary User registration
// @Description Register a new user account
// @Tags auth
// @Accept json
// @Produce json
// @Param request body registerRequest true "Registration details"
// @Success 201 {object} UserResponse
// @Failure 400 {object} utils.Response
// @Failure 409 {object} utils.Response
// @Router /api/v1/auth/register [post]
func (h *Handler) Register(c *gin.Context) {
	clientIP := c.ClientIP()
	var req users.CreateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.Error(c, errors.Wrap(err, errors.ErrCodeBadRequest, "Invalid request body"))
		return
	}

	if err := h.v.Validate(req); err != nil {
		utils.Error(c, errors.WithDetails(errors.ErrCodeValidation, "Validation failed", validator.TranslateValidationErrors(err)))
		return
	}

	user, err := h.service.Register(c.Request.Context(), users.CreateUserRequest{
		Email:     req.Email,
		Password:  req.Password,
		FirstName: req.FirstName,
		LastName:  req.LastName,
	})
	if err != nil {
		if h.auditLogger != nil {
			// FIX: Handle nil user safely
			var userID uint64
			if user != nil {
				userID = user.ID
			}
			h.auditLogger.LogSecurityEvent(c.Request.Context(), observability.SecurityEvent{
				Type:      "registration",
				Action:    "registration_failed",
				UserID:    userID,
				Success:   false,
				IPAddress: clientIP,
			})
		}
		utils.Error(c, err)
		return
	}

	if user == nil {
		utils.Error(c, errors.New(errors.ErrCodeInternal, "Registration succeeded but user data is missing"))
		return
	}

	if h.auditLogger != nil {
		h.auditLogger.LogSecurityEvent(c.Request.Context(), observability.SecurityEvent{
			Type:      "registration",
			Action:    "user_registered",
			UserID:    user.ID,
			Success:   true,
			IPAddress: clientIP,
		})
	}

	utils.Success(c, http.StatusCreated, user)
}

// @Summary Refresh tokens
// @Description Get new access token using refresh token from cookie
// @Tags auth
// @Produce json
// @Success 200 {object} map[string]string "Contains access_token and csrf_token"
// @Failure 401 {object} utils.Response
// @Router /auth/refresh [post]
func (h *Handler) RefreshTokens(c *gin.Context) {
	h.metrics.TokenRefreshes.WithLabelValues("attempted").Inc()

	refreshToken := h.getRefreshTokenFromCookie(c)
	if refreshToken == "" {
		h.metrics.TokenRefreshes.WithLabelValues("missing_token").Inc()
		utils.Error(c, errors.ErrInvalidToken)
		return
	}

	tokens, userID, err := h.service.RefreshTokens(c.Request.Context(), refreshToken)
	if err != nil {
		h.metrics.TokenRefreshes.WithLabelValues("failed").Inc()
		utils.Error(c, err)
		return
	}

	h.setRefreshTokenCookie(c, tokens.RefreshToken)

	csrfToken, err := h.csrfManager.Generate(userID)
	if err != nil {
		h.metrics.CSRFValidations.WithLabelValues("generation_failed").Inc()
		utils.Error(c, errors.Wrap(err, errors.ErrCodeInternal, "Failed to generate CSRF token"))
		return
	}

	h.metrics.TokenRefreshes.WithLabelValues("success").Inc()
	h.metrics.CSRFValidations.WithLabelValues("generated").Inc()

	utils.Success(c, http.StatusOK, gin.H{
		"access_token": tokens.AccessToken,
		"csrf_token":   csrfToken,
	})
}

// @Summary User logout
// @Description Revoke refresh token and clear cookies
// @Tags auth
// @Produce json
// @Success 200 {object} map[string]string
// @Failure 401 {object} utils.Response
// @Router /auth/logout [post]
func (h *Handler) Logout(c *gin.Context) {
	refreshToken := h.getRefreshTokenFromCookie(c)
	if refreshToken == "" {
		utils.Error(c, errors.ErrInvalidToken)
		return
	}

	csrfToken := c.GetHeader("X-CSRF-Token")
	if csrfToken != "" {
		h.csrfManager.Delete(csrfToken)
	}

	if err := h.service.Logout(c.Request.Context(), refreshToken); err != nil {
		utils.Error(c, err)
		return
	}

	h.clearRefreshTokenCookie(c)
	h.metrics.ActiveSessions.Dec()

	h.auditLogger.LogSecurityEvent(c.Request.Context(), observability.SecurityEvent{
		Type:      "authentication",
		Action:    "logout_success",
		Success:   true,
		IPAddress: c.ClientIP(),
	})

	utils.Success(c, http.StatusOK, gin.H{"message": "Successfully logged out"})
}

func (h *Handler) setRefreshTokenCookie(c *gin.Context, refreshToken string) {
	refreshExpiry := h.service.jwtService.GetRefreshExpiry()

	cookie := &http.Cookie{
		Name:     "refresh_token",
		Value:    refreshToken,
		MaxAge:   int(refreshExpiry.Seconds()),
		HttpOnly: true,
		Secure:   h.isProduction,
		SameSite: http.SameSiteStrictMode,
		Path:     "/api/v1/auth",
	}
	http.SetCookie(c.Writer, cookie)
}

func (h *Handler) clearRefreshTokenCookie(c *gin.Context) {
	cookie := &http.Cookie{
		Name:     "refresh_token",
		Value:    "",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   h.isProduction,
		SameSite: http.SameSiteStrictMode,
		Path:     "/api/v1/auth",
	}
	http.SetCookie(c.Writer, cookie)
}

func (h *Handler) getRefreshTokenFromCookie(c *gin.Context) string {
	cookie, err := c.Cookie("refresh_token")
	if err != nil {
		return ""
	}
	return cookie
}

// @Summary Get CSRF token
// @Description Get a new CSRF token for state-changing requests
// @Tags auth
// @Param Authorization header string true "Bearer <access_token>"
// @Produce json
// @Success 200 {object} map[string]string "Contains csrf_token"
// @Failure 401 {object} utils.Response
// @Router /auth/csrf-token [get]
func (h *Handler) GetCSRFToken(c *gin.Context) {
	userIDVal, exists := c.Get(string(security.UserIDKey))
	if !exists {
		utils.Error(c, errors.ErrUnauthorized)
		return
	}

	userID, ok := userIDVal.(uint64)
	if !ok {
		utils.Error(c, errors.Wrap(errors.ErrUnauthorized, errors.ErrCodeInternal, "Invalid user ID type"))
		return
	}

	token, err := h.csrfManager.Generate(userID)
	if err != nil {
		h.metrics.CSRFValidations.WithLabelValues("generation_failed").Inc()
		utils.Error(c, errors.Wrap(err, errors.ErrCodeInternal, "Failed to generate CSRF token"))
		return
	}

	h.metrics.CSRFValidations.WithLabelValues("generated").Inc()
	utils.Success(c, http.StatusOK, gin.H{"csrf_token": token})
}
