package auth

import (
	"context"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/waqasmani/go-boilerplate/internal/infrastructure/security"
	"github.com/waqasmani/go-boilerplate/internal/shared/errors"
	"github.com/waqasmani/go-boilerplate/internal/shared/utils"
)

type AuthMiddleware struct {
	jwtService  *security.JWTService
	csrfManager security.CSRFManager
}

func NewAuthMiddleware(jwtService *security.JWTService, csrfManager security.CSRFManager) *AuthMiddleware {
	return &AuthMiddleware{
		jwtService:  jwtService,
		csrfManager: csrfManager,
	}
}

func (m *AuthMiddleware) Authenticate() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			utils.Error(c, errors.ErrUnauthorized)
			c.Abort()
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			utils.Error(c, errors.Wrap(errors.ErrUnauthorized, errors.ErrCodeUnauthorized, "Invalid authorization header format"))
			c.Abort()
			return
		}

		claims, err := m.jwtService.ValidateAccessToken(c.Request.Context(), tokenString)
		if err != nil {
			utils.Error(c, err)
			c.Abort()
			return
		}

		ctx := context.WithValue(c.Request.Context(), security.UserIDKey, claims.UserID)
		ctx = context.WithValue(ctx, security.UserRoleKey, claims.Role)
		ctx = context.WithValue(ctx, security.UserEmailKey, claims.Email)
		c.Request = c.Request.WithContext(ctx)

		c.Set(string(security.UserIDKey), claims.UserID)
		c.Set(string(security.UserRoleKey), claims.Role)
		c.Set(string(security.UserEmailKey), claims.Email)

		c.Next()
	}
}

func (m *AuthMiddleware) Authorize(allowedRoles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userRole, exists := c.Get(string(security.UserRoleKey))
		if !exists {
			utils.Error(c, errors.ErrForbidden)
			c.Abort()
			return
		}

		role, ok := userRole.(string)
		if !ok {
			utils.Error(c, errors.Wrap(errors.ErrForbidden, errors.ErrCodeInternal, "Invalid role type in context"))
			c.Abort()
			return
		}

		hasPermission := false
		for _, allowedRole := range allowedRoles {
			if role == allowedRole {
				hasPermission = true
				break
			}
		}

		if !hasPermission {
			utils.Error(c, errors.ErrForbidden)
			c.Abort()
			return
		}

		c.Next()
	}
}

func (m *AuthMiddleware) CSRFProtection() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Method == "GET" || c.Request.Method == "HEAD" || c.Request.Method == "OPTIONS" {
			c.Next()
			return
		}

		csrfToken := c.GetHeader("X-CSRF-Token")
		if csrfToken == "" {
			utils.Error(c, errors.Wrap(errors.ErrForbidden, errors.ErrCodeForbidden, "Missing CSRF token"))
			c.Abort()
			return
		}

		userIDVal, exists := c.Get(string(security.UserIDKey))
		if !exists {
			utils.Error(c, errors.ErrUnauthorized)
			c.Abort()
			return
		}

		userID, ok := userIDVal.(uint64)
		if !ok {
			utils.Error(c, errors.Wrap(errors.ErrUnauthorized, errors.ErrCodeInternal, "Invalid user ID type"))
			c.Abort()
			return
		}

		if !m.csrfManager.Validate(csrfToken, userID) {
			utils.Error(c, errors.Wrap(errors.ErrForbidden, errors.ErrCodeForbidden, "Invalid CSRF token"))
			c.Abort()
			return
		}

		c.Next()
	}
}

func GetCurrentUserID(c *gin.Context) (uint64, error) {
	userID, exists := c.Get(string(security.UserIDKey))
	if !exists {
		return 0, errors.ErrUnauthorized
	}

	id, ok := userID.(uint64)
	if !ok {
		return 0, errors.Wrap(errors.ErrUnauthorized, errors.ErrCodeInternal, "Invalid user ID type in context")
	}

	return id, nil
}

func GetCurrentUserRole(c *gin.Context) (string, error) {
	userRole, exists := c.Get(string(security.UserRoleKey))
	if !exists {
		return "", errors.ErrUnauthorized
	}

	role, ok := userRole.(string)
	if !ok {
		return "", errors.Wrap(errors.ErrUnauthorized, errors.ErrCodeInternal, "Invalid role type in context")
	}

	return role, nil
}
