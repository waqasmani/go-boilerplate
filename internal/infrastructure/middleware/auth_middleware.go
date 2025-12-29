package middleware

import (
	"context"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/waqasmani/go-boilerplate/internal/infrastructure/security"
	"github.com/waqasmani/go-boilerplate/internal/shared/errors"
	"github.com/waqasmani/go-boilerplate/internal/shared/utils"
)

type AuthMiddleware struct {
	jwtService *security.JWTService
}

func NewAuthMiddleware(jwtService *security.JWTService) *AuthMiddleware {
	return &AuthMiddleware{
		jwtService: jwtService,
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

		const bearerPrefix = "Bearer "
		if !strings.HasPrefix(authHeader, bearerPrefix) {
			utils.Error(c, errors.Wrap(errors.ErrUnauthorized, errors.ErrCodeUnauthorized, "Invalid authorization header format"))
			c.Abort()
			return
		}
		tokenString := strings.TrimSpace(authHeader[len(bearerPrefix):])
		if tokenString == "" {
			utils.Error(c, errors.Wrap(errors.ErrUnauthorized, errors.ErrCodeUnauthorized, "Missing token"))
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

// IsAdminOrOwner checks if the authenticated user is either an admin or the owner of the resource
// Returns an error if authorization fails, nil if authorized
func IsAdminOrOwner(c *gin.Context, targetID uint64) error {
	authUserID, err := GetCurrentUserID(c)
	if err != nil {
		return errors.Wrap(err, errors.ErrCodeUnauthorized, "Failed to get user ID from context")
	}

	// Owner check - user can access their own resources
	if authUserID == targetID {
		return nil
	}

	// Admin check - admins can access any resource
	role, err := GetCurrentUserRole(c)
	if err != nil {
		return errors.Wrap(err, errors.ErrCodeUnauthorized, "Failed to get user role from context")
	}

	if role == "admin" {
		return nil
	}

	// Neither owner nor admin
	return errors.New(errors.ErrCodeForbidden, "Access denied: insufficient permissions")
}

// IsAdmin checks if the authenticated user has admin role
func IsAdmin(c *gin.Context) bool {
	role, err := GetCurrentUserRole(c)
	if err != nil {
		return false
	}
	return role == "admin"
}

// RequireOwnership ensures the authenticated user is the owner of the resource
// This is stricter than IsAdminOrOwner - even admins are not allowed
func RequireOwnership(c *gin.Context, targetID uint64) error {
	authUserID, err := GetCurrentUserID(c)
	if err != nil {
		return errors.Wrap(err, errors.ErrCodeUnauthorized, "Failed to get user ID from context")
	}

	if authUserID != targetID {
		return errors.New(errors.ErrCodeForbidden, "Access denied: you can only access your own resources")
	}

	return nil
}