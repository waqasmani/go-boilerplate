package auth

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/waqasmani/go-boilerplate/internal/infrastructure/security"
)

func RegisterRoutes(router *gin.Engine, h *Handler, authMiddleware *AuthMiddleware, rl security.RateLimiter) {
	authGroup := router.Group("/api/v1/auth")
	{
		authGroup.POST("/register", security.RouteRateLimitMiddleware(rl, 5, time.Minute), h.Register)
		authGroup.POST("/login", security.RouteRateLimitMiddleware(rl, 5, time.Minute), h.Login)

		// Refresh can be slightly more relaxed
		authGroup.POST("/refresh", security.RouteRateLimitMiddleware(rl, 20, time.Minute), h.RefreshTokens)

		// Logout doesn't strictly need a heavy rate limit but can be capped
		authGroup.POST("/logout", h.Logout)
	}

	csrfGroup := router.Group("/api/v1/auth")
	csrfGroup.Use(authMiddleware.Authenticate())
	{
		csrfGroup.GET("/csrf-token", h.GetCSRFToken)
	}
}
