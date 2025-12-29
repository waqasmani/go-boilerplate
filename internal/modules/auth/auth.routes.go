package auth

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/waqasmani/go-boilerplate/internal/infrastructure/middleware"
	"github.com/waqasmani/go-boilerplate/internal/infrastructure/security"
)

func RegisterRoutes(router *gin.Engine, handler *Handler, authMiddleware *middleware.AuthMiddleware, rateLimiter security.RateLimiter) {
	authGroup := router.Group("/api/v1/auth")
	{
		authGroup.POST("/register",
			security.RouteRateLimitMiddleware(rateLimiter, 5, time.Minute),
			handler.Register,
		)

		authGroup.POST("/login",
			security.RouteRateLimitMiddleware(rateLimiter, 5, time.Minute),
			handler.Login,
		)

		authGroup.POST("/refresh",
			security.RouteRateLimitMiddleware(rateLimiter, 10, time.Minute),
			handler.Refresh,
		)

		authGroup.POST("/logout",
			authMiddleware.Authenticate(),
			handler.Logout,
		)

		authGroup.GET("/me",
			authMiddleware.Authenticate(),
			handler.Me,
		)
	}
}