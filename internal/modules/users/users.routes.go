package users

import (
	"github.com/gin-gonic/gin"
	"github.com/waqasmani/go-boilerplate/internal/infrastructure/middleware"
)

func RegisterRoutes(router *gin.Engine, handler *Handler, authMiddleware *middleware.AuthMiddleware) {
	usersGroup := router.Group("/api/v1/users")
	usersGroup.Use(authMiddleware.Authenticate())
	{
		usersGroup.GET("/:id", handler.GetUser)
		usersGroup.PUT("/:id", handler.UpdateUser)
		usersGroup.PUT("/:id/password", handler.UpdatePassword)

		// Admin-only routes
		adminGroup := usersGroup.Group("")
		adminGroup.Use(authMiddleware.Authorize("admin"))
		{
			adminGroup.GET("", handler.ListUsers)
			adminGroup.POST("", handler.CreateUser)
			adminGroup.DELETE("/:id", handler.DeleteUser)
		}
	}
}