package health

import (
	"github.com/gin-gonic/gin"
)

func RegisterRoutes(router *gin.Engine, handler *Handler) {
	healthGroup := router.Group("/api/v1")
	healthGroup.GET("/health", handler.Health)
	healthGroup.GET("/ready", handler.Ready)
	healthGroup.GET("/alive", handler.Alive)
}
