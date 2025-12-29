package health

import (
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

func RegisterRoutes(router *gin.Engine, handler *Handler) {
	// Set Redis client provider if available
	if handler.redisEnabled {
		// This will be set by the container after initialization
		handler.SetRedisClientProvider(func() (*redis.Client, error) {
			// This is a placeholder - actual implementation will be provided by container
			return nil, nil
		})
	}

	healthGroup := router.Group("/api/v1")
	healthGroup.GET("/health", handler.Health)
	healthGroup.GET("/ready", handler.Ready)
	healthGroup.GET("/alive", handler.Alive)
}