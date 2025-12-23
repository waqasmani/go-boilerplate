package app

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	"github.com/waqasmani/go-boilerplate/internal/config"
	"github.com/waqasmani/go-boilerplate/internal/infrastructure/observability"
	"github.com/waqasmani/go-boilerplate/internal/infrastructure/security"
	"github.com/waqasmani/go-boilerplate/internal/modules/auth"
	"github.com/waqasmani/go-boilerplate/internal/modules/health"
	"go.uber.org/zap"
)

func SetupRouter(container *Container) *gin.Engine {
	if container.Config.Server.Env == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(PanicRecoveryMiddleware(container.Logger))

	router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
	router.Use(RequestIDMiddleware())
	router.Use(LoggerMiddleware(container.Logger))
	router.Use(TimeoutMiddleware(30 * time.Second))
	router.Use(NewCORSMiddleware(container.Config.CORS))
	router.Use(SecurityHeadersMiddleware())

	if container.Config.Metrics.Enabled {
		router.Use(MetricsMiddleware(container.Metrics))
		router.Use(DatabaseMetricsMiddleware(container.DB, container.Metrics))
	}
	health.RegisterRoutes(router, container.HealthHandler)

	auth.RegisterRoutes(router, container.AuthHandler, container.AuthMiddleware, container.RateLimiter)

	protected := router.Group("/api/v1")
	protected.Use(container.AuthMiddleware.Authenticate())
	{
		stateChangingRoutes := protected.Group("/")
		stateChangingRoutes.Use(container.AuthMiddleware.CSRFProtection())

		usersGroup := stateChangingRoutes.Group("/users")
		usersGroup.Use(security.RouteRateLimitMiddleware(container.RateLimiter, 100, time.Hour))
		{
			adminRoutes := usersGroup.Group("/")
			adminRoutes.Use(container.AuthMiddleware.Authorize("admin"))
			adminRoutes.Use(security.RouteRateLimitMiddleware(container.RateLimiter, 50, time.Hour))
			{
				adminRoutes.POST("/", container.UsersHandler.CreateUser)
				adminRoutes.GET("/", container.UsersHandler.ListUsers)
				adminRoutes.DELETE("/:id", container.UsersHandler.DeactivateUser)
			}

			usersGroup.GET("/:id", container.UsersHandler.GetUserByID)
			usersGroup.PUT("/:id", container.UsersHandler.UpdateUser)
			usersGroup.PUT("/:id/password", container.UsersHandler.ChangePassword)
		}
	}

	if container.Config.Metrics.Enabled {
		router.GET("/api/v1/metrics", gin.WrapH(promhttp.Handler()))
	}

	return router
}

func RequestIDMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := c.GetHeader("X-Request-ID")
		if requestID == "" {
			id, _ := uuid.NewRandom()
			requestID = id.String()
		}

		ctx := context.WithValue(c.Request.Context(), observability.RequestIDKey, requestID)
		c.Request = c.Request.WithContext(ctx)

		c.Set(string(observability.RequestIDKey), requestID)
		c.Header("X-Request-ID", requestID)

		c.Next()
	}
}

func TimeoutMiddleware(timeout time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), timeout)
		defer cancel()

		c.Request = c.Request.WithContext(ctx)

		finished := make(chan struct{})
		go func() {
			c.Next()
			finished <- struct{}{}
		}()

		select {
		case <-finished:
			return
		case <-ctx.Done():
			if ctx.Err() == context.DeadlineExceeded {
				c.AbortWithStatusJSON(http.StatusRequestTimeout, gin.H{
					"success": false,
					"error": gin.H{
						"code":    "REQUEST_TIMEOUT",
						"message": "Request timeout",
					},
				})
			}
		}
	}
}

func NewCORSMiddleware(cfg config.CORSConfig) gin.HandlerFunc {
	corsCfg := cors.Config{
		AllowOrigins:     cfg.AllowedOrigins,
		AllowMethods:     cfg.AllowedMethods,
		AllowHeaders:     append(cfg.AllowedHeaders, "X-CSRF-Token", "X-Request-ID"),
		AllowCredentials: true,
		MaxAge:           24 * time.Hour,
		ExposeHeaders:    []string{"X-Request-ID", "X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset"},
	}

	for _, origin := range cfg.AllowedOrigins {
		if origin == "*" {
			corsCfg.AllowAllOrigins = true
			corsCfg.AllowOrigins = nil
			break
		}
	}

	return cors.New(corsCfg)
}

func SecurityHeadersMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		c.Header("Content-Security-Policy", "default-src 'self'")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Header("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		c.Next()
	}
}

func LoggerMiddleware(logger *observability.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		method := c.Request.Method
		userAgent := c.Request.UserAgent()
		clientIP := c.ClientIP()

		c.Next()

		latency := time.Since(start)
		statusCode := c.Writer.Status()

		fields := []zap.Field{
			logger.Field("method", method),
			logger.Field("path", path),
			logger.Field("status", statusCode),
			logger.Field("latency_ms", latency.Milliseconds()),
			logger.Field("client_ip", clientIP),
			logger.Field("user_agent", userAgent),
		}

		if len(c.Errors) > 0 {
			fields = append(fields, logger.Field("errors", c.Errors.String()))
		}

		if statusCode >= 500 {
			logger.Error(c.Request.Context(), "HTTP Request completed with server error", fields...)
		} else if statusCode >= 400 {
			logger.Warn(c.Request.Context(), "HTTP Request completed with client error", fields...)
		} else {
			logger.Info(c.Request.Context(), "HTTP Request completed", fields...)
		}
	}
}

func MetricsMiddleware(metrics *observability.Metrics) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		method := c.Request.Method

		c.Next()

		duration := time.Since(start).Seconds()
		status := fmt.Sprintf("%d", c.Writer.Status())

		metrics.HttpRequestsTotal.WithLabelValues(method, path, status).Inc()
		metrics.HttpRequestDuration.WithLabelValues(method, path).Observe(duration)

		if c.Request.ContentLength > 0 {
			metrics.HttpRequestSize.WithLabelValues(method, path).Observe(float64(c.Request.ContentLength))
		}

		responseSize := c.Writer.Size()
		if responseSize > 0 {
			metrics.HttpResponseSize.WithLabelValues(method, path).Observe(float64(responseSize))
		}
	}
}

func DatabaseMetricsMiddleware(db *sql.DB, metrics *observability.Metrics) gin.HandlerFunc {
	ticker := time.NewTicker(10 * time.Second)

	go func() {
		for range ticker.C {
			stats := db.Stats()
			metrics.RecordDatabaseStats(
				stats.OpenConnections,
				stats.InUse,
				stats.Idle,
			)
		}
	}()

	return func(c *gin.Context) {
		c.Next()
	}
}

func PanicRecoveryMiddleware(logger *observability.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				logger.Error(c.Request.Context(), "Panic recovered",
					zap.Any("error", err),
					zap.String("path", c.Request.URL.Path),
					zap.String("method", c.Request.Method),
				)

				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
					"success": false,
					"error": gin.H{
						"code":    "INTERNAL_ERROR",
						"message": "Internal server error",
					},
				})
			}
		}()
		c.Next()
	}
}
