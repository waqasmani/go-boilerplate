package app

import (
	"context"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	"github.com/waqasmani/go-boilerplate/internal/infrastructure/middleware"
	"github.com/waqasmani/go-boilerplate/internal/modules/attendance"
	"github.com/waqasmani/go-boilerplate/internal/modules/auth"
	"github.com/waqasmani/go-boilerplate/internal/modules/health"
	"github.com/waqasmani/go-boilerplate/internal/modules/users"
)

func SetupRouter(container *Container) *gin.Engine {
	if container.Config.Server.Env == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(middleware.BodyLimitMiddleware(2 * 1024 * 1024))
	if len(container.Config.Server.TrustedProxies) > 0 {
		router.SetTrustedProxies(container.Config.Server.TrustedProxies)
	} else if container.Config.Server.Env == "production" {
		container.Logger.Warn(context.Background(), "Production mode active with no TrustedProxies configured")
	}
	router.Use(middleware.PanicRecoveryMiddleware(container.Logger))
	router.Use(middleware.RequestIDMiddleware())
	router.Use(middleware.ErrorHandlingMiddleware(container.Logger, container.Metrics))
	router.Use(middleware.TracingMiddleware(container.Logger))
	router.Use(middleware.LoggerMiddleware(container.Logger))
	router.Use(middleware.TimeoutMiddleware(30 * time.Second))
	router.Use(middleware.NewCORSMiddleware(container.Config.CORS))
	router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
	router.Use(middleware.SecurityHeadersMiddleware())
	if container.Config.Metrics.Enabled {
		router.Use(middleware.MetricsMiddleware(container.Metrics))
	}

	// Health Handler & Route
	healthHandler := health.NewHandler(container.DB, container.Config.Redis.Enabled)
	if container.Config.Redis.Enabled {
		healthHandler.SetRedisClientProvider(container.GetRedisClient)
	}
	health.RegisterRoutes(router, healthHandler)

	// Auth Services & Routes
	authService := auth.NewService(
		container.Queries,
		container.Repo,
		container.JWTService,
		container.PasswordService,
		container.Validator,
		container.AuditLogger,
		container.Metrics,
		container.Config,
		container.Logger,
	)
	authHandler := auth.NewHandler(authService)
	rateLimiter := container.GetRateLimiter()
	auth.RegisterRoutes(router, authHandler, container.AuthMiddleware, rateLimiter)

	// User Services & Routes
	usersService := users.NewService(
		container.Queries,
		container.Repo,
		container.PasswordService,
		container.Validator,
		container.AuditLogger,
		container.Logger,
	)
	usersHandler := users.NewHandler(usersService)
	users.RegisterRoutes(router, usersHandler, container.AuthMiddleware)

	// Attendance Services & Routes
	attendanceService := attendance.NewService(
		container.Queries,
		container.AuditLogger,
		container.Validator,
		container.Logger,
		container.Config,
	)
	attendanceHandler := attendance.NewHandler(attendanceService)
	attendance.RegisterRoutes(router, attendanceHandler, container.AuthMiddleware)

	// Metrics Route
	if container.Config.Metrics.Enabled {
		router.GET("/api/v1/metrics", gin.WrapH(promhttp.Handler()))
	}

	return router
}
