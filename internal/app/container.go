package app

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/waqasmani/go-boilerplate/internal/config"
	"github.com/waqasmani/go-boilerplate/internal/infrastructure/observability"
	"github.com/waqasmani/go-boilerplate/internal/infrastructure/security"
	"github.com/waqasmani/go-boilerplate/internal/infrastructure/sqlc"
	"github.com/waqasmani/go-boilerplate/internal/modules/auth"
	"github.com/waqasmani/go-boilerplate/internal/modules/health"
	"github.com/waqasmani/go-boilerplate/internal/modules/users"
	"github.com/waqasmani/go-boilerplate/internal/shared/validator"
	"go.uber.org/zap"
)

type Container struct {
	Config *config.Config
	DB     *sql.DB
	Logger *observability.Logger

	Queries *sqlc.Queries
	Repo    *sqlc.Repository

	JWTService      *security.JWTService
	PasswordService *security.PasswordService
	CSRFManager     security.CSRFManager
	AuthMiddleware  *auth.AuthMiddleware

	Validator *validator.Validator

	Metrics *observability.Metrics

	AuditLogger *observability.AuditLogger

	HealthHandler *health.Handler
	AuthHandler   *auth.Handler
	UsersHandler  *users.Handler
	RateLimiter   security.RateLimiter
}

func NewContainer(cfg *config.Config, db *sql.DB, logger *observability.Logger) *Container {
	jwtService := security.NewJWTService(&cfg.JWT)
	passwordService := security.NewPasswordService(cfg.Security.BcryptCost)
	var csrfManager security.CSRFManager
	var rateLimiter security.RateLimiter

	if cfg.Redis.Enabled {
		rdb := redis.NewClient(&redis.Options{
			Addr:            fmt.Sprintf("%s:%s", cfg.Redis.Host, cfg.Redis.Port),
			Password:        cfg.Redis.Password,
			DB:              cfg.Redis.DB,
			MaxRetries:      cfg.Redis.MaxRetries,
			PoolSize:        cfg.Redis.PoolSize,
			MinIdleConns:    cfg.Redis.MinIdleConns,
			ConnMaxLifetime: cfg.Redis.ConnMaxLifetime,
		})

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := rdb.Ping(ctx).Err(); err != nil {
			logger.Error(context.Background(), "Failed to connect to Redis, falling back to in-memory", zap.Error(err))
			csrfManager = security.NewInMemoryCSRFManager(time.Hour)
			rateLimiter = security.NewInMemoryRateLimiter()
		} else {
			logger.Info(context.Background(), "Using Redis for CSRF and rate limiting")
			csrfManager = security.NewRedisCSRFManager(rdb, time.Hour)
			rateLimiter = security.NewRedisRateLimiter(rdb)
		}
	} else {
		rateLimiter = security.NewInMemoryRateLimiter()
		csrfManager = security.NewInMemoryCSRFManager(time.Hour)
	}

	validatorInstance := validator.New()
	metrics := observability.NewMetrics()
	queries := sqlc.New(db)
	repo := sqlc.NewRepository(db)
	authMiddleware := auth.NewAuthMiddleware(jwtService, csrfManager)
	auditLogger := observability.NewAuditLogger(logger)

	healthHandler := health.NewHandler(db)
	authService := auth.NewAuthService(queries, repo, jwtService, passwordService)
	authHandler := auth.NewHandler(authService, validatorInstance, cfg.Server.Env == "production", auditLogger, csrfManager, metrics)
	usersService := users.NewUsersService(queries, passwordService, repo)
	usersHandler := users.NewHandler(usersService, validatorInstance)

	return &Container{
		Config:          cfg,
		DB:              db,
		Logger:          logger,
		Queries:         queries,
		Repo:            repo,
		JWTService:      jwtService,
		PasswordService: passwordService,
		CSRFManager:     csrfManager,
		AuthMiddleware:  authMiddleware,
		Validator:       validatorInstance,
		Metrics:         metrics,
		AuditLogger:     auditLogger,
		HealthHandler:   healthHandler,
		AuthHandler:     authHandler,
		UsersHandler:    usersHandler,
		RateLimiter:     rateLimiter,
	}
}