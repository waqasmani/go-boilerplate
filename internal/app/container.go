package app

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/waqasmani/go-boilerplate/internal/config"
	"github.com/waqasmani/go-boilerplate/internal/infrastructure/database"
	"github.com/waqasmani/go-boilerplate/internal/infrastructure/middleware"
	"github.com/waqasmani/go-boilerplate/internal/infrastructure/observability"
	"github.com/waqasmani/go-boilerplate/internal/infrastructure/security"
	"github.com/waqasmani/go-boilerplate/internal/infrastructure/sqlc"
	"github.com/waqasmani/go-boilerplate/internal/modules/health"
	"github.com/waqasmani/go-boilerplate/internal/shared/validator"
	"go.uber.org/zap"
)

type Container struct {
	Config          *config.Config
	DB              *sql.DB
	Logger          *observability.Logger
	Queries         *sqlc.Queries
	Repo            *sqlc.Repository
	JWTService      *security.JWTService
	PasswordService *security.PasswordService
	AuthMiddleware  *middleware.AuthMiddleware
	Validator       *validator.Validator
	Metrics         *observability.Metrics
	AuditLogger     *observability.AuditLogger
	HealthHandler   *health.Handler
	rateLimiter     security.RateLimiter
	redisMu         sync.RWMutex
	redisClient     *redis.Client
}

func NewContainer(cfg *config.Config, db *sql.DB, logger *observability.Logger) *Container {
	metrics := observability.NewMetrics()
	jwtService := security.NewJWTService(&cfg.JWT)
	passwordService := security.NewPasswordService(cfg.Security.BcryptCost)
	validatorInstance := validator.New()

	var auditLogger *observability.AuditLogger
	if cfg.AuditLog.Enabled && cfg.AuditLog.Path != "" {
		dedicatedAuditLogger, err := observability.NewDedicatedAuditLogger(
			cfg.AuditLog.Path,
			cfg.AuditLog.Format,
		)
		if err != nil {
			logger.Error(context.Background(), "Failed to initialize dedicated audit logger, falling back to main logger",
				zap.Error(err),
				zap.String("path", cfg.AuditLog.Path),
			)
			auditLogger = observability.NewAuditLogger(logger)
		} else {
			logger.Info(context.Background(), "Audit logging enabled with dedicated file",
				zap.String("path", cfg.AuditLog.Path),
				zap.String("format", cfg.AuditLog.Format),
			)
			auditLogger = dedicatedAuditLogger
		}
	} else {
		auditLogger = observability.NewAuditLogger(logger)
	}

	var queryDB database.DBTX = db
	if cfg.Database.CircuitBreaker.Enabled {
		logger.Info(context.Background(), "Initializing database circuit breaker",
			zap.Bool("enabled", cfg.Database.CircuitBreaker.Enabled),
			zap.Uint32("max_failures", cfg.Database.CircuitBreaker.MaxFailures),
			zap.Float64("failure_threshold", cfg.Database.CircuitBreaker.FailureThreshold),
			zap.Duration("reset_timeout", cfg.Database.CircuitBreaker.ResetTimeout),
		)
		// Use the DB wrapper with circuit breaker that also has retry configuration
		queryDB = database.NewBreakerDB(db, cfg.Database.CircuitBreaker, metrics, logger)
	}

	queries := sqlc.New(queryDB)
	repo := sqlc.NewRepository(db)
	authMiddleware := middleware.NewAuthMiddleware(jwtService)
	healthHandler := health.NewHandler(db, cfg.Redis.Enabled)

	return &Container{
		Config:          cfg,
		DB:              db,
		Logger:          logger,
		Queries:         queries,
		Repo:            repo,
		JWTService:      jwtService,
		PasswordService: passwordService,
		AuthMiddleware:  authMiddleware,
		Validator:       validatorInstance,
		Metrics:         metrics,
		AuditLogger:     auditLogger,
		HealthHandler:   healthHandler,
	}
}

// GetRedisClient provides a thread-safe singleton that allows retries on failure
// GetRedisClient provides a thread-safe singleton that allows retries on failure
func (c *Container) GetRedisClient() (*redis.Client, error) {
	c.redisMu.RLock()
	if c.redisClient != nil {
		client := c.redisClient
		c.redisMu.RUnlock()
		return client, nil
	}
	c.redisMu.RUnlock()

	c.redisMu.Lock()
	defer c.redisMu.Unlock()

	// Double-check after acquiring lock
	if c.redisClient != nil {
		return c.redisClient, nil
	}

	client := redis.NewClient(&redis.Options{
		Addr:         fmt.Sprintf("%s:%s", c.Config.Redis.Host, c.Config.Redis.Port),
		Password:     c.Config.Redis.Password,
		DB:           c.Config.Redis.DB,
		DialTimeout:  5 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
		PoolSize:     c.Config.Redis.PoolSize,
		MinIdleConns: c.Config.Redis.MinIdleConns,
		MaxRetries:   c.Config.Redis.MaxRetries,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		client.Close()
		c.redisClient = nil // Explicitly nullify on failure
		return nil, fmt.Errorf("redis connection failed: %w", err)
	}

	c.redisClient = client
	return c.redisClient, nil
}

func (c *Container) GetRateLimiter() security.RateLimiter {
	if c.rateLimiter != nil {
		return c.rateLimiter
	}

	if c.Config.Redis.Enabled {
		client, err := c.GetRedisClient()
		if err != nil {
			// Only fatal in production, log warning in other environments
			if c.Config.Server.Env == "production" {
				c.Logger.Fatal(context.Background(),
					"Redis required for rate limiting in production but unavailable",
					zap.Error(err),
					zap.String("redis_host", c.Config.Redis.Host),
					zap.String("redis_port", c.Config.Redis.Port),
				)
			} else {
				c.Logger.Warn(context.Background(),
					"Redis connection failed, falling back to in-memory rate limiter",
					zap.Error(err),
				)
			}
		} else {
			// Redis connection succeeded
			c.Logger.Info(context.Background(),
				"Successfully connected to Redis for rate limiting and CSRF protection",
				zap.String("redis_host", c.Config.Redis.Host),
			)
			c.rateLimiter = security.NewRedisRateLimiter(client)
			return c.rateLimiter
		}
	}

	// Fallback to in-memory rate limiter
	if c.Config.Server.Env == "production" && c.Config.Redis.Enabled {
		c.Logger.Warn(context.Background(),
			"Using in-memory rate limiter in production - not recommended for multi-instance deployments",
		)
	} else if !c.Config.Redis.Enabled {
		c.Logger.Info(context.Background(), "Redis disabled in configuration, using in-memory rate limiter")
	}

	c.rateLimiter = security.NewInMemoryRateLimiter()
	return c.rateLimiter
}

// Close gracefully closes all infrastructure connections
func (c *Container) Close() {
	if c.AuditLogger != nil {
		if err := c.AuditLogger.Close(); err != nil {
			c.Logger.Error(context.Background(), "Error closing audit logger", zap.Error(err))
		}
	}

	c.redisMu.Lock()
	defer c.redisMu.Unlock()

	if c.DB != nil {
		if err := c.DB.Close(); err != nil {
			c.Logger.Error(context.Background(), "Error closing DB", zap.Error(err))
		}
	}

	if c.redisClient != nil {
		if err := c.redisClient.Close(); err != nil {
			c.Logger.Error(context.Background(), "Error closing Redis", zap.Error(err))
		}
		c.redisClient = nil
	}
}
