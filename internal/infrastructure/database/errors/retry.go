package errors

import (
	"context"
	"database/sql"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/waqasmani/go-boilerplate/internal/config"
	"github.com/waqasmani/go-boilerplate/internal/infrastructure/observability"
)

type RetryConfig struct {
	Enabled           bool
	MaxRetries        int
	InitialInterval   time.Duration
	MaxInterval       time.Duration
	Multiplier        float64
	Randomization     float64
	FatalErrorTypes   []DBErrorType
	TransientErrorFN  func(error) bool
	OperationTimeHook func(operation string, duration time.Duration, attempt uint64)
}

func DefaultRetryConfig() *RetryConfig {
	return &RetryConfig{
		Enabled:         true,
		MaxRetries:      3,
		InitialInterval: 100 * time.Millisecond,
		MaxInterval:     2 * time.Second,
		Multiplier:      2.0,
		Randomization:   0.2,
		FatalErrorTypes: []DBErrorType{
			ErrorTypeConstraintViolation,
			ErrorTypeDuplicateKey,
			ErrorTypeForeignKeyViolation,
		},
		TransientErrorFN: IsTransientError,
	}
}

func (cfg *RetryConfig) MergeWith(config *config.DatabaseRetryConfig) *RetryConfig {
	if config == nil {
		return cfg
	}

	if config.Enabled != nil {
		cfg.Enabled = *config.Enabled
	}
	if config.MaxRetries != nil {
		cfg.MaxRetries = *config.MaxRetries
	}
	if config.InitialInterval != nil {
		cfg.InitialInterval = *config.InitialInterval
	}
	if config.MaxInterval != nil {
		cfg.MaxInterval = *config.MaxInterval
	}
	if config.Multiplier != nil {
		cfg.Multiplier = *config.Multiplier
	}
	if config.Randomization != nil {
		cfg.Randomization = *config.Randomization
	}
	if len(config.FatalErrorTypes) > 0 {
		cfg.FatalErrorTypes = make([]DBErrorType, len(config.FatalErrorTypes))
		for i, errType := range config.FatalErrorTypes {
			cfg.FatalErrorTypes[i] = DBErrorType(errType)
		}
	}

	return cfg
}

func (cfg *RetryConfig) IsFatalError(err error) bool {
	if !cfg.Enabled {
		return true
	}

	errType := ClassifyError(err)
	for _, fatalType := range cfg.FatalErrorTypes {
		if errType == fatalType {
			return true
		}
	}
	return false
}

func (cfg *RetryConfig) ShouldRetry(err error) bool {
	if !cfg.Enabled {
		return false
	}

	if cfg.IsFatalError(err) {
		return false
	}

	if cfg.TransientErrorFN != nil {
		return cfg.TransientErrorFN(err)
	}

	return IsTransientError(err)
}

type RetryableFunc func(attempt uint64) error

func RetryOperation(ctx context.Context, operationName string, f RetryableFunc, cfg *RetryConfig, metrics *observability.Metrics, logger *observability.Logger) error {
	if !cfg.Enabled {
		return f(0)
	}

	expBackoff := backoff.NewExponentialBackOff()
	expBackoff.InitialInterval = cfg.InitialInterval
	expBackoff.MaxInterval = cfg.MaxInterval
	expBackoff.Multiplier = cfg.Multiplier
	expBackoff.RandomizationFactor = cfg.Randomization
	expBackoff.MaxElapsedTime = 0 // No maximum elapsed time, controlled by MaxRetries
	expBackoff.Reset()

	startTime := time.Now()
	var attempt uint64 = 0
	var lastErr error

	for {
		attempt++
		lastErr = f(attempt)

		if lastErr == nil {
			if attempt > 1 && cfg.OperationTimeHook != nil {
				duration := time.Since(startTime)
				cfg.OperationTimeHook(operationName, duration, attempt)
			}
			return nil
		}

		if !cfg.ShouldRetry(lastErr) {
			if metrics != nil {
				metrics.DatabaseRetrySkipped.WithLabelValues(operationName, string(ClassifyError(lastErr))).Inc()
			}
			return lastErr
		}

		if attempt >= uint64(cfg.MaxRetries) {
			if metrics != nil {
				metrics.DatabaseRetryMaxAttempts.WithLabelValues(operationName).Inc()
			}
			return lastErr
		}

		if metrics != nil {
			metrics.DatabaseRetryAttempts.WithLabelValues(operationName, string(ClassifyError(lastErr))).Inc()
		}

		if logger != nil {
			logger.Warn(ctx, "Retrying database operation",
				logger.Field("operation", operationName),
				logger.Field("attempt", attempt),
				logger.Field("max_attempts", cfg.MaxRetries),
				logger.Field("error", lastErr.Error()),
			)
		}

		nextInterval := expBackoff.NextBackOff()
		select {
		case <-time.After(nextInterval):
			// Continue to next attempt
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func WithRetryTx(ctx context.Context, db *sql.DB, fn func(tx *sql.Tx) error, cfg *RetryConfig, metrics *observability.Metrics, logger *observability.Logger) error {
	return RetryOperation(ctx, "transaction", func(attempt uint64) error {
		tx, err := db.BeginTx(ctx, &sql.TxOptions{
			Isolation: sql.LevelReadCommitted,
		})
		if err != nil {
			return err
		}
		defer func() {
			if p := recover(); p != nil {
				_ = tx.Rollback()
				panic(p)
			}
		}()

		if err := fn(tx); err != nil {
			rbErr := tx.Rollback()
			if rbErr != nil {
				return err // Return original error, rollback error is secondary
			}
			return err
		}

		if err := tx.Commit(); err != nil {
			return err
		}

		return nil
	}, cfg, metrics, logger)
}