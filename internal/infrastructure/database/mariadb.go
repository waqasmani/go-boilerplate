package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/waqasmani/go-boilerplate/internal/config"
	"github.com/waqasmani/go-boilerplate/internal/infrastructure/database/errors"
	"github.com/waqasmani/go-boilerplate/internal/infrastructure/observability"
)

type DB struct {
	*sql.DB
	retryConfig *errors.RetryConfig
	metrics     *observability.Metrics
	logger      *observability.Logger
}

func NewMariaDB(ctx context.Context, cfg *config.DatabaseConfig, metrics *observability.Metrics, logger *observability.Logger) (*DB, error) {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?parseTime=true&charset=utf8mb4&collation=utf8mb4_unicode_ci&maxAllowedPacket=67108864&interpolateParams=true&timeout=10s&readTimeout=10s&writeTimeout=10s",
		cfg.User,
		cfg.Password,
		cfg.Host,
		cfg.Port,
		cfg.Name,
	)

	var db *sql.DB
	var err error

	// Initialize retry configuration for connection attempts
	retryCfg := errors.DefaultRetryConfig().MergeWith(&cfg.Retry)

	// Wrap connection logic in retry mechanism
	err = errors.RetryOperation(ctx, "db_connection", func(attempt uint64) error {
		var connectErr error
		db, connectErr = sql.Open("mysql", dsn)
		if connectErr != nil {
			return connectErr
		}

		db.SetMaxOpenConns(cfg.MaxOpenConns)
		db.SetMaxIdleConns(cfg.MaxIdleConns)
		db.SetConnMaxLifetime(cfg.ConnMaxLifetime)
		db.SetConnMaxIdleTime(cfg.ConnMaxIdleTime)

		pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		connectErr = db.PingContext(pingCtx)
		if connectErr != nil {
			_ = db.Close() // Clean up the failed connection
			return connectErr
		}

		return nil
	}, retryCfg, metrics, logger)

	if err != nil {
		return nil, fmt.Errorf("failed to connect to database after %d attempts: %w", retryCfg.MaxRetries, err)
	}

	// Create DB wrapper with retry configuration
	return &DB{
		DB:          db,
		retryConfig: retryCfg,
		metrics:     metrics,
		logger:      logger,
	}, nil
}

type TxFunc func(*sql.Tx) error

func (db *DB) WithTx(ctx context.Context, fn TxFunc) error {
	return errors.WithRetryTx(ctx, db.DB, fn, db.retryConfig, db.metrics, db.logger)
}

func (db *DB) ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error) {
	var result sql.Result
	var err error

	err = errors.RetryOperation(ctx, "exec", func(attempt uint64) error {
		start := time.Now()
		result, err = db.DB.ExecContext(ctx, query, args...)
		duration := time.Since(start)

		// Record metrics
		if db.metrics != nil {
			db.metrics.DatabaseQueryDuration.WithLabelValues("exec", "unknown").Observe(duration.Seconds())
			if err != nil {
				db.metrics.DatabaseQueryErrors.WithLabelValues("exec", "unknown", string(errors.ClassifyError(err))).Inc()
			} else {
				db.metrics.DatabaseQuerySuccess.WithLabelValues("exec", "unknown").Inc()
			}
		}

		// Log errors
		if err != nil {
			errors.LogDBError(db.logger, err, "exec", query)
		}

		return err
	}, db.retryConfig, db.metrics, db.logger)

	return result, err
}

func (db *DB) QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error) {
	var rows *sql.Rows
	var err error

	err = errors.RetryOperation(ctx, "query", func(attempt uint64) error {
		start := time.Now()
		rows, err = db.DB.QueryContext(ctx, query, args...)
		duration := time.Since(start)

		// Record metrics
		if db.metrics != nil {
			db.metrics.DatabaseQueryDuration.WithLabelValues("query", "unknown").Observe(duration.Seconds())
			if err != nil {
				db.metrics.DatabaseQueryErrors.WithLabelValues("query", "unknown", string(errors.ClassifyError(err))).Inc()
			} else {
				db.metrics.DatabaseQuerySuccess.WithLabelValues("query", "unknown").Inc()
			}
		}

		// Log errors
		if err != nil {
			errors.LogDBError(db.logger, err, "query", query)
		}

		return err
	}, db.retryConfig, db.metrics, db.logger)

	return rows, err
}

func (db *DB) QueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row {
	return db.DB.QueryRowContext(ctx, query, args...)
}

func (db *DB) Close() error {
	return db.DB.Close()
}
