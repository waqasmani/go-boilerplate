// internal/infrastructure/database/circuit_breaker.go
package database

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"sync"
	"time"

	"github.com/sony/gobreaker"
	"github.com/waqasmani/go-boilerplate/internal/config"
	"github.com/waqasmani/go-boilerplate/internal/infrastructure/database/errors"
	"github.com/waqasmani/go-boilerplate/internal/infrastructure/observability"
	"go.uber.org/zap"
)

// DBTX defines the interface needed for database operations
type DBTX interface {
	ExecContext(context.Context, string, ...interface{}) (sql.Result, error)
	PrepareContext(context.Context, string) (*sql.Stmt, error)
	QueryContext(context.Context, string, ...interface{}) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...interface{}) *sql.Row
}

// BreakerDB wraps sql.DB with a circuit breaker to prevent cascading failures
type BreakerDB struct {
	*sql.DB
	cb      *gobreaker.CircuitBreaker
	metrics *observability.Metrics
	logger  *observability.Logger
}

// NewBreakerDB creates a new BreakerDB from config
func NewBreakerDB(db *sql.DB, cfg config.CBConfig, metrics *observability.Metrics, logger *observability.Logger) *BreakerDB {
	settings := gobreaker.Settings{
		Name: "MariaDB",
		// MaxRequests is used for half-open state, not max failures
		MaxRequests: uint32(cfg.MaxFailures),
		Interval:    0, // Disable cyclic timer, we'll use ReadyToTrip
		Timeout:     cfg.ResetTimeout,
		ReadyToTrip: func(counts gobreaker.Counts) bool {
			failureRatio := float64(counts.TotalFailures) / float64(counts.Requests)
			return counts.Requests >= 3 && failureRatio >= cfg.FailureThreshold
		},
		OnStateChange: func(name string, from gobreaker.State, to gobreaker.State) {
			defer logger.Sync()
			logger.Warn(context.Background(), "Circuit breaker state changed",
				zap.String("db", name),
				zap.String("from_state", from.String()),
				zap.String("to_state", to.String()),
				zap.Time("timestamp", time.Now()),
			)

			// Record state as metric (0=closed, 0.5=half_open, 1=open)
			stateValue := 0.0
			switch to {
			case gobreaker.StateOpen:
				stateValue = 1.0
			case gobreaker.StateHalfOpen:
				stateValue = 0.5
			}
			if metrics != nil {
				metrics.CircuitBreakerState.WithLabelValues(name, to.String()).Set(stateValue)
				metrics.CircuitBreakerEvents.WithLabelValues(name, "state_change", from.String()+"_to_"+to.String()).Inc()
			}
		},
	}

	return &BreakerDB{
		DB:      db,
		cb:      gobreaker.NewCircuitBreaker(settings),
		metrics: metrics,
		logger:  logger,
	}
}

// ExecContext wraps the Exec call in the circuit breaker
func (b *BreakerDB) ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error) {
	start := time.Now()
	defer func() {
		duration := time.Since(start).Seconds()
		success := "success"
		if err := recover(); err != nil {
			success = "panic"
		}
		if b.metrics != nil {
			b.metrics.CircuitBreakerDuration.WithLabelValues("MariaDB", success).Observe(duration)
		}
	}()

	result, err := b.cb.Execute(func() (interface{}, error) {
		return b.DB.ExecContext(ctx, query, args...)
	})
	if err != nil {
		// Only count non-transient errors towards circuit breaker
		if !errors.IsTransientError(err) {
			if b.metrics != nil {
				b.metrics.CircuitBreakerEvents.WithLabelValues("MariaDB", "failure", string(errors.ClassifyError(err))).Inc()
			}
		}
		if b.metrics != nil {
			b.metrics.CircuitBreakerDuration.WithLabelValues("MariaDB", "error").Observe(time.Since(start).Seconds())
		}
		return nil, err
	}

	if b.metrics != nil {
		b.metrics.CircuitBreakerDuration.WithLabelValues("MariaDB", "success").Observe(time.Since(start).Seconds())
	}
	return result.(sql.Result), nil
}

// QueryContext wraps the Query call in the circuit breaker
func (b *BreakerDB) QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error) {
	start := time.Now()
	defer func() {
		duration := time.Since(start).Seconds()
		success := "success"
		if err := recover(); err != nil {
			success = "panic"
		}
		if b.metrics != nil {
			b.metrics.CircuitBreakerDuration.WithLabelValues("MariaDB", success).Observe(duration)
		}
	}()

	rows, err := b.cb.Execute(func() (interface{}, error) {
		return b.DB.QueryContext(ctx, query, args...)
	})
	if err != nil {
		// Only count non-transient errors towards circuit breaker
		if !errors.IsTransientError(err) {
			if b.metrics != nil {
				b.metrics.CircuitBreakerEvents.WithLabelValues("MariaDB", "failure", string(errors.ClassifyError(err))).Inc()
			}
		}
		if b.metrics != nil {
			b.metrics.CircuitBreakerDuration.WithLabelValues("MariaDB", "error").Observe(time.Since(start).Seconds())
		}
		return nil, err
	}

	if b.metrics != nil {
		b.metrics.CircuitBreakerDuration.WithLabelValues("MariaDB", "success").Observe(time.Since(start).Seconds())
	}
	return rows.(*sql.Rows), nil
}

// QueryRowContext wraps the QueryRow call with circuit breaker protection
func (b *BreakerDB) QueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row {
	// First check if circuit is open to fail fast
	if b.cb.State() == gobreaker.StateOpen {
		return newErrorRow(gobreaker.ErrOpenState)
	}

	start := time.Now()
	defer func() {
		duration := time.Since(start).Seconds()
		success := "success"
		if err := recover(); err != nil {
			success = "panic"
		}
		if b.metrics != nil {
			b.metrics.CircuitBreakerDuration.WithLabelValues("MariaDB", success).Observe(duration)
		}
	}()

	// Execute within circuit breaker
	result, err := b.cb.Execute(func() (interface{}, error) {
		return b.DB.QueryRowContext(ctx, query, args...), nil
	})
	if err != nil {
		if b.metrics != nil {
			b.metrics.CircuitBreakerDuration.WithLabelValues("MariaDB", "error").Observe(time.Since(start).Seconds())
		}
		return newErrorRow(err)
	}

	if b.metrics != nil {
		b.metrics.CircuitBreakerDuration.WithLabelValues("MariaDB", "success").Observe(time.Since(start).Seconds())
	}
	return result.(*sql.Row)
}

// PrepareContext passes through to the underlying DB connection
// This doesn't use the circuit breaker because preparing a statement
// doesn't actually execute against the database
func (b *BreakerDB) PrepareContext(ctx context.Context, query string) (*sql.Stmt, error) {
	return b.DB.PrepareContext(ctx, query)
}

var (
	faultDB       *sql.DB
	faultOnce     sync.Once
	errorRegistry sync.Map
)

// initFaultDB initializes a singleton DB connection that always fails
func initFaultDB() {
	faultOnce.Do(func() {
		sql.Register("fault_injector", &faultDriver{})
		// Open the DB once. The DSN doesn't matter for our driver.
		var err error
		faultDB, err = sql.Open("fault_injector", "")
		if err != nil {
			// This should never happen with our mock driver
			panic(fmt.Sprintf("failed to initialize fault driver: %v", err))
		}
	})
}

// newErrorRow returns a *sql.Row that will yield the provided error when Scanned.
// It uses a custom driver to avoid using reflection on internal sql.Row fields.
func newErrorRow(err error) *sql.Row {
	initFaultDB()

	// Generate a unique token for this error
	token := fmt.Sprintf("%d", time.Now().UnixNano())
	errorRegistry.Store(token, err)

	// Schedule cleanup (since we don't know when Scan() finishes)
	time.AfterFunc(1*time.Minute, func() {
		errorRegistry.Delete(token)
	})

	// db.QueryRow calls the driver's Prepare/Query.
	// We pass the token as the query string.
	// The driver will look up the error and return it.
	return faultDB.QueryRow(token)
}

type faultDriver struct{}

func (d *faultDriver) Open(name string) (driver.Conn, error) {
	return &faultConn{}, nil
}

type faultConn struct{}

func (c *faultConn) Prepare(query string) (driver.Stmt, error) {
	// The query string is our error token
	if val, ok := errorRegistry.Load(query); ok {
		if err, ok := val.(error); ok {
			return nil, err
		}
	}
	return nil, fmt.Errorf("unknown fault error")
}

func (c *faultConn) Close() error              { return nil }
func (c *faultConn) Begin() (driver.Tx, error) { return nil, fmt.Errorf("not supported") }

// GetState returns the current state of the circuit breaker
func (b *BreakerDB) GetState() gobreaker.State {
	return b.cb.State()
}
