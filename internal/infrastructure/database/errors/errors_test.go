package errors

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/go-sql-driver/mysql"
	"github.com/stretchr/testify/assert"
	"github.com/waqasmani/go-boilerplate/internal/config"
	"github.com/waqasmani/go-boilerplate/internal/infrastructure/observability"
)

func TestClassifyError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected DBErrorType
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: "",
		},
		{
			name:     "deadlock error",
			err:      &mysql.MySQLError{Number: 1213, Message: "Deadlock found when trying to get lock"},
			expected: ErrorTypeDeadlock,
		},
		{
			name:     "duplicate key error",
			err:      &mysql.MySQLError{Number: 1062, Message: "Duplicate entry"},
			expected: ErrorTypeDuplicateKey,
		},
		{
			name:     "foreign key violation",
			err:      &mysql.MySQLError{Number: 1451, Message: "Cannot delete or update a parent row"},
			expected: ErrorTypeForeignKeyViolation,
		},
		{
			name:     "connection timeout",
			err:      &mysql.MySQLError{Number: 2013, Message: "Lost connection to MySQL server during query"},
			expected: ErrorTypeConnectionTimeout,
		},
		{
			name:     "connection refused",
			err:      &mysql.MySQLError{Number: 2003, Message: "Can't connect to MySQL server"},
			expected: ErrorTypeConnectionRefused,
		},
		{
			name:     "unknown error",
			err:      &mysql.MySQLError{Number: 9999, Message: "Unknown error"},
			expected: ErrorTypeUnknown,
		},
		{
			name:     "context deadline exceeded",
			err:      context.DeadlineExceeded,
			expected: ErrorTypeQueryTimeout,
		},
		{
			name:     "no rows error",
			err:      sql.ErrNoRows,
			expected: ErrorTypeUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ClassifyError(tt.err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsTransientError(t *testing.T) {
	transientErrors := []error{
		&mysql.MySQLError{Number: 1213}, // Deadlock
		&mysql.MySQLError{Number: 2013}, // Lost connection
		context.DeadlineExceeded,
	}

	nonTransientErrors := []error{
		&mysql.MySQLError{Number: 1062}, // Duplicate key
		&mysql.MySQLError{Number: 1451}, // Foreign key violation
		sql.ErrNoRows,
		errors.New("some other error"),
	}

	for _, err := range transientErrors {
		assert.True(t, IsTransientError(err), "Expected transient error for: %v", err)
	}

	for _, err := range nonTransientErrors {
		assert.False(t, IsTransientError(err), "Expected non-transient error for: %v", err)
	}
}

func TestRetryOperation_Success(t *testing.T) {
	logger, _ := observability.NewLogger("info", "console")
	metrics := observability.NewMetrics()

	cfg := DefaultRetryConfig()
	cfg.MaxRetries = 3

	attempts := 0
	err := RetryOperation(context.Background(), "test_operation", func(attempt uint64) error {
		attempts++
		if attempts < 2 {
			return &mysql.MySQLError{Number: 1213} // Deadlock
		}
		return nil
	}, cfg, metrics, logger)

	assert.NoError(t, err)
	assert.Equal(t, 2, attempts)
}

func TestRetryOperation_MaxRetries(t *testing.T) {
	logger, _ := observability.NewLogger("info", "console")
	metrics := observability.NewMetrics()

	cfg := DefaultRetryConfig()
	cfg.MaxRetries = 2

	attempts := 0
	err := RetryOperation(context.Background(), "test_operation", func(attempt uint64) error {
		attempts++
		return &mysql.MySQLError{Number: 1213} // Deadlock
	}, cfg, metrics, logger)

	assert.Error(t, err)
	assert.Equal(t, 2, attempts)
}

func TestRetryOperation_FatalError(t *testing.T) {
	logger, _ := observability.NewLogger("info", "console")
	metrics := observability.NewMetrics()

	cfg := DefaultRetryConfig()

	attempts := 0
	err := RetryOperation(context.Background(), "test_operation", func(attempt uint64) error {
		attempts++
		return &mysql.MySQLError{Number: 1062} // Duplicate key (fatal)
	}, cfg, metrics, logger)

	assert.Error(t, err)
	assert.Equal(t, 1, attempts)
}

func TestWithRetryTx(t *testing.T) {
	logger, _ := observability.NewLogger("info", "console")
	metrics := observability.NewMetrics()
	cfg := DefaultRetryConfig()

	db, mock, err := sqlmock.New()
	assert.NoError(t, err)
	defer db.Close()

	// First attempt fails with deadlock
	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO test").WillReturnError(&mysql.MySQLError{Number: 1213})
	mock.ExpectRollback()

	// Second attempt succeeds
	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO test").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	err = WithRetryTx(context.Background(), db, func(tx *sql.Tx) error {
		_, execErr := tx.Exec("INSERT INTO test VALUES (?)", 1)
		return execErr
	}, cfg, metrics, logger)

	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestRetryConfig_MergeWith(t *testing.T) {
	original := DefaultRetryConfig()
	config := &config.DatabaseRetryConfig{
		Enabled:         ptr(true),
		MaxRetries:      ptr(5),
		InitialInterval: ptr(50 * time.Millisecond),
		MaxInterval:     ptr(3 * time.Second),
		Multiplier:      ptr(1.5),
		Randomization:   ptr(0.25),
		FatalErrorTypes: []string{"constraint_violation", "duplicate_key"},
	}

	result := original.MergeWith(config)

	assert.True(t, result.Enabled)
	assert.Equal(t, 5, result.MaxRetries)
	assert.Equal(t, 50*time.Millisecond, result.InitialInterval)
	assert.Equal(t, 3*time.Second, result.MaxInterval)
	assert.Equal(t, 1.5, result.Multiplier)
	assert.Equal(t, 0.25, result.Randomization)
	assert.Len(t, result.FatalErrorTypes, 2)
	assert.Contains(t, result.FatalErrorTypes, ErrorTypeConstraintViolation)
	assert.Contains(t, result.FatalErrorTypes, ErrorTypeDuplicateKey)
}

func ptr[T any](v T) *T {
	return &v
}
