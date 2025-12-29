package database

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/go-sql-driver/mysql"
	"github.com/stretchr/testify/assert"
	"github.com/waqasmani/go-boilerplate/internal/config"
	"github.com/waqasmani/go-boilerplate/internal/infrastructure/database/errors"
	"github.com/waqasmani/go-boilerplate/internal/infrastructure/observability"
)

func TestNewMariaDB(t *testing.T) {
	logger, _ := observability.NewLogger("info", "json")
	metrics := observability.NewMetrics()

	cfg := &config.DatabaseConfig{
		Host:     "localhost",
		Port:     "3306",
		User:     "testuser",
		Password: "testpass",
		Name:     "testdb",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Test successful connection
	db, err := NewMariaDB(ctx, cfg, metrics, logger)
	if err == nil {
		defer db.Close()
		assert.NotNil(t, db)
	}

	// Test connection failure
	badCfg := &config.DatabaseConfig{
		Host:     "invalidhost",
		Port:     "3306",
		User:     "testuser",
		Password: "testpass",
		Name:     "testdb",
	}

	db, err = NewMariaDB(ctx, badCfg, metrics, logger)
	assert.Nil(t, db)
	assert.Error(t, err)
}

func TestWithTx(t *testing.T) {
	logger, _ := observability.NewLogger("info", "json")
	metrics := observability.NewMetrics()

	// Create a mock database
	db, mock, err := sqlmock.New()
	assert.NoError(t, err)
	defer db.Close()

	mockDB := &DB{
		DB:          db,
		retryConfig: errors.DefaultRetryConfig(),
		metrics:     metrics,
		logger:      logger,
	}

	// Test successful transaction
	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO users").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	err = mockDB.WithTx(context.Background(), func(tx *sql.Tx) error {
		_, err := tx.Exec("INSERT INTO users (name) VALUES (?)", "test")
		return err
	})
	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())

	// Test failed transaction
	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO users").WillReturnError(assert.AnError)
	mock.ExpectRollback()

	err = mockDB.WithTx(context.Background(), func(tx *sql.Tx) error {
		_, err := tx.Exec("INSERT INTO users (name) VALUES (?)", "test")
		return err
	})
	assert.Error(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestRetryOnTransientErrors(t *testing.T) {
	logger, _ := observability.NewLogger("info", "json")
	metrics := observability.NewMetrics()

	// Create a mock database
	db, mock, err := sqlmock.New()
	assert.NoError(t, err)
	defer db.Close()

	mockDB := &DB{
		DB:          db,
		retryConfig: errors.DefaultRetryConfig(),
		metrics:     metrics,
		logger:      logger,
	}

	mock.ExpectQuery("SELECT \\* FROM users").WillReturnError(&mysql.MySQLError{Number: 1213})

	// Second expectation: return successful result on retry
	mock.ExpectQuery("SELECT \\* FROM users").WillReturnRows(sqlmock.NewRows([]string{"id", "name"}).AddRow(1, "test"))

	rows, err := mockDB.QueryContext(context.Background(), "SELECT * FROM users")
	assert.NoError(t, err)
	assert.NotNil(t, rows)
	assert.NoError(t, mock.ExpectationsWereMet())
}
