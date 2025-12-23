package database

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/waqasmani/go-boilerplate/internal/config"
)

func TestNewMariaDB_Config(t *testing.T) {
	// 1. Test invalid connection (Ping failure)
	// We point to a port that shouldn't be open or a bad host to force a ping error
	// without needing to mock the driver internals heavily for this specific function.
	cfg := &config.DatabaseConfig{
		Host:            "255.255.255.255", // Non-routable IP to force timeout/fail
		Port:            "3306",
		User:            "user",
		Password:        "pass",
		Name:            "db",
		ConnMaxLifetime: time.Millisecond * 10,
	}

	// Short timeout for test speed
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	db, err := NewMariaDB(ctx, cfg)
	assert.Error(t, err)
	assert.Nil(t, db)
	assert.Contains(t, err.Error(), "failed to ping database")
}

func TestNewMariaDB_DSN_Format(t *testing.T) {
	// This test ensures the formatting logic in NewMariaDB doesn't panic
	// even if the driver fails immediately.
	cfg := &config.DatabaseConfig{
		Host:     "localhost",
		Port:     "3306",
		User:     "testuser",
		Password: "testpass",
		Name:     "testdb",
	}

	// We simply call NewMariaDB with this config.
	// We expect an error (because no DB is running), but we verify
	// that the DSN string formatting inside the function didn't panic.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	_, err := NewMariaDB(ctx, cfg)

	// We expect a ping error, but not a panic.
	assert.Error(t, err)
}

func TestDB_Tx(t *testing.T) {
	// Note: Detailed Transaction testing requires a mock or real DB.
	// Since DB embeds *sql.DB, standard sql behavior is assumed.
	// The WithTx wrapper is best tested in the Service layer tests using sqlmock.
}
