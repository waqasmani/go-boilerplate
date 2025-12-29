package app

import (
	"os"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/waqasmani/go-boilerplate/internal/config"
	"github.com/waqasmani/go-boilerplate/internal/infrastructure/observability"
)

func TestServer_Cleanup(t *testing.T) {
	os.Clearenv()
	os.Setenv("JWT_ACCESS_SECRET", "a_very_secure_secret_that_is_at_least_32_characters_long")

	db, mock, err := sqlmock.New()
	assert.NoError(t, err)
	defer db.Close()

	logger, err := observability.NewLogger("error", "console")
	assert.NoError(t, err)

	cfg, err := config.Load()
	assert.NoError(t, err)
	cfg.Security.RefreshTokenCleanupInterval = time.Millisecond * 10

	container := NewContainer(cfg, db, logger)

	server := NewServer(container)

	mock.ExpectExec("DELETE FROM refresh_tokens").
		WillReturnResult(sqlmock.NewResult(0, 5))

	server.cleanupExpiredTokens()

	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestContainer_Initialization(t *testing.T) {
	registry := prometheus.NewRegistry()
	prometheus.DefaultRegisterer = registry
	prometheus.DefaultGatherer = registry

	db, _, _ := sqlmock.New()
	cfg := &config.Config{
		JWT: config.JWTConfig{
			AccessSecret: "valid_secret_at_least_32_characters_long",
		},
	}
	logger, _ := observability.NewLogger("info", "console")
	container := NewContainer(cfg, db, logger)
	assert.NotNil(t, container.Queries)
	assert.NotNil(t, container.JWTService)
	assert.NotNil(t, container.HealthHandler)
}
