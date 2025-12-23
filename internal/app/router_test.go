package app

import (
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/waqasmani/go-boilerplate/internal/config"
	"github.com/waqasmani/go-boilerplate/internal/infrastructure/observability"
)

func TestSetupRouter_ConfigVariations(t *testing.T) {
	db, _, _ := sqlmock.New()
	logger, _ := observability.NewLogger("info", "console")

	t.Run("Production Mode", func(t *testing.T) {
		cfg := &config.Config{
			Server:   config.ServerConfig{Env: "production"},
			Metrics:  config.MetricsConfig{Enabled: true},
			Redis:    config.RedisConfig{Enabled: false},
			Security: config.SecurityConfig{BcryptCost: 4},
			JWT: config.JWTConfig{
				AccessSecret:  "12345678901234567890123456789012",
				RefreshSecret: "12345678901234567890123456789012",
			},
			CORS: config.CORSConfig{AllowedOrigins: []string{"*"}},
		}

		container := NewContainer(cfg, db, logger)
		router := SetupRouter(container)
		assert.NotNil(t, router)
	})

	t.Run("Development Mode", func(t *testing.T) {
		cfg := &config.Config{
			Server:   config.ServerConfig{Env: "development"},
			Metrics:  config.MetricsConfig{Enabled: false},
			Redis:    config.RedisConfig{Enabled: false},
			Security: config.SecurityConfig{BcryptCost: 4},
			JWT: config.JWTConfig{
				AccessSecret:  "12345678901234567890123456789012",
				RefreshSecret: "12345678901234567890123456789012",
			},
			CORS: config.CORSConfig{AllowedOrigins: []string{"*"}},
		}

		container := NewContainer(cfg, db, logger)
		router := SetupRouter(container)
		assert.NotNil(t, router)
	})
}
