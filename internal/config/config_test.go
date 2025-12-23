package config

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestLoad_Success(t *testing.T) {
	os.Clearenv()
	// Set minimal required fields
	os.Setenv("JWT_ACCESS_SECRET", "12345678901234567890123456789012")
	os.Setenv("JWT_REFRESH_SECRET", "12345678901234567890123456789012")

	// Set specific overrides
	os.Setenv("SERVER_PORT", "9090")
	os.Setenv("ENABLE_METRICS", "false")
	os.Setenv("DB_MAX_OPEN_CONNS", "50")
	os.Setenv("CORS_ALLOWED_ORIGINS", "http://foo.com,http://bar.com")

	defer os.Clearenv()

	cfg, err := Load()
	assert.NoError(t, err)
	assert.NotNil(t, cfg)

	assert.Equal(t, "9090", cfg.Server.Port)
	assert.False(t, cfg.Metrics.Enabled)
	assert.Equal(t, 50, cfg.Database.MaxOpenConns)
	assert.Equal(t, []string{"http://foo.com", "http://bar.com"}, cfg.CORS.AllowedOrigins)
}

func TestLoad_ValidationFailure(t *testing.T) {
	os.Clearenv()

	// Case 1: Missing Secrets completely
	_, err := Load()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "JWT_ACCESS_SECRET is required")

	// Case 2: Short Secret
	// We must set the OTHER secret to valid, so we only fail on the one we are testing
	os.Setenv("JWT_REFRESH_SECRET", "12345678901234567890123456789012")
	os.Setenv("JWT_ACCESS_SECRET", "short")

	_, err = Load()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "must be at least 32 characters")
}

func TestGetEnvHelpers(t *testing.T) {
	os.Setenv("TEST_INT", "abc")
	os.Setenv("TEST_BOOL", "not_bool")
	os.Setenv("TEST_DUR", "invalid_dur")
	defer os.Clearenv()

	assert.Equal(t, 10, getEnvAsInt("TEST_INT", 10))
	assert.Equal(t, true, getEnvAsBool("TEST_BOOL", true))
	assert.Equal(t, time.Second, getEnvAsDuration("TEST_DUR", time.Second))

	os.Setenv("TEST_SLICE", "")
	assert.Equal(t, []string{"default"}, getEnvAsSlice("TEST_SLICE", []string{"default"}))
}
