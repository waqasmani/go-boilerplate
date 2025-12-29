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

func TestValidate_Production(t *testing.T) {
	validConfig := &Config{
		Server: ServerConfig{
			Port:            "8080",
			Host:            "0.0.0.0",
			Env:             "production",
			ReadTimeout:     15 * time.Second,
			WriteTimeout:    15 * time.Second,
			IdleTimeout:     60 * time.Second,
			ShutdownTimeout: 30 * time.Second,
			UseHTTPS:        true,
		},
		Database: DatabaseConfig{
			Host:            "localhost",
			Port:            "3306",
			User:            "prod_user",
			Password:        "Str0ngP@ssw0rd!123",
			Name:            "prod_db",
			MaxOpenConns:    25,
			MaxIdleConns:    5,
			ConnMaxLifetime: 30 * time.Minute,
			ConnMaxIdleTime: 30 * time.Minute,
			SlowQueryTime:   500 * time.Millisecond,
			CircuitBreaker: CBConfig{
				Enabled:          true,
				MaxFailures:      5,
				FailureThreshold: 0.5,
				ResetTimeout:     30 * time.Second,
			},
		},
		JWT: JWTConfig{
			AccessSecret:  "X7sP3kQbN9rT2yV5zX8cW6mJhGfEaBdC0123456789ab",
			AccessExpiry:  15 * time.Minute,
			RefreshExpiry: 168 * time.Hour,
		},
		Security: SecurityConfig{
			BcryptCost:                  12,
			RefreshTokenCleanupInterval: 24 * time.Hour,
			MaxLoginAttempts:            5,
			LoginLockoutDuration:        15 * time.Minute,
			SessionBindingEnabled:       true,
		},
		CORS: CORSConfig{
			AllowedOrigins: []string{"https://example.com"},
			AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"},
			AllowedHeaders: []string{"Content-Type", "Authorization"},
		},
		Logging: LoggingConfig{
			Level:    "info",
			Encoding: "json",
		},
		Metrics: MetricsConfig{
			Enabled: true,
		},
		AuditLog: AuditLogConfig{
			Enabled: true,
			Path:    "/var/log/app/audit.log",
			Format:  "json",
		},
		Redis: RedisConfig{
			Enabled:         true,
			Host:            "redis.example.com",
			Port:            "6379",
			Password:        "redis_strong_password",
			DB:              0,
			MaxRetries:      3,
			PoolSize:        10,
			MinIdleConns:    5,
			ConnMaxLifetime: 30 * time.Minute,
		},
	}

	tests := []struct {
		name        string
		modify      func(cfg *Config)
		expectedErr string
	}{
		{
			name: "Valid production config",
			modify: func(cfg *Config) {
				// No modifications - valid config
			},
			expectedErr: "",
		},
		{
			name: "Invalid JWT secrets (too short)",
			modify: func(cfg *Config) {
				cfg.JWT.AccessSecret = "short_secret"
			},
			expectedErr: "must be at least 32 characters long",
		},
		{
			name: "Default JWT secret in production",
			modify: func(cfg *Config) {
				cfg.JWT.AccessSecret = "change-this-to-a-secure-random-string-that-is-at-least-32-chars"
			},
			expectedErr: "Default/insecure JWT Access Secret detected in production",
		},
		{
			name: "Weak database password",
			modify: func(cfg *Config) {
				cfg.Database.Password = "password"
			},
			expectedErr: "Weak or default database password detected in production",
		},
		{
			name: "Short database password",
			modify: func(cfg *Config) {
				cfg.Database.Password = "Short1!"
			},
			expectedErr: "Database password must be at least 16 characters in production",
		},
		{
			name: "Database password missing complexity",
			modify: func(cfg *Config) {
				cfg.Database.Password = "passwordpassword123"
			},
			expectedErr: "Database password must contain uppercase, lowercase, numbers, and special characters in production",
		},
		{
			name: "Low BCRYPT_COST in production",
			modify: func(cfg *Config) {
				cfg.Security.BcryptCost = 10
			},
			expectedErr: "BCRYPT_COST must be at least 12 in production",
		},
		{
			name: "HTTPS disabled in production",
			modify: func(cfg *Config) {
				cfg.Server.UseHTTPS = false
			},
			expectedErr: "HTTPS must be enabled in production",
		},
		{
			name: "Redis disabled in production",
			modify: func(cfg *Config) {
				cfg.Redis.Enabled = false
			},
			expectedErr: "Redis is disabled in production. In-memory rate limiting will not work across multiple server instances",
		},
		{
			name: "Low MAX_LOGIN_ATTEMPTS in production",
			modify: func(cfg *Config) {
				cfg.Security.MaxLoginAttempts = 2
			},
			expectedErr: "MAX_LOGIN_ATTEMPTS should be at least 3 in production",
		},
		{
			name: "Short LOGIN_LOCKOUT_DURATION in production",
			modify: func(cfg *Config) {
				cfg.Security.LoginLockoutDuration = 4 * time.Minute
			},
			expectedErr: "LOGIN_LOCKOUT_DURATION should be at least 5 minutes in production",
		},
		{
			name: "Non-JSON logging in production",
			modify: func(cfg *Config) {
				cfg.Logging.Encoding = "console"
			},
			expectedErr: "Production logging should use JSON format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testConfig := *validConfig
			tt.modify(&testConfig)
			err := testConfig.Validate()
			if tt.expectedErr == "" {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedErr)
			}
		})
	}
}

func TestValidate_Staging(t *testing.T) {
	validConfig := &Config{
		Server: ServerConfig{
			Port:            "8080",
			Host:            "0.0.0.0",
			Env:             "staging",
			ReadTimeout:     15 * time.Second,
			WriteTimeout:    15 * time.Second,
			IdleTimeout:     60 * time.Second,
			ShutdownTimeout: 30 * time.Second,
			UseHTTPS:        true,
		},
		Database: DatabaseConfig{
			Host:            "localhost",
			Port:            "3306",
			User:            "staging_user",
			Password:        "Str0ngP@ssw0rd!123",
			Name:            "staging_db",
			MaxOpenConns:    25,
			MaxIdleConns:    5,
			ConnMaxLifetime: 30 * time.Minute,
			ConnMaxIdleTime: 30 * time.Minute,
			SlowQueryTime:   500 * time.Millisecond,
			CircuitBreaker: CBConfig{
				Enabled:          true,
				MaxFailures:      5,
				FailureThreshold: 0.5,
				ResetTimeout:     30 * time.Second,
			},
		},
		JWT: JWTConfig{
			AccessSecret:  "X7sP3kQbN9rT2yV5zX8cW6mJhGfEaBdC0123456789ab",
			AccessExpiry:  15 * time.Minute,
			RefreshExpiry: 168 * time.Hour,
		},
		Security: SecurityConfig{
			BcryptCost:                  12,
			RefreshTokenCleanupInterval: 24 * time.Hour,
			MaxLoginAttempts:            5,
			LoginLockoutDuration:        15 * time.Minute,
			SessionBindingEnabled:       true,
		},
		CORS: CORSConfig{
			AllowedOrigins: []string{"https://staging.example.com"},
			AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"},
			AllowedHeaders: []string{"Content-Type", "Authorization"},
		},
		Logging: LoggingConfig{
			Level:    "info",
			Encoding: "json",
		},
		Metrics: MetricsConfig{
			Enabled: true,
		},
		AuditLog: AuditLogConfig{
			Enabled: true,
			Path:    "/var/log/app/audit.log",
			Format:  "json",
		},
		Redis: RedisConfig{
			Enabled:         true,
			Host:            "redis-staging.example.com",
			Port:            "6379",
			Password:        "redis_strong_password",
			DB:              0,
			MaxRetries:      3,
			PoolSize:        10,
			MinIdleConns:    5,
			ConnMaxLifetime: 30 * time.Minute,
		},
	}

	tests := []struct {
		name        string
		modify      func(cfg *Config)
		expectedErr string
	}{
		{
			name: "Valid staging config",
			modify: func(cfg *Config) {
				// No modifications - valid config
			},
			expectedErr: "",
		},
		{
			name: "Low BCRYPT_COST in staging",
			modify: func(cfg *Config) {
				cfg.Security.BcryptCost = 10
			},
			expectedErr: "SECURITY WARNING: BCRYPT_COST should be at least 12 in staging",
		},
		{
			name: "Non-JSON logging in staging",
			modify: func(cfg *Config) {
				cfg.Logging.Encoding = "console"
			},
			expectedErr: "Staging logging should use JSON format",
		},
		{
			name: "Redis disabled in staging",
			modify: func(cfg *Config) {
				cfg.Redis.Enabled = false
			},
			expectedErr: "Redis is disabled in staging. This should match production configuration",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testConfig := *validConfig
			tt.modify(&testConfig)
			err := testConfig.Validate()
			if tt.expectedErr == "" {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedErr)
			}
		})
	}
}

func TestValidate_Common(t *testing.T) {
	validConfig := &Config{
		Server: ServerConfig{
			Port:            "8080",
			Host:            "0.0.0.0",
			Env:             "development",
			ReadTimeout:     15 * time.Second,
			WriteTimeout:    15 * time.Second,
			IdleTimeout:     60 * time.Second,
			ShutdownTimeout: 30 * time.Second,
			UseHTTPS:        false,
		},
		Database: DatabaseConfig{
			Host:            "localhost",
			Port:            "3306",
			User:            "dev_user",
			Password:        "dev_password",
			Name:            "dev_db",
			MaxOpenConns:    25,
			MaxIdleConns:    5,
			ConnMaxLifetime: 30 * time.Minute,
			ConnMaxIdleTime: 30 * time.Minute,
			SlowQueryTime:   500 * time.Millisecond,
			CircuitBreaker: CBConfig{
				Enabled:          true,
				MaxFailures:      5,
				FailureThreshold: 0.5,
				ResetTimeout:     30 * time.Second,
			},
		},
		JWT: JWTConfig{
			AccessSecret:  "X7sP3kQbN9rT2yV5zX8cW6mJhGfEaBdC0123456789ab",
			AccessExpiry:  15 * time.Minute,
			RefreshExpiry: 168 * time.Hour,
		},
		Security: SecurityConfig{
			BcryptCost:                  10,
			RefreshTokenCleanupInterval: 24 * time.Hour,
			MaxLoginAttempts:            3,
			LoginLockoutDuration:        15 * time.Minute,
			SessionBindingEnabled:       true,
		},
		CORS: CORSConfig{
			AllowedOrigins: []string{"*"},
			AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"},
			AllowedHeaders: []string{"Content-Type", "Authorization"},
		},
		Logging: LoggingConfig{
			Level:    "info",
			Encoding: "console",
		},
		Metrics: MetricsConfig{
			Enabled: true,
		},
	}

	tests := []struct {
		name        string
		modify      func(cfg *Config)
		expectedErr string
	}{
		{
			name: "MaxIdleConns exceeds MaxOpenConns",
			modify: func(cfg *Config) {
				cfg.Database.MaxIdleConns = 30
				cfg.Database.MaxOpenConns = 25
			},
			expectedErr: "DB_MAX_IDLE_CONNS cannot exceed DB_MAX_OPEN_CONNS",
		},
		{
			name: "Invalid circuit breaker settings - negative reset timeout",
			modify: func(cfg *Config) {
				cfg.Database.CircuitBreaker.ResetTimeout = -1 * time.Second
			},
			expectedErr: "DB_RESET_TIMEOUT must be greater than 0",
		},
		{
			name: "Invalid circuit breaker settings - invalid failure threshold",
			modify: func(cfg *Config) {
				cfg.Database.CircuitBreaker.FailureThreshold = 1.5
			},
			expectedErr: "DB_FAILURE_THRESHOLD must be between 0 and 1.0",
		},
		{
			name: "Invalid circuit breaker settings - max failures too low",
			modify: func(cfg *Config) {
				cfg.Database.CircuitBreaker.MaxFailures = 0
			},
			expectedErr: "DB_MAX_FAILURES must be at least 1 when circuit breaker is enabled",
		},
		{
			name: "Missing Redis host when enabled",
			modify: func(cfg *Config) {
				cfg.Redis.Enabled = true
				cfg.Redis.Host = ""
			},
			expectedErr: "redis host required when redis is enabled",
		},
		{
			name: "Missing JWT access secret",
			modify: func(cfg *Config) {
				cfg.JWT.AccessSecret = ""
			},
			expectedErr: "JWT_ACCESS_SECRET is required",
		},
		{
			name: "Short JWT access secret",
			modify: func(cfg *Config) {
				cfg.JWT.AccessSecret = "short"
			},
			expectedErr: "must be at least 32 characters long",
		},
		{
			name: "Invalid slow query time",
			modify: func(cfg *Config) {
				cfg.Database.SlowQueryTime = -1
			},
			expectedErr: "DB_SLOW_QUERY_TIME must be greater than 0",
		},
		{
			name: "Invalid bcrypt cost",
			modify: func(cfg *Config) {
				cfg.Security.BcryptCost = 3
			},
			expectedErr: "BCRYPT_COST must be at least 4",
		},
		{
			name: "Invalid read timeout",
			modify: func(cfg *Config) {
				cfg.Server.ReadTimeout = 0
			},
			expectedErr: "SERVER_READ_TIMEOUT must be greater than 0",
		},
		{
			name: "Invalid write timeout",
			modify: func(cfg *Config) {
				cfg.Server.WriteTimeout = 0
			},
			expectedErr: "SERVER_WRITE_TIMEOUT must be greater than 0",
		},
		{
			name: "Invalid shutdown timeout",
			modify: func(cfg *Config) {
				cfg.Server.ShutdownTimeout = 0
			},
			expectedErr: "SERVER_SHUTDOWN_TIMEOUT must be greater than 0",
		},
		{
			name: "Invalid refresh token cleanup interval",
			modify: func(cfg *Config) {
				cfg.Security.RefreshTokenCleanupInterval = 0
			},
			expectedErr: "REFRESH_TOKEN_CLEANUP_INTERVAL must be greater than 0",
		},
		{
			name: "Invalid login lockout duration",
			modify: func(cfg *Config) {
				cfg.Security.LoginLockoutDuration = 0
			},
			expectedErr: "LOGIN_LOCKOUT_DURATION must be greater than 0",
		},
		{
			name: "Invalid max login attempts",
			modify: func(cfg *Config) {
				cfg.Security.MaxLoginAttempts = 0
			},
			expectedErr: "MAX_LOGIN_ATTEMPTS must be at least 1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testConfig := *validConfig
			tt.modify(&testConfig)
			err := testConfig.Validate()
			if tt.expectedErr == "" {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedErr)
			}
		})
	}
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
