package config

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

type AuditLogConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	Path    string `mapstructure:"path"`
	Format  string `mapstructure:"format"`
}

type DatabaseRetryConfig struct {
	Enabled         *bool          `mapstructure:"enabled"`
	MaxRetries      *int           `mapstructure:"max_retries"`
	InitialInterval *time.Duration `mapstructure:"initial_interval"`
	MaxInterval     *time.Duration `mapstructure:"max_interval"`
	Multiplier      *float64       `mapstructure:"multiplier"`
	Randomization   *float64       `mapstructure:"randomization"`
	FatalErrorTypes []string       `mapstructure:"fatal_error_types"`
}

type Config struct {
	Server   ServerConfig   `mapstructure:"server"`
	Database DatabaseConfig `mapstructure:"database"`
	JWT      JWTConfig      `mapstructure:"jwt"`
	Security SecurityConfig `mapstructure:"security"`
	CORS     CORSConfig     `mapstructure:"cors"`
	Logging  LoggingConfig  `mapstructure:"logging"`
	Metrics  MetricsConfig  `mapstructure:"metrics"`
	Redis    RedisConfig    `mapstructure:"redis"`
	AuditLog AuditLogConfig `mapstructure:"audit_log"`
}

type RedisConfig struct {
	Enabled         bool          `mapstructure:"enabled"`
	Host            string        `mapstructure:"host"`
	Port            string        `mapstructure:"port"`
	Password        string        `mapstructure:"password"`
	DB              int           `mapstructure:"db"`
	MaxRetries      int           `mapstructure:"max_retries"`
	PoolSize        int           `mapstructure:"pool_size"`
	MinIdleConns    int           `mapstructure:"min_idle_conns"`
	ConnMaxLifetime time.Duration `mapstructure:"conn_max_lifetime"`
}

type ServerConfig struct {
	Port            string        `mapstructure:"port"`
	Host            string        `mapstructure:"host"`
	Env             string        `mapstructure:"env"`
	ReadTimeout     time.Duration `mapstructure:"read_timeout"`
	WriteTimeout    time.Duration `mapstructure:"write_timeout"`
	IdleTimeout     time.Duration `mapstructure:"idle_timeout"`
	ShutdownTimeout time.Duration `mapstructure:"shutdown_timeout"`
	UseHTTPS        bool          `mapstructure:"use_https"`
	TrustedProxies  []string      `mapstructure:"trusted_proxies"`
}

type DatabaseConfig struct {
	Host            string              `mapstructure:"host"`
	Port            string              `mapstructure:"port"`
	User            string              `mapstructure:"user"`
	Password        string              `mapstructure:"password"`
	Name            string              `mapstructure:"name"`
	MaxOpenConns    int                 `mapstructure:"max_open_conns"`
	MaxIdleConns    int                 `mapstructure:"max_idle_conns"`
	ConnMaxLifetime time.Duration       `mapstructure:"conn_max_lifetime"`
	ConnMaxIdleTime time.Duration       `mapstructure:"conn_max_idle_time"`
	SlowQueryTime   time.Duration       `mapstructure:"slow_query_time"`
	Retry           DatabaseRetryConfig `mapstructure:"retry"`
	CircuitBreaker  CBConfig            `mapstructure:"circuit_breaker"`
}

type CBConfig struct {
	Enabled          bool          `mapstructure:"enabled"`
	MaxFailures      uint32        `mapstructure:"max_failures"`
	FailureThreshold float64       `mapstructure:"failure_threshold"`
	ResetTimeout     time.Duration `mapstructure:"reset_timeout"`
}

type JWTConfig struct {
	AccessSecret  string        `mapstructure:"access_secret"`
	AccessExpiry  time.Duration `mapstructure:"access_expiry"`
	RefreshExpiry time.Duration `mapstructure:"refresh_expiry"`
}

type SecurityConfig struct {
	BcryptCost                   int           `mapstructure:"bcrypt_cost"`
	RefreshTokenCleanupInterval  time.Duration `mapstructure:"refresh_token_cleanup_interval"`
	RefreshTokenCleanupBatchSize int           `mapstructure:"refresh_token_cleanup_batch_size"`
	MaxLoginAttempts             int           `mapstructure:"max_login_attempts"`
	LoginLockoutDuration         time.Duration `mapstructure:"login_lockout_duration"`
	SessionBindingEnabled        bool          `mapstructure:"session_binding_enabled"`
	DatabaseRetryEnabled         bool          `mapstructure:"database_retry_enabled"`
}

type CORSConfig struct {
	AllowedOrigins []string `mapstructure:"allowed_origins"`
	AllowedMethods []string `mapstructure:"allowed_methods"`
	AllowedHeaders []string `mapstructure:"allowed_headers"`
}

type LoggingConfig struct {
	Level    string `mapstructure:"level"`
	Encoding string `mapstructure:"encoding"`
}

type MetricsConfig struct {
	Enabled bool `mapstructure:"enabled"`
}

func Load() (*Config, error) {
	if err := godotenv.Load(); err != nil {
		fmt.Println("Warning: .env file not found, using environment variables")
	}

	cfg := &Config{
		Server: ServerConfig{
			Port:            getEnv("SERVER_PORT", "8080"),
			Host:            getEnv("SERVER_HOST", "localhost"),
			Env:             getEnv("ENV", "development"),
			ReadTimeout:     getEnvAsDuration("SERVER_READ_TIMEOUT", 15*time.Second),
			WriteTimeout:    getEnvAsDuration("SERVER_WRITE_TIMEOUT", 15*time.Second),
			IdleTimeout:     getEnvAsDuration("SERVER_IDLE_TIMEOUT", 60*time.Second),
			ShutdownTimeout: getEnvAsDuration("SERVER_SHUTDOWN_TIMEOUT", 30*time.Second),
			UseHTTPS:        getEnvAsBool("SERVER_USE_HTTPS", false),
			TrustedProxies:  getEnvAsSlice("SERVER_TRUSTED_PROXIES", []string{"127.0.0.1"}),
		},
		Database: DatabaseConfig{
			Host:            getEnv("DB_HOST", "localhost"),
			Port:            getEnv("DB_PORT", "3306"),
			User:            getEnv("DB_USER", "apiuser"),
			Password:        getEnv("DB_PASSWORD", "apipassword"),
			Name:            getEnv("DB_NAME", "apidb"),
			MaxOpenConns:    getEnvAsInt("DB_MAX_OPEN_CONNS", 25),
			MaxIdleConns:    getEnvAsInt("DB_MAX_IDLE_CONNS", 5),
			ConnMaxLifetime: getEnvAsDuration("DB_CONN_MAX_LIFETIME", 5*time.Minute),
			ConnMaxIdleTime: getEnvAsDuration("DB_CONN_MAX_IDLE_TIME", 5*time.Minute),
			SlowQueryTime:   getEnvAsDuration("DB_SLOW_QUERY_TIME", 500*time.Millisecond),
			Retry: DatabaseRetryConfig{
				Enabled:         getEnvAsBoolPtr("DB_RETRY_ENABLED", true),
				MaxRetries:      getEnvAsIntPtr("DB_RETRY_MAX_RETRIES", 3),
				InitialInterval: getEnvAsDurationPtr("DB_RETRY_INITIAL_INTERVAL", 100*time.Millisecond),
				MaxInterval:     getEnvAsDurationPtr("DB_RETRY_MAX_INTERVAL", 2*time.Second),
				Multiplier:      getEnvAsFloatPtr("DB_RETRY_MULTIPLIER", 2.0),
				Randomization:   getEnvAsFloatPtr("DB_RETRY_RANDOMIZATION", 0.2),
				FatalErrorTypes: getEnvAsSlice("DB_RETRY_FATAL_ERROR_TYPES", []string{"constraint_violation", "duplicate_key", "foreign_key_violation"}),
			},
			CircuitBreaker: CBConfig{
				Enabled:          getEnvAsBool("DB_CIRCUIT_BREAKER_ENABLED", true),
				MaxFailures:      uint32(getEnvAsInt("DB_MAX_FAILURES", 5)),
				FailureThreshold: getEnvAsFloat("DB_FAILURE_THRESHOLD", 0.5),
				ResetTimeout:     getEnvAsDuration("DB_RESET_TIMEOUT", 30*time.Second),
			},
		},
		JWT: JWTConfig{
			AccessSecret:  getEnv("JWT_ACCESS_SECRET", ""),
			AccessExpiry:  getEnvAsDuration("JWT_ACCESS_EXPIRY", 15*time.Minute),
			RefreshExpiry: getEnvAsDuration("JWT_REFRESH_EXPIRY", 168*time.Hour),
		},
		Security: SecurityConfig{
			BcryptCost:                   getEnvAsInt("BCRYPT_COST", 12),
			RefreshTokenCleanupInterval:  getEnvAsDuration("REFRESH_TOKEN_CLEANUP_INTERVAL", 24*time.Hour),
			RefreshTokenCleanupBatchSize: getEnvAsInt("REFRESH_TOKEN_CLEANUP_BATCH_SIZE", 1000),
			MaxLoginAttempts:             getEnvAsInt("MAX_LOGIN_ATTEMPTS", 5),
			LoginLockoutDuration:         getEnvAsDuration("LOGIN_LOCKOUT_DURATION", 15*time.Minute),
			SessionBindingEnabled:        getEnvAsBool("SESSION_BINDING_ENABLED", true),
			DatabaseRetryEnabled:         getEnvAsBool("DATABASE_RETRY_ENABLED", true),
		},
		CORS: CORSConfig{
			AllowedOrigins: getEnvAsSlice("CORS_ALLOWED_ORIGINS", []string{"*"}),
			AllowedMethods: getEnvAsSlice("CORS_ALLOWED_METHODS", []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"}),
			AllowedHeaders: getEnvAsSlice("CORS_ALLOWED_HEADERS", []string{"Content-Type", "Authorization"}),
		},
		Logging: LoggingConfig{
			Level:    getEnv("LOG_LEVEL", "info"),
			Encoding: getEnv("LOG_ENCODING", "json"),
		},
		Metrics: MetricsConfig{
			Enabled: getEnvAsBool("ENABLE_METRICS", true),
		},
		AuditLog: AuditLogConfig{
			Enabled: getEnvAsBool("AUDIT_LOG_ENABLED", true),
			Path:    getEnv("AUDIT_LOG_PATH", ""),
			Format:  getEnv("AUDIT_LOG_FORMAT", "json"),
		},
		Redis: RedisConfig{
			Enabled:         getEnvAsBool("ENABLE_REDIS", false),
			Host:            getEnv("REDIS_HOST", "localhost"),
			Port:            getEnv("REDIS_PORT", "6379"),
			Password:        getEnv("REDIS_PASSWORD", ""),
			DB:              getEnvAsInt("REDIS_DB", 0),
			MaxRetries:      getEnvAsInt("REDIS_MAX_RETRIES", 3),
			PoolSize:        getEnvAsInt("REDIS_POOL_SIZE", 10),
			MinIdleConns:    getEnvAsInt("REDIS_MIN_IDLE_CONNS", 5),
			ConnMaxLifetime: getEnvAsDuration("REDIS_CONN_MAX_LIFETIME", 30*time.Minute),
		},
	}

	return cfg, nil
}

func (c *Config) Validate() error {
	// Common validation for all environments
	if err := c.validateDependencies(); err != nil {
		return err
	}

	// Environment-specific validation
	switch c.Server.Env {
	case "production":
		if err := c.validateProduction(); err != nil {
			return err
		}
	case "staging":
		if err := c.validateStaging(); err != nil {
			return err
		}
	}

	return nil
}

func (c *Config) validateDependencies() error {
	if c.Database.CircuitBreaker.Enabled {
		if c.Database.CircuitBreaker.MaxFailures < 1 {
			return fmt.Errorf("DB_MAX_FAILURES must be at least 1 when circuit breaker is enabled")
		}
		if c.Database.CircuitBreaker.FailureThreshold <= 0 ||
			c.Database.CircuitBreaker.FailureThreshold > 1.0 {
			return fmt.Errorf("DB_FAILURE_THRESHOLD must be between 0 and 1.0")
		}
		if c.Database.CircuitBreaker.ResetTimeout <= 0 {
			return fmt.Errorf("DB_RESET_TIMEOUT must be greater than 0")
		}
	}

	if c.Redis.Enabled && c.Redis.Host == "" {
		return fmt.Errorf("redis host required when redis is enabled")
	}

	if c.JWT.AccessSecret == "" {
		return fmt.Errorf("JWT_ACCESS_SECRET is required")
	}
	if len(c.JWT.AccessSecret) < 32 {
		return fmt.Errorf("JWT access secret must be at least 32 characters long")
	}
	if c.Database.MaxIdleConns > c.Database.MaxOpenConns {
		return fmt.Errorf("DB_MAX_IDLE_CONNS cannot exceed DB_MAX_OPEN_CONNS")
	}

	if c.Database.SlowQueryTime <= 0 {
		return fmt.Errorf("DB_SLOW_QUERY_TIME must be greater than 0")
	}

	if c.Security.BcryptCost < 4 {
		return fmt.Errorf("BCRYPT_COST must be at least 4")
	}

	if c.Server.ReadTimeout <= 0 {
		return fmt.Errorf("SERVER_READ_TIMEOUT must be greater than 0")
	}
	if c.Server.WriteTimeout <= 0 {
		return fmt.Errorf("SERVER_WRITE_TIMEOUT must be greater than 0")
	}
	if c.Server.ShutdownTimeout <= 0 {
		return fmt.Errorf("SERVER_SHUTDOWN_TIMEOUT must be greater than 0")
	}

	if c.Security.RefreshTokenCleanupInterval <= 0 {
		return fmt.Errorf("REFRESH_TOKEN_CLEANUP_INTERVAL must be greater than 0")
	}

	if c.Security.LoginLockoutDuration <= 0 {
		return fmt.Errorf("LOGIN_LOCKOUT_DURATION must be greater than 0")
	}

	if c.Security.MaxLoginAttempts < 1 {
		return fmt.Errorf("MAX_LOGIN_ATTEMPTS must be at least 1")
	}

	return nil
}

func (c *Config) validateProduction() error {
	if len(c.JWT.AccessSecret) < 32 {
		return fmt.Errorf("FATAL SECURITY: JWT access secret must be at least 32 characters long in production")
	}
	// Check for default/insecure JWT secrets
	insecureDefaults := []string{
		"change-this-to-a-secure-random-string",
		"change-this-to-another-secure-random-string",
		"secret",
		"your-secret-key",
	}

	for _, defaultVal := range insecureDefaults {
		if strings.Contains(strings.ToLower(c.JWT.AccessSecret), strings.ToLower(defaultVal)) {
			return fmt.Errorf("FATAL SECURITY: Default/insecure JWT Access Secret detected in production. Please generate a cryptographically secure secret with at least 32 random characters")
		}
	}

	// Validate password strength
	weakPasswords := []string{"password", "apipassword", "admin", "root", "test", ""}
	dbPass := strings.ToLower(c.Database.Password)
	for _, weak := range weakPasswords {
		if dbPass == weak {
			return fmt.Errorf("FATAL SECURITY: Weak or default database password detected in production (current: %s). Use a strong password with at least 16 characters, including uppercase, lowercase, numbers, and special characters", weak)
		}
	}
	// Validate password complexity
	if len(c.Database.Password) < 16 {
		return fmt.Errorf("FATAL SECURITY: Database password must be at least 16 characters in production (current length: %d)", len(c.Database.Password))
	}
	if !hasPasswordComplexity(c.Database.Password) {
		return fmt.Errorf("FATAL SECURITY: Database password must contain uppercase, lowercase, numbers, and special characters in production")
	}

	// Enforce stronger bcrypt cost in production
	if c.Security.BcryptCost < 12 {
		return fmt.Errorf("FATAL SECURITY: BCRYPT_COST must be at least 12 in production (current: %d). Higher values provide better security against brute-force attacks", c.Security.BcryptCost)
	}

	// Validate HTTPS is enabled in production
	if !c.Server.UseHTTPS {
		return fmt.Errorf("FATAL SECURITY: HTTPS must be enabled in production (SERVER_USE_HTTPS=true). HTTP connections expose sensitive data including authentication tokens")
	}

	// Validate Redis is properly configured if rate limiting is production critical
	if !c.Redis.Enabled {
		return fmt.Errorf("WARNING: Redis is disabled in production. In-memory rate limiting will not work across multiple server instances. Enable Redis for distributed rate limiting")
	}

	// Validate rate limiting configuration
	if c.Security.MaxLoginAttempts < 3 {
		return fmt.Errorf("FATAL SECURITY: MAX_LOGIN_ATTEMPTS should be at least 3 in production (current: %d)", c.Security.MaxLoginAttempts)
	}
	if c.Security.LoginLockoutDuration < 5*time.Minute {
		return fmt.Errorf("FATAL SECURITY: LOGIN_LOCKOUT_DURATION should be at least 5 minutes in production (current: %v)", c.Security.LoginLockoutDuration)
	}

	// Production logging should be JSON format
	if c.Logging.Encoding != "json" {
		return fmt.Errorf("FATAL SECURITY: Production logging should use JSON format for better log aggregation and analysis")
	}

	return nil
}

func (c *Config) validateStaging() error {
	// Staging environment should closely mirror production
	if c.Security.BcryptCost < 12 {
		return fmt.Errorf("SECURITY WARNING: BCRYPT_COST should be at least 12 in staging (current: %d) to match production security standards", c.Security.BcryptCost)
	}
	if c.Logging.Encoding != "json" {
		return fmt.Errorf("WARNING: Staging logging should use JSON format to match production logging configuration")
	}
	if !c.Redis.Enabled {
		return fmt.Errorf("WARNING: Redis is disabled in staging. This should match production configuration for accurate testing")
	}
	return nil
}

func hasPasswordComplexity(password string) bool {
	hasUpper := regexp.MustCompile(`[A-Z]`).MatchString(password)
	hasLower := regexp.MustCompile(`[a-z]`).MatchString(password)
	hasNumber := regexp.MustCompile(`[0-9]`).MatchString(password)
	hasSpecial := regexp.MustCompile(`[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>/?]`).MatchString(password)
	return hasUpper && hasLower && hasNumber && hasSpecial
}

func getEnvAsFloatPtr(key string, defaultValue float64) *float64 {
	value := os.Getenv(key)
	if value == "" {
		return &defaultValue
	}
	if floatValue, err := strconv.ParseFloat(value, 64); err == nil {
		return &floatValue
	}
	return &defaultValue
}

func getEnvAsBoolPtr(key string, defaultValue bool) *bool {
	value := os.Getenv(key)
	if value == "" {
		return &defaultValue
	}
	if boolValue, err := strconv.ParseBool(value); err == nil {
		return &boolValue
	}
	return &defaultValue
}

func getEnvAsIntPtr(key string, defaultValue int) *int {
	value := os.Getenv(key)
	if value == "" {
		return &defaultValue
	}
	if intValue, err := strconv.Atoi(value); err == nil {
		return &intValue
	}
	return &defaultValue
}

func getEnvAsDurationPtr(key string, defaultValue time.Duration) *time.Duration {
	value := os.Getenv(key)
	if value == "" {
		return &defaultValue
	}
	if durationValue, err := time.ParseDuration(value); err == nil {
		return &durationValue
	}
	return &defaultValue
}

func getEnvAsFloat(key string, defaultValue float64) float64 {
	if value := os.Getenv(key); value != "" {
		if floatValue, err := strconv.ParseFloat(value, 64); err == nil {
			return floatValue
		}
	}
	return defaultValue
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvAsInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getEnvAsBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	return defaultValue
}

func getEnvAsDuration(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if durationValue, err := time.ParseDuration(value); err == nil {
			return durationValue
		}
	}
	return defaultValue
}

func getEnvAsSlice(key string, defaultValue []string) []string {
	valueStr := os.Getenv(key)
	if valueStr == "" {
		return defaultValue
	}

	parts := strings.Split(valueStr, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmedPart := strings.TrimSpace(part)
		if trimmedPart != "" {
			result = append(result, trimmedPart)
		}
	}
	return result
}
