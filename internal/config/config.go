package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	Server   ServerConfig   `mapstructure:"server"`
	Database DatabaseConfig `mapstructure:"database"`
	JWT      JWTConfig      `mapstructure:"jwt"`
	Security SecurityConfig `mapstructure:"security"`
	CORS     CORSConfig     `mapstructure:"cors"`
	Logging  LoggingConfig  `mapstructure:"logging"`
	Metrics  MetricsConfig  `mapstructure:"metrics"`
	Redis    RedisConfig    `mapstructure:"redis"`
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
}

type DatabaseConfig struct {
	Host            string        `mapstructure:"host"`
	Port            string        `mapstructure:"port"`
	User            string        `mapstructure:"user"`
	Password        string        `mapstructure:"password"`
	Name            string        `mapstructure:"name"`
	MaxOpenConns    int           `mapstructure:"max_open_conns"`
	MaxIdleConns    int           `mapstructure:"max_idle_conns"`
	ConnMaxLifetime time.Duration `mapstructure:"conn_max_lifetime"`
	ConnMaxIdleTime time.Duration `mapstructure:"conn_max_idle_time"`
}

type JWTConfig struct {
	AccessSecret  string        `mapstructure:"access_secret"`
	RefreshSecret string        `mapstructure:"refresh_secret"`
	AccessExpiry  time.Duration `mapstructure:"access_expiry"`
	RefreshExpiry time.Duration `mapstructure:"refresh_expiry"`
}

type SecurityConfig struct {
	BcryptCost                  int           `mapstructure:"bcrypt_cost"`
	RefreshTokenCleanupInterval time.Duration `mapstructure:"refresh_token_cleanup_interval"`
	MaxLoginAttempts            int           `mapstructure:"max_login_attempts"`
	LoginLockoutDuration        time.Duration `mapstructure:"login_lockout_duration"`
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
		},
		JWT: JWTConfig{
			AccessSecret:  getEnv("JWT_ACCESS_SECRET", ""),
			RefreshSecret: getEnv("JWT_REFRESH_SECRET", ""),
			AccessExpiry:  getEnvAsDuration("JWT_ACCESS_EXPIRY", 15*time.Minute),
			RefreshExpiry: getEnvAsDuration("JWT_REFRESH_EXPIRY", 168*time.Hour),
		},
		Security: SecurityConfig{
			BcryptCost:                  getEnvAsInt("BCRYPT_COST", 12),
			RefreshTokenCleanupInterval: getEnvAsDuration("REFRESH_TOKEN_CLEANUP_INTERVAL", 24*time.Hour),
			MaxLoginAttempts:            getEnvAsInt("MAX_LOGIN_ATTEMPTS", 5),
			LoginLockoutDuration:        getEnvAsDuration("LOGIN_LOCKOUT_DURATION", 15*time.Minute),
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

	if err := cfg.ValidateDependencies(); err != nil {
		return nil, err
	}

	return cfg, nil
}

func (c *Config) ValidateDependencies() error {
	if c.Redis.Enabled && c.Redis.Host == "" {
		return fmt.Errorf("redis host required when redis is enabled")
	}
	if c.JWT.AccessSecret == "" {
		return fmt.Errorf("JWT_ACCESS_SECRET is required")
	}
	if c.JWT.RefreshSecret == "" {
		return fmt.Errorf("JWT_REFRESH_SECRET is required")
	}
	if len(c.JWT.AccessSecret) < 32 {
		return fmt.Errorf("JWT_ACCESS_SECRET must be at least 32 characters long")
	}
	if len(c.JWT.RefreshSecret) < 32 {
		return fmt.Errorf("JWT_REFRESH_SECRET must be at least 32 characters long")
	}
	if c.Database.MaxIdleConns > c.Database.MaxOpenConns {
		return fmt.Errorf("DB_MAX_IDLE_CONNS cannot exceed DB_MAX_OPEN_CONNS")
	}
	if c.Security.BcryptCost < 4 || c.Security.BcryptCost > 31 {
		return fmt.Errorf("BCRYPT_COST must be between 4 and 31")
	}
	return nil
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
