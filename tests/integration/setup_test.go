package integration

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	_ "github.com/go-sql-driver/mysql"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
	"github.com/waqasmani/go-boilerplate/internal/app"
	"github.com/waqasmani/go-boilerplate/internal/config"
	"github.com/waqasmani/go-boilerplate/internal/infrastructure/observability"
)

type TestContext struct {
	DB        *sql.DB
	Container *app.Container
	Router    *gin.Engine
	Config    *config.Config
	Logger    *observability.Logger
}

func SetupTestEnvironment(t *testing.T) *TestContext {
	// Reset Prometheus registry before each test
	registry := prometheus.NewRegistry()
	prometheus.DefaultRegisterer = registry
	prometheus.DefaultGatherer = registry
	gin.SetMode(gin.TestMode)
	os.Setenv("ENABLE_RATE_LIMIT", "false")
	os.Setenv("JWT_ACCESS_SECRET", "test_access_secret_that_is_at_least_32_characters_long")
	os.Setenv("JWT_REFRESH_SECRET", "test_refresh_secret_that_is_at_least_32_characters_long")

	// Only set default expiry if not already set by the test
	if os.Getenv("JWT_ACCESS_EXPIRY") == "" {
		os.Setenv("JWT_ACCESS_EXPIRY", "15m")
	}

	os.Setenv("JWT_REFRESH_EXPIRY", "168h")
	os.Setenv("BCRYPT_COST", "4")
	os.Setenv("ENV", "test")

	testDBHost := os.Getenv("TEST_DB_HOST")
	if testDBHost == "" {
		testDBHost = "localhost"
	}

	testDBPort := os.Getenv("TEST_DB_PORT")
	if testDBPort == "" {
		testDBPort = "3306"
	}

	testDBUser := os.Getenv("TEST_DB_USER")
	if testDBUser == "" {
		// Use the same credentials as defined in the CI workflow
		testDBUser = "auth_user"
	}

	testDBPassword := os.Getenv("TEST_DB_PASSWORD")
	if testDBPassword == "" {
		// Use the same credentials as defined in the CI workflow
		testDBPassword = "your_secure_password"
	}

	testDBName := "auth_test_db"

	os.Setenv("DB_HOST", testDBHost)
	os.Setenv("DB_PORT", testDBPort)
	os.Setenv("DB_USER", testDBUser)
	os.Setenv("DB_PASSWORD", testDBPassword)
	os.Setenv("DB_NAME", testDBName)

	cfg, err := config.Load()
	require.NoError(t, err, "Failed to load config")

	logger, err := observability.NewLogger("error", "console")
	require.NoError(t, err, "Failed to create logger")

	// Create database as root user first
	rootDSN := fmt.Sprintf("root:root_password@tcp(%s:%s)/", testDBHost, testDBPort)
	rootDB, err := sql.Open("mysql", rootDSN)
	require.NoError(t, err, "Failed to connect to MySQL as root")

	defer func() {
		if err := rootDB.Close(); err != nil {
			t.Logf("Warning: Failed to close root database connection: %v", err)
		}
	}()

	// Create test database
	_, err = rootDB.Exec(fmt.Sprintf("CREATE DATABASE IF NOT EXISTS `%s`", testDBName))
	require.NoError(t, err, "Failed to create test database")

	// Grant privileges to the test user
	_, err = rootDB.Exec(fmt.Sprintf("GRANT ALL PRIVILEGES ON `%s`.* TO '%s'@'%%'", testDBName, testDBUser))
	require.NoError(t, err, "Failed to grant privileges to test user")

	testDSN := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?parseTime=true&charset=utf8mb4&collation=utf8mb4_unicode_ci",
		testDBUser, testDBPassword, testDBHost, testDBPort, testDBName)

	db, err := sql.Open("mysql", testDSN)
	require.NoError(t, err, "Failed to connect to test database")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	require.NoError(t, db.PingContext(ctx), "Failed to ping test database")

	require.NoError(t, runMigrations(db), "Failed to run migrations")

	container := app.NewContainer(cfg, db, logger)
	router := app.SetupRouter(container)

	return &TestContext{
		DB:        db,
		Container: container,
		Router:    router,
		Config:    cfg,
		Logger:    logger,
	}
}

func (tc *TestContext) Cleanup(t *testing.T) {
	if tc == nil {
		return
	}

	if tc.DB != nil {
		if err := tc.DB.Close(); err != nil {
			t.Logf("Warning: Failed to close test database connection: %v", err)
		}
	}

	if tc.Logger != nil {
		if err := tc.Logger.Sync(); err != nil {
			t.Logf("Warning: Failed to sync logger: %v", err)
		}
	}

	if tc.Config == nil {
		return
	}

	testDBName := tc.Config.Database.Name
	testDBHost := tc.Config.Database.Host
	testDBPort := tc.Config.Database.Port

	// Use root credentials for cleanup
	rootDSN := fmt.Sprintf("root:root_password@tcp(%s:%s)/", testDBHost, testDBPort)
	rootDB, err := sql.Open("mysql", rootDSN)
	if err != nil {
		t.Logf("Warning: Failed to connect to MySQL for cleanup: %v", err)
		return
	}
	defer func() {
		if err := rootDB.Close(); err != nil {
			t.Logf("Warning: Failed to close root database connection during cleanup: %v", err)
		}
	}()

	_, err = rootDB.Exec(fmt.Sprintf("DROP DATABASE IF EXISTS `%s`", testDBName))
	if err != nil {
		t.Logf("Warning: Failed to drop test database: %v", err)
	}
}

func runMigrations(db *sql.DB) error {
	migrations := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
			email VARCHAR(255) NOT NULL UNIQUE,
			password_hash VARCHAR(255) NOT NULL,
			first_name VARCHAR(100) NOT NULL,
			last_name VARCHAR(100) NOT NULL,
			role VARCHAR(50) NOT NULL DEFAULT 'user',
			is_active BOOLEAN NOT NULL DEFAULT TRUE,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
			INDEX idx_email (email),
			INDEX idx_role (role),
			INDEX idx_is_active (is_active)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,

		`CREATE TABLE IF NOT EXISTS refresh_tokens (
			id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
			user_id BIGINT UNSIGNED NOT NULL,
			token_hash VARCHAR(255) NOT NULL UNIQUE,
			expires_at TIMESTAMP NOT NULL,
			revoked_at TIMESTAMP NULL,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			INDEX idx_user_id (user_id),
			INDEX idx_expires_at (expires_at),
			INDEX idx_revoked_at (revoked_at),
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	for _, migration := range migrations {
		if _, err := tx.ExecContext(ctx, migration); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration failed: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit migrations: %w", err)
	}

	return nil
}

func (tc *TestContext) CreateTestUser(t *testing.T, email, password, role string) uint64 {
	hashedPassword, err := tc.Container.PasswordService.Hash(context.Background(), password)
	require.NoError(t, err, "Failed to hash password")

	result, err := tc.DB.Exec(
		"INSERT INTO users (email, password_hash, first_name, last_name, role, is_active) VALUES (?, ?, ?, ?, ?, TRUE)",
		email, hashedPassword, "Test", "User", role,
	)
	require.NoError(t, err, "Failed to create test user")

	userID, err := result.LastInsertId()
	require.NoError(t, err, "Failed to get user ID")

	return uint64(userID)
}
