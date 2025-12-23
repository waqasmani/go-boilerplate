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
		testDBUser = "vms_user"
	}

	testDBPassword := os.Getenv("TEST_DB_PASSWORD")
	if testDBPassword == "" {
		testDBPassword = "your_secure_password"
	}

	testDBName := "auth_test_db"

	os.Setenv("DB_HOST", testDBHost)
	os.Setenv("DB_PORT", testDBPort)
	os.Setenv("DB_USER", testDBUser)
	os.Setenv("DB_PASSWORD", testDBPassword)
	os.Setenv("DB_NAME", testDBName)

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	logger, err := observability.NewLogger("error", "console")
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	rootDSN := fmt.Sprintf("%s:%s@tcp(%s:%s)/", testDBUser, testDBPassword, testDBHost, testDBPort)
	rootDB, err := sql.Open("mysql", rootDSN)
	if err != nil {
		t.Fatalf("Failed to connect to MySQL: %v", err)
	}

	_, err = rootDB.Exec(fmt.Sprintf("CREATE DATABASE IF NOT EXISTS `%s`", testDBName))
	if err != nil {
		t.Fatalf("Failed to create test database: %v", err)
	}
	rootDB.Close()

	testDSN := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?parseTime=true&charset=utf8mb4&collation=utf8mb4_unicode_ci",
		testDBUser, testDBPassword, testDBHost, testDBPort, testDBName)

	db, err := sql.Open("mysql", testDSN)
	if err != nil {
		t.Fatalf("Failed to connect to test database: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("Failed to ping test database: %v", err)
	}

	if err := runMigrations(db); err != nil {
		t.Fatalf("Failed to run migrations: %v", err)
	}

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
	testDBName := tc.Config.Database.Name

	tc.DB.Close()

	testDBHost := tc.Config.Database.Host
	testDBPort := tc.Config.Database.Port
	testDBUser := tc.Config.Database.User
	testDBPassword := tc.Config.Database.Password

	rootDSN := fmt.Sprintf("%s:%s@tcp(%s:%s)/", testDBUser, testDBPassword, testDBHost, testDBPort)
	rootDB, err := sql.Open("mysql", rootDSN)
	if err != nil {
		t.Logf("Warning: Failed to connect to MySQL for cleanup: %v", err)
		return
	}
	defer rootDB.Close()

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

	for _, migration := range migrations {
		if _, err := db.Exec(migration); err != nil {
			return fmt.Errorf("migration failed: %w", err)
		}
	}

	return nil
}

func (tc *TestContext) CreateTestUser(t *testing.T, email, password, role string) uint64 {
	hashedPassword, err := tc.Container.PasswordService.Hash(context.Background(), password)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}

	result, err := tc.DB.Exec(
		"INSERT INTO users (email, password_hash, first_name, last_name, role) VALUES (?, ?, ?, ?, ?)",
		email, hashedPassword, "Test", "User", role,
	)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	userID, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("Failed to get user ID: %v", err)
	}

	return uint64(userID)
}
