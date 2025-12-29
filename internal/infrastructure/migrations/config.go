package migrations

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "github.com/go-sql-driver/mysql"
	"github.com/pressly/goose/v3"
)

// MigrationConfig holds configuration for database migrations
type MigrationConfig struct {
	Dir        string
	DBDriver   string
	DBSource   string
	DirAbsPath string
}

// NewMigrationConfig creates a new MigrationConfig from environment variables
func NewMigrationConfig() (*MigrationConfig, error) {
	dir := getEnv("MIGRATION_DIR", "./migrations")
	dbDriver := getEnv("DB_DRIVER", "mysql")

	// Construct DB source string from environment variables
	dbHost := getEnv("DB_HOST", "localhost")
	dbPort := getEnv("DB_PORT", "3306")
	dbUser := getEnv("DB_USER", "auth_user")
	dbPass := getEnv("DB_PASSWORD", "")
	dbName := getEnv("DB_NAME", "auth_db")

	dbSource := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?parseTime=true",
		dbUser, dbPass, dbHost, dbPort, dbName)

	absPath, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path for migration directory: %w", err)
	}

	return &MigrationConfig{
		Dir:        dir,
		DBDriver:   dbDriver,
		DBSource:   dbSource,
		DirAbsPath: absPath,
	}, nil
}

// InitDB initializes and returns a database connection for migrations
func (cfg *MigrationConfig) InitDB() (*sql.DB, error) {
	db, err := sql.Open(cfg.DBDriver, cfg.DBSource)
	if err != nil {
		return nil, fmt.Errorf("failed to open database connection: %w", err)
	}

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return db, nil
}

// RunMigrations applies all pending migrations
func (cfg *MigrationConfig) RunMigrations() error {
	db, err := cfg.InitDB()
	if err != nil {
		return err
	}
	defer db.Close()

	return goose.Up(db, cfg.Dir)
}

// GetMigrationStatus returns the status of all migrations
func (cfg *MigrationConfig) GetMigrationStatus() error {
	db, err := cfg.InitDB()
	if err != nil {
		return err
	}
	defer db.Close()

	return goose.Status(db, cfg.Dir)
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
