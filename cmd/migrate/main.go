package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/pressly/goose/v3"
	"github.com/waqasmani/go-boilerplate/internal/config"
	"github.com/waqasmani/go-boilerplate/internal/infrastructure/database"
	"github.com/waqasmani/go-boilerplate/internal/infrastructure/observability"
)

var (
	flags = flag.NewFlagSet("migrate", flag.ExitOnError)
	dir   = flags.String("dir", "./migrations", "directory with migration files")
)

func main() {
	flags.Usage = func() {
		fmt.Fprintf(flags.Output(), "Usage: %s [command] [arguments]\n\n", os.Args[0])
		fmt.Fprintf(flags.Output(), "Commands:\n")
		fmt.Fprintf(flags.Output(), "  create <name> [sql|go]   Create a new migration file\n")
		fmt.Fprintf(flags.Output(), "  up                      Apply all migrations\n")
		fmt.Fprintf(flags.Output(), "  up-by-one               Apply one migration\n")
		fmt.Fprintf(flags.Output(), "  down                    Roll back the last migration\n")
		fmt.Fprintf(flags.Output(), "  down-to <version>       Roll back migrations to specific version\n")
		fmt.Fprintf(flags.Output(), "  redo                    Reapply the last migration\n")
		fmt.Fprintf(flags.Output(), "  reset                   Roll back all migrations\n")
		fmt.Fprintf(flags.Output(), "  status                  Show migration status\n")
		fmt.Fprintf(flags.Output(), "  version                 Show applied version\n")
		fmt.Fprintf(flags.Output(), "\n")
		flags.PrintDefaults()
	}

	flags.Parse(os.Args[1:])
	args := flags.Args()

	if len(args) < 1 {
		flags.Usage()
		os.Exit(1)
	}

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Create database connection
	dbConfig := &cfg.Database
	if len(args) > 1 && args[1] == "test" {
		// Use test database for test migrations
		dbConfig.Name = "auth_test_db"
	}
	ctx := context.Background()
	metrics := observability.NewMetrics()
	logger, err := observability.NewLogger(cfg.Logging.Level, cfg.Logging.Encoding)
	if err != nil {
		fmt.Printf("Failed to create logger: %v\n", err)
		os.Exit(1)
	}
	defer logger.Sync()
	dbWrapper, err := database.NewMariaDB(ctx, dbConfig, metrics, logger)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer dbWrapper.Close()

	// Get the underlying *sql.DB from the wrapper
	db := dbWrapper.DB

	// Set dialect explicitly for MariaDB/MySQL
	goose.SetDialect("mysql")

	goose.SetTableName("goose_db_version")

	command := args[0]
	switch command {
	case "create":
		handleCreateCommand(db, args)
	case "up", "up-by-one", "down", "redo", "reset", "status", "version":
		handleMigrationCommand(db, command, args)
	case "down-to":
		handleDownToCommand(db, args)
	default:
		log.Fatalf("Unknown command: %s", command)
	}
}

func handleCreateCommand(db *sql.DB, args []string) {
	if len(args) < 2 {
		log.Fatal("create command requires a migration name")
	}

	name := args[1]
	mtype := "sql" // default to SQL migration
	if len(args) > 2 {
		mtype = args[2]
		if mtype != "sql" && mtype != "go" {
			log.Fatalf("Invalid migration type: %s. Must be 'sql' or 'go'", mtype)
		}
	}

	if err := goose.Create(db, *dir, name, mtype); err != nil {
		log.Fatalf("Failed to create migration: %v", err)
	}

	log.Printf("Created new %s migration: %s", mtype, name)
}

func handleMigrationCommand(db *sql.DB, command string, args []string) {
	var err error
	switch command {
	case "up":
		err = goose.Up(db, *dir)
	case "up-by-one":
		err = goose.UpByOne(db, *dir)
	case "down":
		err = goose.Down(db, *dir)
	case "redo":
		err = goose.Redo(db, *dir)
	case "reset":
		err = goose.Reset(db, *dir)
	case "status":
		err = goose.Status(db, *dir)
	case "version":
		err = goose.Version(db, *dir)
	}

	if err != nil {
		log.Fatalf("Migration failed: %v", err)
	}
}

func handleDownToCommand(db *sql.DB, args []string) {
	if len(args) < 2 {
		log.Fatal("down-to command requires a version number")
	}

	version, err := parseVersion(args[1])
	if err != nil {
		log.Fatalf("Invalid version: %v", err)
	}

	if err := goose.DownTo(db, *dir, version); err != nil {
		log.Fatalf("Failed to roll back to version %d: %v", version, err)
	}
}

func parseVersion(str string) (int64, error) {
	var version int64
	_, err := fmt.Sscanf(str, "%d", &version)
	return version, err
}
