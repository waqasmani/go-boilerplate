package main

import (
	"context"
	"log"

	"github.com/waqasmani/go-boilerplate/cmd/api/docs"
	"github.com/waqasmani/go-boilerplate/internal/app"
	"github.com/waqasmani/go-boilerplate/internal/config"
	"github.com/waqasmani/go-boilerplate/internal/infrastructure/database"
	"github.com/waqasmani/go-boilerplate/internal/infrastructure/observability"
)

// @title           Go Boilerplate API
// @version         1.0
// @description     This is an attendance and employee management server.

// @securityDefinitions.apikey Bearer
// @in header
// @name Authorization
// @description Type "Bearer <your_token>" (include the word Bearer and a space)

// @securityDefinitions.apikey CsrfToken
// @in header
// @name X-CSRF-TOKEN
// @description Enter your CSRF token
func main() {
	// Load configuration first and validate before any resource initialization
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Configuration loading failed: %v", err)
	}

	// Validate configuration before initializing any resources
	if err := cfg.Validate(); err != nil {
		log.Fatalf("Configuration validation failed: %v", err)
	}

	// Programmatically set swagger info
	docs.SwaggerInfo.BasePath = "/api/v1"

	// Initialize logger after config validation
	logger, err := observability.NewLogger(cfg.Logging.Level, cfg.Logging.Encoding)
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}
	defer func() {
		if err := logger.Sync(); err != nil {
			log.Printf("Failed to sync logger: %v", err)
		}
	}()
	metrics := observability.NewMetrics()
	// Initialize database after config validation
	db, err := database.NewMariaDB(context.Background(), &cfg.Database, metrics, logger)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	container := app.NewContainer(cfg, db.DB, logger)
	server := app.NewServer(container)

	if err := server.Start(); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
