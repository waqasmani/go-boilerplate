package auth

import (
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/require"
	"github.com/waqasmani/go-boilerplate/internal/config"
	"github.com/waqasmani/go-boilerplate/internal/infrastructure/observability"
	"github.com/waqasmani/go-boilerplate/internal/infrastructure/security"
	"github.com/waqasmani/go-boilerplate/internal/infrastructure/sqlc"
	"github.com/waqasmani/go-boilerplate/internal/shared/validator"
)

// authDependencies holds all the mocked and real dependencies
type authDependencies struct {
	mockDB      sqlmock.Sqlmock
	service     *Service
	cfg         *config.Config
	jwtService  *security.JWTService
	passService *security.PasswordService
}

// Helper to create a complete user row that matches sqlc expectations (9 columns)
func mockUserRow(id uint64, email, passwordHash, role string) *sqlmock.Rows {
	return sqlmock.NewRows([]string{
		"id", "email", "password_hash", "first_name", "last_name",
		"role", "is_active", "created_at", "updated_at",
	}).AddRow(
		id, email, passwordHash, "Test", "User",
		role, true, time.Now(), time.Now(),
	)
}

func setupAuthTest(t *testing.T) (*authDependencies, func()) {
	// 1. Setup SQL Mock
	db, mock, err := sqlmock.New()
	require.NoError(t, err)

	// 2. Real Config
	cfg := &config.Config{
		Server: config.ServerConfig{Env: "test"},
		JWT: config.JWTConfig{
			AccessSecret:  "test_secret_key_must_be_32_bytes_long",
			AccessExpiry:  15 * time.Minute,
			RefreshExpiry: 24 * time.Hour,
		},
		Security: config.SecurityConfig{
			BcryptCost:            4,
			MaxLoginAttempts:      3,
			LoginLockoutDuration:  15 * time.Minute,
			SessionBindingEnabled: true,
		},
	}

	// 3. Services
	jwtService := security.NewJWTService(&cfg.JWT)
	passService := security.NewPasswordService(cfg.Security.BcryptCost)
	validatorInstance := validator.New()

	// 4. Observability
	logger, _ := observability.NewLogger("info", "console")
	auditLogger := observability.NewAuditLogger(logger)
	metrics := observability.NewMetrics()

	// 5. Repositories
	queries := sqlc.New(db)
	repo := sqlc.NewRepository(db)

	service := NewService(
		queries,
		repo,
		jwtService,
		passService,
		validatorInstance,
		auditLogger,
		metrics,
		cfg,
		logger,
	)

	deps := &authDependencies{
		mockDB:      mock,
		service:     service,
		cfg:         cfg,
		jwtService:  jwtService,
		passService: passService,
	}

	return deps, func() { db.Close() }
}
