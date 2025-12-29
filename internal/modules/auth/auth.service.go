package auth

import (
	"context"
	"database/sql"
	"time"

	"github.com/waqasmani/go-boilerplate/internal/config"
	"github.com/waqasmani/go-boilerplate/internal/infrastructure/observability"
	"github.com/waqasmani/go-boilerplate/internal/infrastructure/security"
	"github.com/waqasmani/go-boilerplate/internal/infrastructure/sqlc"
	apperrors "github.com/waqasmani/go-boilerplate/internal/shared/errors"
	"github.com/waqasmani/go-boilerplate/internal/shared/validator"
)

type Service struct {
	queries         *sqlc.Queries
	repo            *sqlc.Repository
	jwtService      *security.JWTService
	passwordService *security.PasswordService
	validator       *validator.Validator
	auditLogger     *observability.AuditLogger
	metrics         *observability.Metrics
	cfg             *config.Config
	logger          *observability.Logger
}

type LoginContext struct {
	ClientIP  string
	UserAgent string
}

func NewService(
	queries *sqlc.Queries,
	repo *sqlc.Repository,
	jwtService *security.JWTService,
	passwordService *security.PasswordService,
	validator *validator.Validator,
	auditLogger *observability.AuditLogger,
	metrics *observability.Metrics,
	cfg *config.Config,
	logger *observability.Logger,
) *Service {
	return &Service{
		queries:         queries,
		repo:            repo,
		jwtService:      jwtService,
		passwordService: passwordService,
		validator:       validator,
		auditLogger:     auditLogger,
		metrics:         metrics,
		cfg:             cfg,
		logger:          logger,
	}
}

func (s *Service) Register(ctx context.Context, email, password, firstName, lastName string) (*sqlc.User, error) {
	existingUser, err := s.queries.GetUserByEmail(ctx, email)
	if err == nil && existingUser.ID > 0 {
		return nil, apperrors.New(apperrors.ErrCodeConflict, "Email already registered")
	}

	if err != nil && err != sql.ErrNoRows {
		return nil, apperrors.Wrap(err, apperrors.ErrCodeInternal, "Failed to check existing user")
	}

	passwordHash, err := s.passwordService.Hash(ctx, password)
	if err != nil {
		return nil, apperrors.Wrap(err, apperrors.ErrCodeValidation, "Invalid password")
	}

	result, err := s.queries.CreateUser(ctx, sqlc.CreateUserParams{
		Email:        email,
		PasswordHash: passwordHash,
		FirstName:    firstName,
		LastName:     lastName,
		Role:         "user",
		IsActive:     true,
	})
	if err != nil {
		return nil, apperrors.Wrap(err, apperrors.ErrCodeInternal, "Failed to create user")
	}

	userID, err := result.LastInsertId()
	if err != nil {
		return nil, apperrors.Wrap(err, apperrors.ErrCodeInternal, "Failed to get user ID")
	}

	user, err := s.queries.GetUserByID(ctx, uint64(userID))
	if err != nil {
		return nil, apperrors.Wrap(err, apperrors.ErrCodeInternal, "Failed to fetch created user")
	}

	s.auditLogger.LogSecurityEvent(ctx, observability.SecurityEvent{
		Type:     "auth",
		Action:   "register",
		UserID:   user.ID,
		Resource: "user",
		Success:  true,
	})

	s.metrics.AuthenticationAttempts.WithLabelValues("register").Inc()
	return &user, nil
}

func (s *Service) Login(ctx context.Context, email, password string, loginCtx LoginContext) (string, string, string, *sqlc.User, error) {
	s.metrics.AuthenticationAttempts.WithLabelValues("login").Inc()

	// Check if account is locked
	lockoutInfo, err := s.checkAccountLockout(ctx, email)
	if err != nil {
		return "", "", "", nil, err
	}

	if lockoutInfo.IsLocked {
		s.metrics.AuthenticationFailures.WithLabelValues("login", "account_locked").Inc()
		return "", "", "", nil, apperrors.WithDetails(
			apperrors.ErrCodeForbidden,
			"Account temporarily locked due to multiple failed login attempts",
			map[string]interface{}{
				"retry_after_seconds": lockoutInfo.RetryAfterSeconds,
				"attempts_remaining":  0,
			},
		)
	}

	user, err := s.queries.GetUserByEmail(ctx, email)
	const dummyHash = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgNI1S8p/8A8z7E83C5U6uL6CjX6"
	if err != nil {
		if err == sql.ErrNoRows {
			_ = s.passwordService.Compare(ctx, dummyHash, password)
			return "", "", "", nil, apperrors.ErrInvalidCredentials
		}
		return "", "", "", nil, apperrors.Wrap(err, apperrors.ErrCodeInternal, "Authentication failed")
	}

	if err := s.passwordService.Compare(ctx, user.PasswordHash, password); err != nil {
		s.recordFailedLogin(ctx, user.ID, email, loginCtx.ClientIP)
		s.auditLogger.LogSecurityEvent(ctx, observability.SecurityEvent{
			Type:      "auth",
			Action:    "login_failed",
			UserID:    user.ID,
			Resource:  "user",
			Success:   false,
			IPAddress: loginCtx.ClientIP,
		})
		s.metrics.AuthenticationFailures.WithLabelValues("login", "invalid_credentials").Inc()

		// Check if this failure causes lockout
		updatedLockoutInfo, _ := s.checkAccountLockout(ctx, email)
		if updatedLockoutInfo.IsLocked {
			return "", "", "", nil, apperrors.WithDetails(
				apperrors.ErrCodeForbidden,
				"Account locked due to multiple failed login attempts",
				map[string]interface{}{
					"retry_after_seconds": updatedLockoutInfo.RetryAfterSeconds,
				},
			)
		}
		return "", "", "", nil, apperrors.WithDetails(
			apperrors.ErrCodeUnauthorized,
			"Invalid credentials",
			map[string]interface{}{
				"attempts_remaining": s.cfg.Security.MaxLoginAttempts - updatedLockoutInfo.FailedAttempts,
			},
		)
	}

	// Clear failed attempts on successful login
	s.queries.ClearFailedLoginAttempts(ctx, email)

	accessToken, err := s.jwtService.GenerateAccessToken(ctx, user.ID, user.Email, user.Role)
	if err != nil {
		return "", "", "", nil, apperrors.Wrap(err, apperrors.ErrCodeInternal, "Failed to generate access token")
	}

	rawRefreshToken, refreshTokenHash, err := s.jwtService.GenerateStateToken(ctx)
	if err != nil {
		return "", "", "", nil, apperrors.Wrap(err, apperrors.ErrCodeInternal, "Failed to generate refresh token")
	}

	rawCsrfToken, csrfTokenHash, err := s.jwtService.GenerateStateToken(ctx)
	if err != nil {
		return "", "", "", nil, apperrors.Wrap(err, apperrors.ErrCodeInternal, "Failed to generate CSRF token")
	}

	err = s.queries.CreateRefreshToken(ctx, sqlc.CreateRefreshTokenParams{
		UserID:    user.ID,
		TokenHash: refreshTokenHash,
		CsrfHash:  csrfTokenHash,
		ClientIp: sql.NullString{
			String: loginCtx.ClientIP,
			Valid:  s.cfg.Security.SessionBindingEnabled && loginCtx.ClientIP != "",
		},
		UserAgent: sql.NullString{
			String: loginCtx.UserAgent,
			Valid:  s.cfg.Security.SessionBindingEnabled && loginCtx.UserAgent != "",
		},
		ExpiresAt: time.Now().Add(s.jwtService.GetRefreshExpiry()),
	})
	if err != nil {
		return "", "", "", nil, apperrors.Wrap(err, apperrors.ErrCodeInternal, "Failed to store refresh token")
	}

	s.auditLogger.LogSecurityEvent(ctx, observability.SecurityEvent{
		Type:      "auth",
		Action:    "login",
		UserID:    user.ID,
		Resource:  "user",
		Success:   true,
		IPAddress: loginCtx.ClientIP,
	})

	return accessToken, rawRefreshToken, rawCsrfToken, &user, nil
}

func (s *Service) RefreshToken(ctx context.Context, refreshToken, csrfToken string, loginCtx LoginContext) (string, string, string, *sqlc.User, error) {
	s.metrics.TokenRefreshes.WithLabelValues("attempted").Inc()

	refreshTokenHash := s.jwtService.HashToken(refreshToken)
	csrfTokenHash := s.jwtService.HashToken(csrfToken)

	newRawRefreshToken, newRefreshTokenHash, err := s.jwtService.GenerateStateToken(ctx)
	if err != nil {
		return "", "", "", nil, apperrors.Wrap(err, apperrors.ErrCodeInternal, "Failed to generate new refresh token")
	}

	newRawCsrfToken, newCsrfTokenHash, err := s.jwtService.GenerateStateToken(ctx)
	if err != nil {
		return "", "", "", nil, apperrors.Wrap(err, apperrors.ErrCodeInternal, "Failed to generate new CSRF token")
	}

	var user sqlc.User
	// Track compromise to execute revocation outside the transaction
	var compromisedUserID uint64

	err = s.repo.WithTransaction(ctx, func(q *sqlc.Queries) error {
		var err error
		token, err := q.ValidateRefreshToken(ctx, sqlc.ValidateRefreshTokenParams{
			TokenHash: refreshTokenHash,
			CsrfHash:  csrfTokenHash,
		})
		if err != nil {
			return apperrors.New(apperrors.ErrCodeUnauthorized, "Invalid or expired refresh token")
		}

		// NEW: Check if token was already revoked - indicates reuse attack
		if token.RevokedAt.Valid {
			s.logger.Error(ctx, "Revoked token reuse detected - potential compromise",
				s.logger.Field("user_id", token.UserID),
				s.logger.Field("revoked_at", token.RevokedAt.Time),
			)

			// Immediately revoke ALL tokens for this user (compromised account)
			compromisedUserID = token.UserID

			return apperrors.New(apperrors.ErrCodeUnauthorized,
				"Security violation detected. All sessions have been terminated. Please login again.")
		}

		s.metrics.CSRFValidations.WithLabelValues("success").Inc()

		// Validate session binding if enabled
		if s.cfg.Security.SessionBindingEnabled {
			// Only enforce binding if the token has binding data (grace period for old tokens)
			if token.ClientIp.Valid || token.UserAgent.Valid {
				bindingMismatch := false
				var mismatchReason string
				if token.ClientIp.Valid && token.ClientIp.String != loginCtx.ClientIP {
					bindingMismatch = true
					mismatchReason = "client_ip_mismatch"
				}
				if token.UserAgent.Valid && token.UserAgent.String != loginCtx.UserAgent {
					bindingMismatch = true
					if mismatchReason != "" {
						mismatchReason = "ip_and_useragent_mismatch"
					} else {
						mismatchReason = "user_agent_mismatch"
					}
				}
				if bindingMismatch {
					// Log security event
					s.auditLogger.LogSecurityEvent(ctx, observability.SecurityEvent{
						Type:      "auth",
						Action:    "refresh_token_binding_failed",
						UserID:    token.UserID,
						Resource:  "session",
						Success:   false,
						IPAddress: loginCtx.ClientIP,
					})
					s.metrics.AuthenticationFailures.WithLabelValues("refresh", mismatchReason).Inc()
					// Potential session hijacking: revoke all tokens for this user for safety
					compromisedUserID = token.UserID
					return apperrors.New(apperrors.ErrCodeUnauthorized, "Session validation failed. Please login again")
				}
			}
		}

		if err := q.RevokeRefreshToken(ctx, refreshTokenHash); err != nil {
			return apperrors.Wrap(err, apperrors.ErrCodeInternal, "Failed to revoke old token")
		}

		user, err = q.GetUserByID(ctx, token.UserID)
		if err != nil {
			return apperrors.Wrap(err, apperrors.ErrCodeInternal, "Failed to fetch user")
		}

		if err := q.CreateRefreshToken(ctx, sqlc.CreateRefreshTokenParams{
			UserID:    user.ID,
			TokenHash: newRefreshTokenHash,
			CsrfHash:  newCsrfTokenHash,
			ClientIp: sql.NullString{
				String: loginCtx.ClientIP,
				Valid:  s.cfg.Security.SessionBindingEnabled && loginCtx.ClientIP != "",
			},
			UserAgent: sql.NullString{
				String: loginCtx.UserAgent,
				Valid:  s.cfg.Security.SessionBindingEnabled && loginCtx.UserAgent != "",
			},
			ExpiresAt: time.Now().Add(s.jwtService.GetRefreshExpiry()),
		}); err != nil {
			return apperrors.Wrap(err, apperrors.ErrCodeInternal, "Failed to store new refresh token")
		}

		return nil
	})
	if compromisedUserID > 0 {
		_ = s.queries.RevokeAllUserRefreshTokens(ctx, compromisedUserID)
	}
	if err != nil {
		s.metrics.TokenRefreshes.WithLabelValues("failed").Inc()
		return "", "", "", nil, err
	}

	accessToken, err := s.jwtService.GenerateAccessToken(ctx, user.ID, user.Email, user.Role)
	if err != nil {
		return "", "", "", nil, apperrors.Wrap(err, apperrors.ErrCodeInternal, "Failed to generate access token")
	}

	s.metrics.TokenRefreshes.WithLabelValues("success").Inc()
	return accessToken, newRawRefreshToken, newRawCsrfToken, &user, nil
}

func (s *Service) Logout(ctx context.Context, refreshToken string) error {
	refreshTokenHash := s.jwtService.HashToken(refreshToken)
	return s.queries.RevokeRefreshToken(ctx, refreshTokenHash)
}

type LockoutInfo struct {
	IsLocked          bool
	FailedAttempts    int
	RetryAfterSeconds int
	LockoutUntil      time.Time
}

func (s *Service) checkAccountLockout(ctx context.Context, email string) (LockoutInfo, error) {
	window := int(s.cfg.Security.LoginLockoutDuration.Minutes())
	attempts, err := s.queries.GetFailedLoginAttempts(ctx, sqlc.GetFailedLoginAttemptsParams{
		Email:   email,
		DATESUB: int32(window),
	})
	if err != nil && err != sql.ErrNoRows {
		return LockoutInfo{}, apperrors.Wrap(err, apperrors.ErrCodeInternal, "Failed to check login attempts")
	}

	failedCount := len(attempts)
	if failedCount < s.cfg.Security.MaxLoginAttempts {
		return LockoutInfo{
			IsLocked:       false,
			FailedAttempts: failedCount,
		}, nil
	}

	// Calculate exponential backoff using bitwise shifting
	lockoutMultiplier := 0
	if diff := failedCount - s.cfg.Security.MaxLoginAttempts; diff >= 0 {
		// 1 << 6 = 64, which is the first power of 2 exceeding the cap of 60.
		// We cap the shift at 6 to prevent potential overflow on very high failedCounts.
		shift := diff
		if shift > 6 {
			shift = 6
		}
		lockoutMultiplier = min(1<<shift, 60)
	}

	baseLockoutSeconds := int(s.cfg.Security.LoginLockoutDuration.Seconds())
	lockoutDuration := time.Duration(baseLockoutSeconds*lockoutMultiplier) * time.Second

	if len(attempts) > 0 {
		lastAttempt := attempts[0].AttemptTime
		lockoutUntil := lastAttempt.Add(lockoutDuration)
		if time.Now().Before(lockoutUntil) {
			retryAfter := int(time.Until(lockoutUntil).Seconds())
			return LockoutInfo{
				IsLocked:          true,
				FailedAttempts:    failedCount,
				RetryAfterSeconds: retryAfter,
				LockoutUntil:      lockoutUntil,
			}, nil
		}
	}

	return LockoutInfo{
		IsLocked:       false,
		FailedAttempts: failedCount,
	}, nil
}

func (s *Service) recordFailedLogin(ctx context.Context, userID uint64, email, ipAddress string) {
	var nullableUserID sql.NullInt64
	if userID > 0 {
		nullableUserID = sql.NullInt64{Int64: int64(userID), Valid: true}
	}

	err := s.queries.RecordFailedLoginAttempt(ctx, sqlc.RecordFailedLoginAttemptParams{
		UserID:    nullableUserID,
		Email:     email,
		IpAddress: ipAddress,
	})
	if err != nil {
		// Log error but don't fail the login flow
		s.auditLogger.LogSecurityEvent(ctx, observability.SecurityEvent{
			Type:      "auth",
			Action:    "failed_login_recording_failed",
			UserID:    userID,
			Resource:  "login",
			Success:   false,
			IPAddress: ipAddress,
		})
	}
}

// Background job to cleanup old failed login attempts
func (s *Service) CleanupOldFailedLogins(ctx context.Context) error {
	_, err := s.queries.CleanupOldFailedLoginAttempts(ctx, 1000)
	if err != nil {
		return apperrors.Wrap(err, apperrors.ErrCodeInternal, "Failed to cleanup old failed login attempts")
	}
	return nil
}
