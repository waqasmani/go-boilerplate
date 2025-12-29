package security

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/waqasmani/go-boilerplate/internal/config"
	"github.com/waqasmani/go-boilerplate/internal/shared/errors"
)

type JWTService struct {
	accessSecret  []byte
	accessExpiry  time.Duration
	refreshExpiry time.Duration
	issuer        string
	audience      string
}

type Claims struct {
	UserID uint64 `json:"user_id"`
	Email  string `json:"email"`
	Role   string `json:"role,omitempty"`
	jwt.RegisteredClaims
}

func NewJWTService(cfg *config.JWTConfig) *JWTService {
	return &JWTService{
		accessSecret:  []byte(cfg.AccessSecret),
		accessExpiry:  cfg.AccessExpiry,
		refreshExpiry: cfg.RefreshExpiry,
		issuer:        "go-boilerplate",
		audience:      "go-boilerplate-users",
	}
}

func (j *JWTService) GenerateAccessToken(ctx context.Context, userID uint64, email, role string) (string, error) {
	jti, _ := uuid.NewRandom()
	claims := &Claims{
		UserID: userID,
		Email:  email,
		Role:   role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(j.accessExpiry)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			ID:        jti.String(),
			Issuer:    j.issuer,
			Audience:  jwt.ClaimStrings{j.audience},
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(j.accessSecret)
}

func (j *JWTService) ValidateAccessToken(ctx context.Context, tokenString string) (*Claims, error) {
	return j.validateToken(tokenString, j.accessSecret)
}

// GenerateStateToken generates a cryptographically secure random token
// Returns two tokens:
// 1. rawToken - the plain token for browser usage.
// 2. hashedToken - SHA256 hashed version for database storage.
// use to generate refresh_token or csrf_token
func (j *JWTService) GenerateStateToken(ctx context.Context) (string, string, error) {
	// Generate 32 random bytes (256 bits) for a secure token
	randomBytes := make([]byte, 32)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Convert to hex string for the raw token (64 characters)
	rawToken := hex.EncodeToString(randomBytes)

	// Hash the token for database storage using existing HashToken method
	hashedToken := j.HashToken(rawToken)
	return rawToken, hashedToken, nil
}

func (j *JWTService) validateToken(tokenString string, secret []byte) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})
	if err != nil {
		return nil, j.handleError(err)
	}

	if !token.Valid {
		return nil, errors.New(errors.ErrCodeInvalidToken, "Authentication failed")
	}

	claims, ok := token.Claims.(*Claims)
	if !ok {
		return nil, errors.New(errors.ErrCodeInvalidToken, "Invalid token claims")
	}

	if claims.Issuer != j.issuer {
		return nil, errors.New(errors.ErrCodeInvalidToken, "Invalid token issuer")
	}

	validAudience := slices.Contains(claims.Audience, j.audience)
	if !validAudience {
		return nil, errors.New(errors.ErrCodeInvalidToken, "Invalid token audience")
	}

	return claims, nil
}

func (j *JWTService) handleError(err error) error {
	if err.Error() == "token is expired" || err.Error() == "Token is expired" {
		return errors.New(errors.ErrCodeExpiredToken, "Token expired")
	}
	if strings.Contains(err.Error(), "signature is invalid") {
		return errors.New(errors.ErrCodeInvalidToken, "Invalid token signature")
	}
	return errors.New(errors.ErrCodeInvalidToken, "Authentication failed")
}

func (j *JWTService) GetRefreshExpiry() time.Duration {
	return j.refreshExpiry
}

func (j *JWTService) GetAccessExpiry() time.Duration {
	return j.accessExpiry
}

func (j *JWTService) HashToken(token string) string {
	hasher := sha256.New()
	hasher.Write([]byte(token))
	return hex.EncodeToString(hasher.Sum(nil))
}
