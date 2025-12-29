package security

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/waqasmani/go-boilerplate/internal/config"
)

func TestPasswordService(t *testing.T) {
	svc := NewPasswordService(4) // Min cost for speed
	ctx := context.Background()

	// Use a password that meets all requirements
	validPassword := "SecurePass123!"
	hash, err := svc.Hash(ctx, validPassword)
	assert.NoError(t, err)
	assert.NotEmpty(t, hash)

	err = svc.Compare(ctx, hash, validPassword)
	assert.NoError(t, err)

	err = svc.Compare(ctx, hash, "wrongpassword")
	assert.Error(t, err)
}

func TestJWTService(t *testing.T) {
	cfg := &config.JWTConfig{
		AccessSecret:  "X7sP3kQbN9rT2yV5zX8cW6mJhGfEaBdC0123456789ab",
		AccessExpiry:  15 * time.Minute,
		RefreshExpiry: 7 * 24 * time.Hour,
	}
	svc := NewJWTService(cfg)
	ctx := context.Background()
	userID := uint64(1)
	email := "test@example.com"
	role := "user"

	t.Run("Generate and validate access token", func(t *testing.T) {
		token, err := svc.GenerateAccessToken(ctx, userID, email, role)
		assert.NoError(t, err)
		assert.NotEmpty(t, token)

		claims, err := svc.ValidateAccessToken(ctx, token)
		assert.NoError(t, err)
		assert.Equal(t, userID, claims.UserID)
		assert.Equal(t, email, claims.Email)
		assert.Equal(t, role, claims.Role)
	})

	t.Run("Validate invalid token format", func(t *testing.T) {
		_, err := svc.ValidateAccessToken(ctx, "invalid.token.format")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Authentication failed")
	})

	t.Run("Validate expired token", func(t *testing.T) {
		// Create an expired token manually
		expiredClaims := &Claims{
			UserID: userID,
			Email:  email,
			Role:   role,
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Minute)),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				NotBefore: jwt.NewNumericDate(time.Now()),
				ID:        "test-id",
				Issuer:    svc.issuer,
				Audience:  jwt.ClaimStrings{svc.audience},
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, expiredClaims)
		expiredToken, err := token.SignedString(svc.accessSecret)
		assert.NoError(t, err)

		_, err = svc.ValidateAccessToken(ctx, expiredToken)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "INVALID_TOKEN: Authentication failed")
	})

	t.Run("Validate token with invalid signature", func(t *testing.T) {
		validToken, err := svc.GenerateAccessToken(ctx, userID, email, role)
		assert.NoError(t, err)

		// Split and tamper with the signature
		parts := strings.Split(validToken, ".")
		assert.Len(t, parts, 3, "JWT should have 3 parts")
		parts[2] = "invalidsignature"
		invalidToken := strings.Join(parts, ".")

		_, err = svc.ValidateAccessToken(ctx, invalidToken)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "INVALID_TOKEN: Invalid token signature")
	})

	t.Run("Validate token with invalid issuer", func(t *testing.T) {
		// Create a token with invalid issuer
		invalidClaims := &Claims{
			UserID: userID,
			Email:  email,
			Role:   role,
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				NotBefore: jwt.NewNumericDate(time.Now()),
				ID:        "test-id",
				Issuer:    "invalid-issuer", // Intentionally wrong issuer
				Audience:  jwt.ClaimStrings{svc.audience},
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, invalidClaims)
		invalidToken, err := token.SignedString(svc.accessSecret)
		assert.NoError(t, err)

		_, err = svc.ValidateAccessToken(ctx, invalidToken)
		assert.Error(t, err)
		// Updated to match actual error message
		assert.Contains(t, err.Error(), "Invalid token issuer")
	})

	t.Run("Validate token with invalid audience", func(t *testing.T) {
		// Create a token with invalid audience
		invalidClaims := &Claims{
			UserID: userID,
			Email:  email,
			Role:   role,
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				NotBefore: jwt.NewNumericDate(time.Now()),
				ID:        "test-id",
				Issuer:    svc.issuer,
				Audience:  jwt.ClaimStrings{"invalid-audience"}, // Intentionally wrong audience
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, invalidClaims)
		invalidToken, err := token.SignedString(svc.accessSecret)
		assert.NoError(t, err)

		_, err = svc.ValidateAccessToken(ctx, invalidToken)
		assert.Error(t, err)
		// Updated to match actual error message
		assert.Contains(t, err.Error(), "Invalid token audience")
	})

	t.Run("Generate state token", func(t *testing.T) {
		rawToken, hashedToken, err := svc.GenerateStateToken(ctx)
		assert.NoError(t, err)
		assert.NotEmpty(t, rawToken)
		assert.NotEmpty(t, hashedToken)
		assert.Equal(t, 64, len(rawToken))    // Hex-encoded 32 bytes
		assert.Equal(t, 64, len(hashedToken)) // SHA256 hex output
		assert.NotEqual(t, rawToken, hashedToken)

		// Verify that hashing the raw token matches the hashed token
		assert.Equal(t, hashedToken, svc.HashToken(rawToken))
	})

	t.Run("Hash token consistency", func(t *testing.T) {
		token := "test_token"
		hash1 := svc.HashToken(token)
		hash2 := svc.HashToken(token)
		assert.Equal(t, hash1, hash2)

		// Different tokens should produce different hashes
		differentHash := svc.HashToken("different_token")
		assert.NotEqual(t, hash1, differentHash)
	})
}

func TestJWT_ExpiredToken(t *testing.T) {
	cfg := &config.JWTConfig{
		AccessSecret: "access_secret_key_must_be_32_bytes_long",
		AccessExpiry: -time.Minute,
	}
	svc := NewJWTService(cfg)
	claims := &Claims{
		UserID: 1,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Minute)),
		},
	}
	tokenObj := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, _ := tokenObj.SignedString([]byte(cfg.AccessSecret))
	_, err := svc.ValidateAccessToken(context.Background(), tokenStr)
	assert.Error(t, err)
	assert.NotNil(t, err)
}
