package security

import (
	"context"
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
		AccessSecret:  "access_secret_key_must_be_32_bytes_long",
		RefreshSecret: "refresh_secret_key_must_be_32_bytes_long",
		AccessExpiry:  time.Minute * 15,
		RefreshExpiry: time.Hour * 24,
	}
	svc := NewJWTService(cfg)
	ctx := context.Background()

	// 1. Generate and Validate Access Token
	token, err := svc.GenerateAccessToken(ctx, 1, "test@example.com", "admin")
	assert.NoError(t, err)
	claims, err := svc.ValidateAccessToken(ctx, token)
	assert.NoError(t, err)
	assert.Equal(t, uint64(1), claims.UserID)

	// 2. Generate and Validate Refresh Token
	rToken, err := svc.GenerateRefreshToken(ctx, 1, "test@example.com")
	assert.NoError(t, err)
	rClaims, err := svc.ValidateRefreshToken(ctx, rToken)
	assert.NoError(t, err)
	assert.Equal(t, uint64(1), rClaims.UserID)

	// 3. Cross Validation Failure (Access Token cannot be validated by Refresh Secret)
	_, err = svc.ValidateRefreshToken(ctx, token)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Authentication failed")

	// 4. Garbage Token
	_, err = svc.ValidateAccessToken(ctx, "invalid.token.string")
	assert.Error(t, err)
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