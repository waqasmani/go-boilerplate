package security

import (
	"context"
	stderrors "errors"
	"fmt"
	"slices"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/waqasmani/go-boilerplate/internal/config"
	"github.com/waqasmani/go-boilerplate/internal/shared/errors"
)

type JWTService struct {
	accessSecret  []byte
	refreshSecret []byte
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
		refreshSecret: []byte(cfg.RefreshSecret),
		accessExpiry:  cfg.AccessExpiry,
		refreshExpiry: cfg.RefreshExpiry,
		issuer:        "api-boilerplate",
		audience:      "api-boilerplate-users",
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

func (j *JWTService) GenerateRefreshToken(ctx context.Context, userID uint64, userEmail string) (string, error) {
	jti, _ := uuid.NewRandom()
	claims := &Claims{
		UserID: userID,
		Email:  userEmail,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(j.refreshExpiry)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			ID:        jti.String(),
			Issuer:    j.issuer,
			Audience:  jwt.ClaimStrings{j.audience},
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(j.refreshSecret)
}

func (j *JWTService) ValidateAccessToken(ctx context.Context, tokenString string) (*Claims, error) {
	return j.validateToken(tokenString, j.accessSecret)
}

func (j *JWTService) ValidateRefreshToken(ctx context.Context, tokenString string) (*Claims, error) {
	return j.validateToken(tokenString, j.refreshSecret)
}

func (j *JWTService) validateToken(tokenString string, secret []byte) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return secret, nil
	})
	if err != nil {
		if stderrors.Is(err, jwt.ErrTokenExpired) {
			return nil, errors.New(errors.ErrCodeExpiredToken, "Token expired")
		}
		return nil, errors.New(errors.ErrCodeInvalidToken, "Authentication failed")
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

func (j *JWTService) GetRefreshExpiry() time.Duration {
	return j.refreshExpiry
}

func (j *JWTService) GetAccessExpiry() time.Duration {
	return j.accessExpiry
}
