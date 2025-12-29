package security

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

const (
	// PolicyVersion indicates the current version of the password policy
	PolicyVersion = "v1"
)

type PasswordService struct {
	cost                 int
	minLength            int
	requireUppercase     bool
	requireLowercase     bool
	requireDigit         bool
	requireSpecialChar   bool
	maxConsecutiveChars  int
	commonPasswordsCache map[string]bool
	version              string
}

func NewPasswordService(cost int) *PasswordService {
	return &PasswordService{
		cost:                cost,
		minLength:           8,
		requireUppercase:    true,
		requireLowercase:    true,
		requireDigit:        true,
		requireSpecialChar:  true,
		maxConsecutiveChars: 3,
		commonPasswordsCache: map[string]bool{
			"password": true, "12345678": true, "qwerty": true,
			"admin": true, "letmein": true, "welcome": true,
		},
		version: PolicyVersion,
	}
}

type PasswordValidationError struct {
	Errors []string
}

func (e *PasswordValidationError) Error() string {
	return strings.Join(e.Errors, "; ")
}

func (p *PasswordService) Validate(password string) error {
	var errors []string

	if len(password) < p.minLength {
		errors = append(errors, fmt.Sprintf("password must be at least %d characters", p.minLength))
	}

	if len(password) > 128 {
		errors = append(errors, "password must not exceed 128 characters")
	}

	if p.requireUppercase && !regexp.MustCompile(`[A-Z]`).MatchString(password) {
		errors = append(errors, "password must contain at least one uppercase letter")
	}

	if p.requireLowercase && !regexp.MustCompile(`[a-z]`).MatchString(password) {
		errors = append(errors, "password must contain at least one lowercase letter")
	}

	if p.requireDigit && !regexp.MustCompile(`[0-9]`).MatchString(password) {
		errors = append(errors, "password must contain at least one digit")
	}

	if p.requireSpecialChar && !regexp.MustCompile(`[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]`).MatchString(password) {
		errors = append(errors, "password must contain at least one special character")
	}

	if p.hasConsecutiveChars(password, p.maxConsecutiveChars) {
		errors = append(errors, fmt.Sprintf("password must not contain more than %d consecutive identical characters", p.maxConsecutiveChars))
	}

	lowerPassword := strings.ToLower(password)
	if p.commonPasswordsCache[lowerPassword] {
		errors = append(errors, "password is too common")
	}

	if len(errors) > 0 {
		return &PasswordValidationError{Errors: errors}
	}

	return nil
}

func (p *PasswordService) hasConsecutiveChars(password string, max int) bool {
	if len(password) < max {
		return false
	}

	count := 1
	for i := 1; i < len(password); i++ {
		if password[i] == password[i-1] {
			count++
			if count >= max {
				return true
			}
		} else {
			count = 1
		}
	}
	return false
}

func (p *PasswordService) Hash(ctx context.Context, password string) (string, error) {
	if err := p.Validate(password); err != nil {
		return "", err
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), p.cost)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}
	return string(hash), nil
}

func (p *PasswordService) Compare(ctx context.Context, hashedPassword, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}
