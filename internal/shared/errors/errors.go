package errors

import (
	"errors"
	"fmt"
)

type ErrorCode string

const (
	ErrCodeInternal           ErrorCode = "INTERNAL_ERROR"
	ErrCodeNotFound           ErrorCode = "NOT_FOUND"
	ErrCodeBadRequest         ErrorCode = "BAD_REQUEST"
	ErrCodeUnauthorized       ErrorCode = "UNAUTHORIZED"
	ErrCodeForbidden          ErrorCode = "FORBIDDEN"
	ErrCodeConflict           ErrorCode = "CONFLICT"
	ErrCodeValidation         ErrorCode = "VALIDATION_ERROR"
	ErrCodeInvalidToken       ErrorCode = "INVALID_TOKEN"
	ErrCodeExpiredToken       ErrorCode = "EXPIRED_TOKEN"
	ErrCodeRevokedToken       ErrorCode = "REVOKED_TOKEN"
	ErrCodeInvalidCredentials ErrorCode = "INVALID_CREDENTIALS"
	ErrCodeTooManyRequests    ErrorCode = "TOO_MANY_REQUESTS"
	ErrCodeTimeout            ErrorCode = "TIMEOUT"
	ErrCodeDatabaseError      ErrorCode = "DATABASE_ERROR"
)

type AppError struct {
	Code       ErrorCode
	Message    string
	Details    any
	Err        error
	StatusCode int
	Retryable  bool
}

func (e *AppError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %s (%v)", e.Code, e.Message, e.Err)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func (e *AppError) Unwrap() error {
	return e.Err
}

func (e *AppError) Is(target error) bool {
	t, ok := target.(*AppError)
	if !ok {
		return false
	}
	return e.Code == t.Code
}

func New(code ErrorCode, message string) *AppError {
	return &AppError{
		Code:      code,
		Message:   message,
		Retryable: false,
	}
}

func Wrap(err error, code ErrorCode, message string) *AppError {
	return &AppError{
		Code:      code,
		Message:   message,
		Err:       err,
		Retryable: false,
	}
}

func WithDetails(code ErrorCode, message string, details interface{}) *AppError {
	return &AppError{
		Code:    code,
		Message: message,
		Details: details,
	}
}

func AsAppError(err error) (*AppError, bool) {
	var appErr *AppError
	if errors.As(err, &appErr) {
		return appErr, true
	}
	return nil, false
}

var (
	ErrInternal           = New(ErrCodeInternal, "Internal server error")
	ErrNotFound           = New(ErrCodeNotFound, "Resource not found")
	ErrBadRequest         = New(ErrCodeBadRequest, "Bad request")
	ErrUnauthorized       = New(ErrCodeUnauthorized, "Unauthorized")
	ErrForbidden          = New(ErrCodeForbidden, "Forbidden")
	ErrConflict           = New(ErrCodeConflict, "Resource already exists")
	ErrInvalidCredentials = New(ErrCodeInvalidCredentials, "Invalid credentials")
	ErrInvalidToken       = New(ErrCodeInvalidToken, "Invalid token")
	ErrExpiredToken       = New(ErrCodeExpiredToken, "Token expired")
	ErrRevokedToken       = New(ErrCodeRevokedToken, "Token revoked")
	ErrTimeout            = New(ErrCodeTimeout, "Request timeout")
)