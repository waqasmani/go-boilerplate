package errors

import (
	"errors"
	"fmt"
)

type ErrorCode string
type ErrorType string

const (
	// Error Types
	ErrorTypeClient  ErrorType = "client_error"
	ErrorTypeServer  ErrorType = "server_error"
	ErrorTypeNetwork ErrorType = "network_error"

	// Error Codes
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
	ErrCodeServiceUnavailable ErrorCode = "SERVICE_UNAVAILABLE"
	ErrInvalidStatus          ErrorCode = "INVALID_STATUS"
)

type AppError struct {
	Code       ErrorCode
	Message    string
	Details    any
	Err        error
	ErrorType  ErrorType
	StatusCode int
	Retryable  bool
	Version    string
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

func (e *AppError) GetErrorType() ErrorType {
	return e.ErrorType
}

func determineErrorType(code ErrorCode) ErrorType {
	switch code {
	case ErrCodeBadRequest, ErrCodeUnauthorized, ErrCodeForbidden,
		ErrCodeNotFound, ErrCodeInvalidToken, ErrCodeExpiredToken,
		ErrCodeValidation, ErrCodeInvalidCredentials, ErrCodeTooManyRequests:
		return ErrorTypeClient
	case ErrCodeServiceUnavailable, ErrCodeTimeout:
		return ErrorTypeNetwork
	default:
		return ErrorTypeServer
	}
}

func New(code ErrorCode, message string) *AppError {
	return &AppError{
		Code:      code,
		Message:   message,
		ErrorType: determineErrorType(code),
		Version:   "v1",
	}
}

func Wrap(err error, code ErrorCode, message string) *AppError {
	return &AppError{
		Code:      code,
		Message:   message,
		Err:       err,
		ErrorType: determineErrorType(code),
		Version:   "v1",
	}
}

func WithDetails(code ErrorCode, message string, details interface{}) *AppError {
	return &AppError{
		Code:      code,
		Message:   message,
		Details:   details,
		ErrorType: determineErrorType(code),
		Version:   "v1",
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
	ErrServiceUnavailable = New(ErrCodeServiceUnavailable, "Service unavailable")
)
