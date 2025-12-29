package utils

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/waqasmani/go-boilerplate/internal/infrastructure/observability"
	"github.com/waqasmani/go-boilerplate/internal/shared/errors"
)

type Response struct {
	Success bool           `json:"success"`
	Data    any            `json:"data,omitempty"`
	Error   *ErrorResponse `json:"error,omitempty"`
	Version string         `json:"version"`
}

type ErrorResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details any    `json:"details,omitempty"`
	Type    string `json:"type"`
}

func Success(c *gin.Context, statusCode int, data any) {
	c.JSON(statusCode, Response{
		Success: true,
		Data:    data,
		Version: "v1",
	})
}

func Error(c *gin.Context, err error) {
	appErr, ok := err.(*errors.AppError)
	if !ok {
		appErr = errors.Wrap(err, errors.ErrCodeInternal, "An unexpected error occurred")
	}

	// Get correlation IDs from context
	traceID := c.GetString(string(observability.TraceIDKey))
	requestID := c.GetString(string(observability.RequestIDKey))

	// Add correlation IDs to error details
	if appErr.Details == nil {
		appErr.Details = make(map[string]string)
	}
	if details, ok := appErr.Details.(map[string]string); ok {
		if traceID != "" {
			details["trace_id"] = traceID
		}
		if requestID != "" {
			details["request_id"] = requestID
		}
	}

	statusCode := getHTTPStatusCode(appErr.Code)
	c.JSON(statusCode, Response{
		Success: false,
		Error: &ErrorResponse{
			Code:    string(appErr.Code),
			Message: appErr.Message,
			Details: appErr.Details,
			Type:    string(appErr.ErrorType),
		},
		Version: "v1",
	})
}

func getHTTPStatusCode(code errors.ErrorCode) int {
	switch code {
	case errors.ErrCodeNotFound:
		return http.StatusNotFound
	case errors.ErrCodeBadRequest, errors.ErrCodeValidation:
		return http.StatusBadRequest
	case errors.ErrCodeUnauthorized, errors.ErrCodeInvalidToken, errors.ErrCodeExpiredToken, errors.ErrCodeRevokedToken, errors.ErrCodeInvalidCredentials:
		return http.StatusUnauthorized
	case errors.ErrCodeForbidden:
		return http.StatusForbidden
	case errors.ErrCodeConflict:
		return http.StatusConflict
	case errors.ErrCodeTooManyRequests:
		return http.StatusTooManyRequests
	case errors.ErrCodeServiceUnavailable:
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}
