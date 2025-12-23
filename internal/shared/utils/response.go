package utils

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/waqasmani/go-boilerplate/internal/shared/errors"
)

type Response struct {
	Success bool           `json:"success"`
	Data    any            `json:"data,omitempty"`
	Error   *ErrorResponse `json:"error,omitempty"`
}

type ErrorResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details any    `json:"details,omitempty"`
}

func Success(c *gin.Context, statusCode int, data any) {
	c.JSON(statusCode, Response{
		Success: true,
		Data:    data,
	})
}

func Error(c *gin.Context, err error) {
	appErr, ok := err.(*errors.AppError)
	if !ok {
		appErr = errors.Wrap(err, errors.ErrCodeInternal, "An unexpected error occurred")
	}

	statusCode := getHTTPStatusCode(appErr.Code)

	c.JSON(statusCode, Response{
		Success: false,
		Error: &ErrorResponse{
			Code:    string(appErr.Code),
			Message: appErr.Message,
			Details: appErr.Details,
		},
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
	default:
		return http.StatusInternalServerError
	}
}
