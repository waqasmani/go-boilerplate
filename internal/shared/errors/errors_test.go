package errors

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAppError(t *testing.T) {
	// 1. Test New()
	err := New(ErrCodeNotFound, "Item missing")
	assert.Equal(t, ErrCodeNotFound, err.Code)
	assert.Equal(t, "Item missing", err.Message)
	assert.Equal(t, "NOT_FOUND: Item missing", err.Error())

	// 2. Test Wrap()
	origErr := errors.New("db connection failed")
	wrappedErr := Wrap(origErr, ErrCodeInternal, "Database error")
	assert.Equal(t, origErr, wrappedErr.Unwrap())
	assert.Contains(t, wrappedErr.Error(), "INTERNAL_ERROR: Database error")
	assert.Contains(t, wrappedErr.Error(), "db connection failed")

	// 3. Test WithDetails()
	details := map[string]string{"field": "email"}
	detailErr := WithDetails(ErrCodeValidation, "Invalid input", details)
	assert.Equal(t, details, detailErr.Details)
}
