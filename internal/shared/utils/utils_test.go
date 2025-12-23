package utils_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	appErrors "github.com/waqasmani/go-boilerplate/internal/shared/errors"
	"github.com/waqasmani/go-boilerplate/internal/shared/utils"
	"github.com/waqasmani/go-boilerplate/internal/shared/validator"
)

func TestResponse_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	data := map[string]string{"foo": "bar"}
	utils.Success(c, http.StatusOK, data)

	var response utils.Response
	assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
	assert.True(t, response.Success)

	respData := response.Data.(map[string]interface{})
	assert.Equal(t, "bar", respData["foo"])
}

func TestResponse_Error(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	appErr := appErrors.New(appErrors.ErrCodeNotFound, "Item missing")
	utils.Error(c, appErr)

	assert.Equal(t, http.StatusNotFound, w.Code)

	var response utils.Response
	json.Unmarshal(w.Body.Bytes(), &response)
	assert.False(t, response.Success)
	assert.Equal(t, "NOT_FOUND", response.Error.Code)
}

func TestResponse_StandardErrorWrapping(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	stdErr := errors.New("something crashed")
	utils.Error(c, stdErr)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestValidator(t *testing.T) {
	v := validator.New()

	type User struct {
		Email string `validate:"required,email"`
		Age   int    `validate:"gte=18"`
	}

	// 1. Success
	u := User{Email: "test@test.com", Age: 20}
	assert.NoError(t, v.Validate(u))

	// 2. Failure
	badUser := User{Email: "invalid", Age: 10}
	err := v.Validate(badUser)
	assert.Error(t, err)

	// 3. Check specific fields without relying on order
	msgs := validator.TranslateValidationErrors(err)
	assert.Len(t, msgs, 2)

	// Create a map for easier checking
	errorMap := make(map[string]string)
	for _, m := range msgs {
		errorMap[m.Field] = m.Message
	}

	assert.Contains(t, errorMap, "Age")
	assert.Contains(t, errorMap, "Email")
	assert.Equal(t, "Invalid email format", errorMap["Email"])
}
