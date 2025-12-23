package app

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/waqasmani/go-boilerplate/internal/infrastructure/observability"
)

func TestRequestIDMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(RequestIDMiddleware())

	// Dummy handler to check context
	r.GET("/test", func(c *gin.Context) {
		// Check Header
		reqID := c.Writer.Header().Get("X-Request-ID")
		assert.NotEmpty(t, reqID)

		// Check Gin Keys
		val, exists := c.Get(string(observability.RequestIDKey))
		assert.True(t, exists)
		assert.Equal(t, reqID, val)

		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NotEmpty(t, w.Header().Get("X-Request-ID"))
}

func TestRequestIDMiddleware_ExistingID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(RequestIDMiddleware())

	existingID := "custom-trace-id-123"

	r.GET("/test", func(c *gin.Context) {
		assert.Equal(t, existingID, c.Writer.Header().Get("X-Request-ID"))
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Request-ID", existingID) // Client sends ID
	r.ServeHTTP(w, req)
}
