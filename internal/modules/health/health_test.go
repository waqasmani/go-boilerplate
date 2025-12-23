package health

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestHealthHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// 1. Setup Mock DB
	db, mock, err := sqlmock.New(sqlmock.MonitorPingsOption(true))
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer db.Close()
	handler := NewHandler(db)

	t.Run("Health Check - OK", func(t *testing.T) {
		// Expect Ping to succeed
		mock.ExpectPing()
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request, _ = http.NewRequest("GET", "/health", nil)
		handler.Health(c)
		assert.Equal(t, http.StatusOK, w.Code)
		
		// Check the response contains the expected status
		assert.Contains(t, w.Body.String(), `"status":"ok"`)
		assert.Contains(t, w.Body.String(), `"database":{"status":"ok"`)
	})

	t.Run("Ready Check - DB Fail", func(t *testing.T) {
		// Expect Ping to fail
		mock.ExpectPing().WillReturnError(assert.AnError)
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request, _ = http.NewRequest("GET", "/ready", nil)
		handler.Ready(c)
		// Your handler returns 503 on db failure
		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
		assert.Contains(t, w.Body.String(), `"database":{"status":"error"`)
	})

	// Verify all expectations were met
	assert.NoError(t, mock.ExpectationsWereMet())
}