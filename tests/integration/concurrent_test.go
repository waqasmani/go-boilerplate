package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConcurrent_UserUpdates(t *testing.T) {
	tc := SetupTestEnvironment(t)
	defer tc.Cleanup(t)

	userEmail := "concurrent@example.com"
	userPassword := "ConcurrentPass123!"
	userID := tc.CreateTestUser(t, userEmail, userPassword, "user")

	accessToken, csrfToken := loginAndGetTokens(t, tc, userEmail, userPassword)

	const numGoroutines = 10
	var wg sync.WaitGroup
	results := make([]int, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()

			updatePayload := map[string]string{
				"first_name": fmt.Sprintf("First%d", index),
				"last_name":  fmt.Sprintf("Last%d", index),
			}
			body, _ := json.Marshal(updatePayload)

			req := httptest.NewRequest("PUT", fmt.Sprintf("/api/v1/users/%d", userID), bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+accessToken)
			req.Header.Set("X-CSRF-Token", csrfToken)
			w := httptest.NewRecorder()

			tc.Router.ServeHTTP(w, req)
			results[index] = w.Code
		}(i)
	}

	wg.Wait()

	for i, code := range results {
		assert.Equal(t, 200, code, "Request %d failed", i)
	}

	req := httptest.NewRequest("GET", fmt.Sprintf("/api/v1/users/%d", userID), nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	w := httptest.NewRecorder()

	tc.Router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
}

func TestConcurrent_TokenRefresh(t *testing.T) {
	tc := SetupTestEnvironment(t)
	defer tc.Cleanup(t)

	userEmail := "refresh@example.com"
	userPassword := "RefreshPass123!"
	tc.CreateTestUser(t, userEmail, userPassword, "user")

	loginPayload := map[string]string{
		"email":    userEmail,
		"password": userPassword,
	}
	body, _ := json.Marshal(loginPayload)

	req := httptest.NewRequest("POST", "/api/v1/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	tc.Router.ServeHTTP(w, req)

	cookies := w.Result().Cookies()
	var refreshToken string
	for _, cookie := range cookies {
		if cookie.Name == "refresh_token" {
			refreshToken = cookie.Value
			break
		}
	}

	const numGoroutines = 5
	var wg sync.WaitGroup
	results := make([]int, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()

			req := httptest.NewRequest("POST", "/api/v1/auth/refresh", nil)
			req.AddCookie(&http.Cookie{
				Name:  "refresh_token",
				Value: refreshToken,
			})
			w := httptest.NewRecorder()

			tc.Router.ServeHTTP(w, req)
			results[index] = w.Code
		}(i)
	}

	wg.Wait()

	successCount := 0
	for _, code := range results {
		if code == 200 {
			successCount++
		}
	}

	assert.Equal(t, 1, successCount, "Only one refresh should succeed due to token rotation")
}
