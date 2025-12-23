package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCSRF_Protection(t *testing.T) {
	tc := SetupTestEnvironment(t)
	defer tc.Cleanup(t)

	userEmail := "user@example.com"
	userPassword := "UserPass123!"
	userID := tc.CreateTestUser(t, userEmail, userPassword, "user")

	accessToken, csrfToken := loginAndGetTokens(t, tc, userEmail, userPassword)

	t.Run("State-Changing Request Without CSRF Token Fails", func(t *testing.T) {
		updatePayload := map[string]string{
			"first_name": "Should",
			"last_name":  "Fail",
		}
		body, _ := json.Marshal(updatePayload)

		req := httptest.NewRequest("PUT", fmt.Sprintf("/api/v1/users/%d", userID), bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+accessToken)
		w := httptest.NewRecorder()

		tc.Router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("State-Changing Request With Valid CSRF Token Succeeds", func(t *testing.T) {
		updatePayload := map[string]string{
			"first_name": "Should",
			"last_name":  "Succeed",
		}
		body, _ := json.Marshal(updatePayload)

		req := httptest.NewRequest("PUT", fmt.Sprintf("/api/v1/users/%d", userID), bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+accessToken)
		req.Header.Set("X-CSRF-Token", csrfToken)
		w := httptest.NewRecorder()

		tc.Router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("State-Changing Request With Invalid CSRF Token Fails", func(t *testing.T) {
		updatePayload := map[string]string{
			"first_name": "Should",
			"last_name":  "Fail",
		}
		body, _ := json.Marshal(updatePayload)

		req := httptest.NewRequest("PUT", fmt.Sprintf("/api/v1/users/%d", userID), bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+accessToken)
		req.Header.Set("X-CSRF-Token", "invalid-csrf-token")
		w := httptest.NewRecorder()

		tc.Router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("GET Request Without CSRF Token Succeeds", func(t *testing.T) {
		req := httptest.NewRequest("GET", fmt.Sprintf("/api/v1/users/%d", userID), nil)
		req.Header.Set("Authorization", "Bearer "+accessToken)
		w := httptest.NewRecorder()

		tc.Router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("CSRF Token From Another User Should Not Work", func(t *testing.T) {
		otherUserEmail := "other@example.com"
		otherUserPassword := "OtherPass123!"
		otherUserID := tc.CreateTestUser(t, otherUserEmail, otherUserPassword, "user")

		_, otherCSRFToken := loginAndGetTokens(t, tc, otherUserEmail, otherUserPassword)

		updatePayload := map[string]string{
			"first_name": "Should",
			"last_name":  "Fail",
		}
		body, _ := json.Marshal(updatePayload)

		req := httptest.NewRequest("PUT", fmt.Sprintf("/api/v1/users/%d", userID), bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+accessToken)
		req.Header.Set("X-CSRF-Token", otherCSRFToken)
		w := httptest.NewRecorder()

		tc.Router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)

		req2 := httptest.NewRequest("GET", fmt.Sprintf("/api/v1/users/%d", otherUserID), nil)
		req2.Header.Set("Authorization", "Bearer "+accessToken)
		w2 := httptest.NewRecorder()

		tc.Router.ServeHTTP(w2, req2)
		assert.Equal(t, http.StatusOK, w2.Code)
	})

	t.Run("Get Fresh CSRF Token", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/auth/csrf-token", nil)
		req.Header.Set("Authorization", "Bearer "+accessToken)
		w := httptest.NewRecorder()

		tc.Router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
		data := response["data"].(map[string]interface{})
		newCSRFToken := data["csrf_token"].(string)

		assert.NotEmpty(t, newCSRFToken)
		assert.NotEqual(t, csrfToken, newCSRFToken)

		updatePayload := map[string]string{
			"first_name": "With",
			"last_name":  "NewToken",
		}
		body, _ := json.Marshal(updatePayload)

		req2 := httptest.NewRequest("PUT", fmt.Sprintf("/api/v1/users/%d", userID), bytes.NewReader(body))
		req2.Header.Set("Content-Type", "application/json")
		req2.Header.Set("Authorization", "Bearer "+accessToken)
		req2.Header.Set("X-CSRF-Token", newCSRFToken)
		w2 := httptest.NewRecorder()

		tc.Router.ServeHTTP(w2, req2)

		assert.Equal(t, http.StatusOK, w2.Code)
	})
}
