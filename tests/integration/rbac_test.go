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

func TestRBAC_Authorization(t *testing.T) {
	tc := SetupTestEnvironment(t)
	defer tc.Cleanup(t)

	adminEmail := "admin@example.com"
	adminPassword := "AdminPass123!"
	tc.CreateTestUser(t, adminEmail, adminPassword, "admin")

	userEmail := "user@example.com"
	userPassword := "UserPass123!"
	userID := tc.CreateTestUser(t, userEmail, userPassword, "user")

	adminAccessToken, adminCSRFToken := loginAndGetTokens(t, tc, adminEmail, adminPassword)
	userAccessToken, userCSRFToken := loginAndGetTokens(t, tc, userEmail, userPassword)

	t.Run("User Cannot Create User", func(t *testing.T) {
		createUserPayload := map[string]string{
			"email":      "blocked@example.com",
			"password":   "BlockedPass123!",
			"first_name": "Blocked",
			"last_name":  "User",
			"role":       "user",
		}
		body, _ := json.Marshal(createUserPayload)

		req := httptest.NewRequest("POST", "/api/v1/users/", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+userAccessToken)
		req.Header.Set("X-CSRF-Token", userCSRFToken)
		w := httptest.NewRecorder()

		tc.Router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("Admin Can Create User", func(t *testing.T) {
		createUserPayload := map[string]string{
			"email":      "allowed@example.com",
			"password":   "AllowedPass123!",
			"first_name": "Allowed",
			"last_name":  "User",
			"role":       "user",
		}
		body, _ := json.Marshal(createUserPayload)

		req := httptest.NewRequest("POST", "/api/v1/users/", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+adminAccessToken)
		req.Header.Set("X-CSRF-Token", adminCSRFToken)
		w := httptest.NewRecorder()

		tc.Router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
	})

	t.Run("User Cannot List All Users", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/users/?page=1&page_size=10", nil)
		req.Header.Set("Authorization", "Bearer "+userAccessToken)
		req.Header.Set("X-CSRF-Token", userCSRFToken)
		w := httptest.NewRecorder()

		tc.Router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("Admin Can List All Users", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/users/?page=1&page_size=10", nil)
		req.Header.Set("Authorization", "Bearer "+adminAccessToken)
		req.Header.Set("X-CSRF-Token", adminCSRFToken)
		w := httptest.NewRecorder()

		tc.Router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("User Cannot Deactivate Another User", func(t *testing.T) {
		otherUserID := tc.CreateTestUser(t, "other@example.com", "OtherPass123!", "user")

		req := httptest.NewRequest("DELETE", fmt.Sprintf("/api/v1/users/%d", otherUserID), nil)
		req.Header.Set("Authorization", "Bearer "+userAccessToken)
		req.Header.Set("X-CSRF-Token", userCSRFToken)
		w := httptest.NewRecorder()

		tc.Router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("User Can View Own Profile", func(t *testing.T) {
		req := httptest.NewRequest("GET", fmt.Sprintf("/api/v1/users/%d", userID), nil)
		req.Header.Set("Authorization", "Bearer "+userAccessToken)
		w := httptest.NewRecorder()

		tc.Router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("User Can Update Own Profile", func(t *testing.T) {
		updatePayload := map[string]string{
			"first_name": "UpdatedFirst",
			"last_name":  "UpdatedLast",
		}
		body, _ := json.Marshal(updatePayload)

		req := httptest.NewRequest("PUT", fmt.Sprintf("/api/v1/users/%d", userID), bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+userAccessToken)
		req.Header.Set("X-CSRF-Token", userCSRFToken)
		w := httptest.NewRecorder()

		tc.Router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("User Cannot Update Another User Profile", func(t *testing.T) {
		otherUserID := tc.CreateTestUser(t, "another@example.com", "AnotherPass123!", "user")

		updatePayload := map[string]string{
			"first_name": "Hacked",
			"last_name":  "User",
		}
		body, _ := json.Marshal(updatePayload)

		req := httptest.NewRequest("PUT", fmt.Sprintf("/api/v1/users/%d", otherUserID), bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+userAccessToken)
		req.Header.Set("X-CSRF-Token", userCSRFToken)
		w := httptest.NewRecorder()

		tc.Router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("Admin Can Update Any User Profile", func(t *testing.T) {
		updatePayload := map[string]string{
			"first_name": "AdminUpdated",
			"last_name":  "ByAdmin",
		}
		body, _ := json.Marshal(updatePayload)

		req := httptest.NewRequest("PUT", fmt.Sprintf("/api/v1/users/%d", userID), bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+adminAccessToken)
		req.Header.Set("X-CSRF-Token", adminCSRFToken)
		w := httptest.NewRecorder()

		tc.Router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &response)
		data := response["data"].(map[string]interface{})

		assert.Equal(t, "AdminUpdated", data["first_name"])
		assert.Equal(t, "ByAdmin", data["last_name"])
	})
}