package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUserManagement_CRUD(t *testing.T) {
	tc := SetupTestEnvironment(t)
	defer tc.Cleanup(t)

	adminEmail := "admin@example.com"
	adminPassword := "AdminPass123!"
	tc.CreateTestUser(t, adminEmail, adminPassword, "admin")

	adminAccessToken, adminCSRFToken := loginAndGetTokens(t, tc, adminEmail, adminPassword)

	var createdUserID uint64

	t.Run("Admin Creates User", func(t *testing.T) {
		createUserPayload := map[string]string{
			"email":      "newuser@example.com",
			"password":   "NewUserPass123!",
			"first_name": "New",
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

		var response map[string]interface{}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))

		assert.True(t, response["success"].(bool))
		data := response["data"].(map[string]interface{})
		createdUserID = uint64(data["id"].(float64))
		assert.Equal(t, "newuser@example.com", data["email"])
		assert.Equal(t, "New", data["first_name"])
		assert.Equal(t, "user", data["role"])
	})

	t.Run("Admin Lists Users", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/users/?page=1&page_size=10", nil)
		req.Header.Set("Authorization", "Bearer "+adminAccessToken)
		req.Header.Set("X-CSRF-Token", adminCSRFToken)
		w := httptest.NewRecorder()

		tc.Router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
		data := response["data"].(map[string]interface{})
		users := data["users"].([]interface{})

		assert.GreaterOrEqual(t, len(users), 2)
	})

	t.Run("Admin Gets User By ID", func(t *testing.T) {
		req := httptest.NewRequest("GET", fmt.Sprintf("/api/v1/users/%d", createdUserID), nil)
		req.Header.Set("Authorization", "Bearer "+adminAccessToken)
		w := httptest.NewRecorder()

		tc.Router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
		data := response["data"].(map[string]interface{})

		assert.Equal(t, float64(createdUserID), data["id"])
		assert.Equal(t, "newuser@example.com", data["email"])
	})

	t.Run("Admin Updates User", func(t *testing.T) {
		updatePayload := map[string]string{
			"first_name": "Updated",
			"last_name":  "Name",
		}
		body, _ := json.Marshal(updatePayload)

		req := httptest.NewRequest("PUT", fmt.Sprintf("/api/v1/users/%d", createdUserID), bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+adminAccessToken)
		req.Header.Set("X-CSRF-Token", adminCSRFToken)
		w := httptest.NewRecorder()

		tc.Router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
		data := response["data"].(map[string]interface{})

		assert.Equal(t, "Updated", data["first_name"])
		assert.Equal(t, "Name", data["last_name"])
	})

	t.Run("Admin Deactivates User", func(t *testing.T) {
		req := httptest.NewRequest("DELETE", fmt.Sprintf("/api/v1/users/%d", createdUserID), nil)
		req.Header.Set("Authorization", "Bearer "+adminAccessToken)
		req.Header.Set("X-CSRF-Token", adminCSRFToken)
		w := httptest.NewRecorder()

		tc.Router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		req2 := httptest.NewRequest("GET", fmt.Sprintf("/api/v1/users/%d", createdUserID), nil)
		req2.Header.Set("Authorization", "Bearer "+adminAccessToken)
		w2 := httptest.NewRecorder()

		tc.Router.ServeHTTP(w2, req2)

		assert.Equal(t, http.StatusNotFound, w2.Code)
	})
}

func TestUserManagement_PasswordChange(t *testing.T) {
	tc := SetupTestEnvironment(t)
	defer tc.Cleanup(t)

	userEmail := "user@example.com"
	userPassword := "OldPass123!"
	userID := tc.CreateTestUser(t, userEmail, userPassword, "user")

	accessToken, csrfToken := loginAndGetTokens(t, tc, userEmail, userPassword)

	t.Run("Change Password Success", func(t *testing.T) {
		changePasswordPayload := map[string]string{
			"current_password": userPassword,
			"new_password":     "NewPass123!",
		}
		body, _ := json.Marshal(changePasswordPayload)

		req := httptest.NewRequest("PUT", fmt.Sprintf("/api/v1/users/%d/password", userID), bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+accessToken)
		req.Header.Set("X-CSRF-Token", csrfToken)
		w := httptest.NewRecorder()

		tc.Router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("Login with Old Password Fails", func(t *testing.T) {
		loginPayload := map[string]string{
			"email":    userEmail,
			"password": userPassword,
		}
		body, _ := json.Marshal(loginPayload)

		req := httptest.NewRequest("POST", "/api/v1/auth/login", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		tc.Router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("Login with New Password Success", func(t *testing.T) {
		loginPayload := map[string]string{
			"email":    userEmail,
			"password": "NewPass123!",
		}
		body, _ := json.Marshal(loginPayload)

		req := httptest.NewRequest("POST", "/api/v1/auth/login", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		tc.Router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("Change Password with Wrong Current Password", func(t *testing.T) {
		newAccessToken, newCsrfToken := loginAndGetTokens(t, tc, userEmail, "NewPass123!")

		changePasswordPayload := map[string]string{
			"current_password": "WrongPassword",
			"new_password":     "AnotherPass123!",
		}
		body, _ := json.Marshal(changePasswordPayload)

		req := httptest.NewRequest("PUT", fmt.Sprintf("/api/v1/users/%d/password", userID), bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+newAccessToken)
		req.Header.Set("X-CSRF-Token", newCsrfToken)
		w := httptest.NewRecorder()

		tc.Router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

func loginAndGetTokens(t *testing.T, tc *TestContext, email, password string) (string, string) {
	loginPayload := map[string]string{
		"email":    email,
		"password": password,
	}
	body, _ := json.Marshal(loginPayload)

	req := httptest.NewRequest("POST", "/api/v1/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	tc.Router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))

	data := response["data"].(map[string]interface{})
	return data["access_token"].(string), data["csrf_token"].(string)
}
