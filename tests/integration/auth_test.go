package integration

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthFlow_CompleteJourney(t *testing.T) {
	tc := SetupTestEnvironment(t)
	defer tc.Cleanup(t)

	testEmail := "test@example.com"
	testPassword := "SecurePass123!"
	tc.CreateTestUser(t, testEmail, testPassword, "user")

	var accessToken, refreshToken, csrfToken string

	t.Run("Login Success", func(t *testing.T) {
		loginPayload := map[string]string{
			"email":    testEmail,
			"password": testPassword,
		}
		body, _ := json.Marshal(loginPayload)

		req := httptest.NewRequest("POST", "/api/v1/auth/login", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		tc.Router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))

		assert.True(t, response["success"].(bool))
		data := response["data"].(map[string]interface{})
		accessToken = data["access_token"].(string)
		csrfToken = data["csrf_token"].(string)

		assert.NotEmpty(t, accessToken)
		assert.NotEmpty(t, csrfToken)

		cookies := w.Result().Cookies()
		var foundRefreshToken bool
		for _, cookie := range cookies {
			if cookie.Name == "refresh_token" {
				refreshToken = cookie.Value
				foundRefreshToken = true
				assert.True(t, cookie.HttpOnly)
				assert.Equal(t, "/api/v1/auth", cookie.Path)
				break
			}
		}
		assert.True(t, foundRefreshToken, "Refresh token cookie not found")
	})

	t.Run("Login with Invalid Credentials", func(t *testing.T) {
		loginPayload := map[string]string{
			"email":    testEmail,
			"password": "WrongPassword",
		}
		body, _ := json.Marshal(loginPayload)

		req := httptest.NewRequest("POST", "/api/v1/auth/login", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		tc.Router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)

		var response map[string]interface{}
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
		assert.False(t, response["success"].(bool))
	})

	t.Run("Access Protected Endpoint with Valid Token", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/users/1", nil)
		req.Header.Set("Authorization", "Bearer "+accessToken)
		w := httptest.NewRecorder()

		tc.Router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("Access Protected Endpoint without Token", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/users/1", nil)
		w := httptest.NewRecorder()

		tc.Router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("Refresh Tokens", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/auth/refresh", nil)
		req.AddCookie(&http.Cookie{
			Name:  "refresh_token",
			Value: refreshToken,
		})
		w := httptest.NewRecorder()

		tc.Router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))

		assert.True(t, response["success"].(bool))
		data := response["data"].(map[string]interface{})
		newAccessToken := data["access_token"].(string)
		newCsrfToken := data["csrf_token"].(string)

		assert.NotEmpty(t, newAccessToken)
		assert.NotEmpty(t, newCsrfToken)
		assert.NotEqual(t, accessToken, newAccessToken)
		assert.NotEqual(t, csrfToken, newCsrfToken)

		cookies := w.Result().Cookies()
		var newRefreshToken string
		for _, cookie := range cookies {
			if cookie.Name == "refresh_token" {
				newRefreshToken = cookie.Value
				break
			}
		}
		assert.NotEmpty(t, newRefreshToken)
		assert.NotEqual(t, refreshToken, newRefreshToken)

		accessToken = newAccessToken
		refreshToken = newRefreshToken
		csrfToken = newCsrfToken
	})

	t.Run("Old Refresh Token Should Not Work", func(t *testing.T) {
		oldRefreshToken := refreshToken

		req := httptest.NewRequest("POST", "/api/v1/auth/refresh", nil)
		req.AddCookie(&http.Cookie{
			Name:  "refresh_token",
			Value: oldRefreshToken,
		})
		w := httptest.NewRecorder()

		tc.Router.ServeHTTP(w, req)

		req2 := httptest.NewRequest("POST", "/api/v1/auth/refresh", nil)
		req2.AddCookie(&http.Cookie{
			Name:  "refresh_token",
			Value: oldRefreshToken,
		})
		w2 := httptest.NewRecorder()

		tc.Router.ServeHTTP(w2, req2)

		assert.Equal(t, http.StatusUnauthorized, w2.Code)
	})

	t.Run("Logout", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/auth/logout", nil)
		req.AddCookie(&http.Cookie{
			Name:  "refresh_token",
			Value: refreshToken,
		})
		w := httptest.NewRecorder()

		tc.Router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		if w.Code != http.StatusOK {
			return // Don't continue if the request failed
		}

		cookies := w.Result().Cookies()
		var refreshCookie *http.Cookie
		for _, cookie := range cookies {
			if cookie.Name == "refresh_token" {
				refreshCookie = cookie
				break
			}
		}
		assert.NotNil(t, refreshCookie)
		assert.Equal(t, -1, refreshCookie.MaxAge)
	})

	t.Run("Refresh After Logout Should Fail", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/auth/refresh", nil)
		req.AddCookie(&http.Cookie{
			Name:  "refresh_token",
			Value: refreshToken,
		})
		w := httptest.NewRecorder()

		tc.Router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

func TestAuthFlow_TokenExpiration(t *testing.T) {
	// Set a slightly longer expiration time to avoid race conditions
	t.Setenv("JWT_ACCESS_EXPIRY", "200ms")
	tc := SetupTestEnvironment(t)
	defer tc.Cleanup(t)

	testEmail := "expiry@example.com"
	testPassword := "SecurePass123!"
	tc.CreateTestUser(t, testEmail, testPassword, "user")

	// Login request
	loginPayload := map[string]string{
		"email":    testEmail,
		"password": testPassword,
	}
	body, _ := json.Marshal(loginPayload)
	req := httptest.NewRequest("POST", "/api/v1/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	tc.Router.ServeHTTP(w, req)

	// Verify login was successful before proceeding
	assert.Equal(t, http.StatusOK, w.Code, "Login failed. Response: %s", w.Body.String())

	var response map[string]interface{}
	assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &response), "Failed to parse response")

	// Check if login was actually successful
	success, ok := response["success"].(bool)
	assert.True(t, ok, "Response missing 'success' field")
	assert.True(t, success, "Login was not successful: %v", response)

	// Safely access data field
	data, dataOk := response["data"].(map[string]interface{})
	if !dataOk {
		t.Fatalf("Response data is not a map or is nil. Full response: %v", response)
	}

	// Safely get access token
	accessToken, tokenOk := data["access_token"].(string)
	assert.True(t, tokenOk, "Access token not found in response")
	assert.NotEmpty(t, accessToken, "Access token is empty")

	// Wait for token to expire (longer than the expiration time)
	time.Sleep(300 * time.Millisecond)

	// Attempt to use the expired token
	req2 := httptest.NewRequest("GET", "/api/v1/users/1", nil)
	req2.Header.Set("Authorization", "Bearer "+accessToken)
	w2 := httptest.NewRecorder()
	tc.Router.ServeHTTP(w2, req2)

	// Verify we get an unauthorized response
	assert.Equal(t, http.StatusUnauthorized, w2.Code,
		"Expected 401 Unauthorized after token expiration, got %d. Response: %s",
		w2.Code, w2.Body.String())
}

func TestAuthFlow_InactiveUser(t *testing.T) {
	tc := SetupTestEnvironment(t)
	defer tc.Cleanup(t)

	testEmail := "inactive@example.com"
	testPassword := "SecurePass123!"
	userID := tc.CreateTestUser(t, testEmail, testPassword, "user")

	_, err := tc.DB.Exec("UPDATE users SET is_active = FALSE WHERE id = ?", userID)
	require.NoError(t, err)

	loginPayload := map[string]string{
		"email":    testEmail,
		"password": testPassword,
	}
	body, _ := json.Marshal(loginPayload)

	req := httptest.NewRequest("POST", "/api/v1/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	tc.Router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var response map[string]interface{}
	assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
	assert.False(t, response["success"].(bool))
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuth_Register(t *testing.T) {
	tc := SetupTestEnvironment(t)
	defer tc.Cleanup(t)

	regEmail := "register_test@example.com"
	regPass := "SecurePass123!"

	// 1. Successful Registration
	t.Run("Successful Registration", func(t *testing.T) {
		payload := map[string]string{
			"email":      regEmail,
			"password":   regPass,
			"first_name": "Test",
			"last_name":  "User",
			"role":       "user",
		}
		body, _ := json.Marshal(payload)

		req := httptest.NewRequest("POST", "/api/v1/auth/register", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		tc.Router.ServeHTTP(w, req)

		// Assertions
		require.Equal(t, http.StatusCreated, w.Code)

		var response map[string]interface{}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))

		// Check success flag
		assert.True(t, response["success"].(bool))

		// Check returned data
		data := response["data"].(map[string]interface{})
		assert.Equal(t, regEmail, data["email"])
		assert.NotEmpty(t, data["id"])
		// Handler forces "user" role for registration, even if request sends otherwise
		assert.Equal(t, "user", data["role"])
	})

	// 2. Duplicate Registration (The Crash Reproduction Case)
	t.Run("Duplicate Registration Should Return 409", func(t *testing.T) {
		payload := map[string]string{
			"email":      regEmail,
			"password":   regPass,
			"first_name": "Test",
			"last_name":  "User",
			"role":       "user", // <--- ADD THIS LINE
		}
		body, _ := json.Marshal(payload)

		req := httptest.NewRequest("POST", "/api/v1/auth/register", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		tc.Router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusConflict, w.Code)

		var response map[string]interface{}
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
		assert.False(t, response["success"].(bool))
	})

	// 3. Validation Failures
	t.Run("Validation Failure", func(t *testing.T) {
		testCases := []struct {
			name    string
			payload map[string]string
		}{
			{
				name: "Invalid Email",
				payload: map[string]string{
					"email":      "not-an-email",
					"password":   "SecurePass123!",
					"first_name": "Test",
					"last_name":  "User",
				},
			},
			{
				name: "Short Password",
				payload: map[string]string{
					"email":      "valid@example.com",
					"password":   "short",
					"first_name": "Test",
					"last_name":  "User",
				},
			},
			{
				name: "Missing Fields",
				payload: map[string]string{
					"email":    "valid@example.com",
					"password": "SecurePass123!",
				},
			},
		}

		for _, tcCase := range testCases {
			t.Run(tcCase.name, func(t *testing.T) {
				body, _ := json.Marshal(tcCase.payload)
				req := httptest.NewRequest("POST", "/api/v1/auth/register", bytes.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				w := httptest.NewRecorder()

				tc.Router.ServeHTTP(w, req)

				assert.Equal(t, http.StatusBadRequest, w.Code)
			})
		}
	})
}
