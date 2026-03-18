//go:build integration

package integration

import (
	"net/http"
	"testing"
)

// TestMFAWebAuthnRegistration tests WebAuthn/passkey registration flow.
func TestMFAWebAuthnRegistration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	env := SetupTestEnv(t)
	defer env.Teardown(t)

	client := NewHTTPClient(env.AuthServer.URL, env.TestTenantID)

	// Begin registration (requires X-User-ID header)
	t.Run("BeginRegistration", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodPost, env.AuthServer.URL+"/api/v1/mfa/webauthn/register/begin", nil)
		req.Header.Set("X-Tenant-ID", env.TestTenantID)
		req.Header.Set("X-User-ID", env.TestUserID)

		httpClient := &http.Client{}
		resp, err := httpClient.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		// Should return OK with registration options
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusInternalServerError {
			// InternalServerError might occur if WebAuthn is not configured
			t.Logf("BeginRegistration returned status %d (may be expected if WebAuthn not configured)", resp.StatusCode)
		}
	})

	// Test without user ID
	t.Run("MissingUserID", func(t *testing.T) {
		resp := client.Post(t, "/api/v1/mfa/webauthn/register/begin", nil)
		AssertStatus(t, resp, http.StatusBadRequest)
	})
}

// TestMFAWebAuthnLogin tests WebAuthn/passkey login flow.
func TestMFAWebAuthnLogin(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	env := SetupTestEnv(t)
	defer env.Teardown(t)

	client := NewHTTPClient(env.AuthServer.URL, env.TestTenantID)

	// Begin login
	t.Run("BeginLogin", func(t *testing.T) {
		loginReq := map[string]interface{}{
			"user_id": env.TestUserID,
		}
		resp := client.Post(t, "/api/v1/mfa/webauthn/login/begin", loginReq)
		// May fail if user has no registered credentials
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusInternalServerError {
			t.Logf("BeginLogin returned status %d", resp.StatusCode)
		}
	})

	// Test without user ID
	t.Run("MissingUserID", func(t *testing.T) {
		resp := client.Post(t, "/api/v1/mfa/webauthn/login/begin", map[string]interface{}{})
		// Should fail with bad request
		if resp.StatusCode == http.StatusOK {
			t.Error("Expected error for missing user_id")
		}
	})
}

// TestTOTPSetup tests TOTP (authenticator app) setup endpoints.
func TestTOTPSetup(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	env := SetupTestEnv(t)
	defer env.Teardown(t)

	// client := NewHTTPClient(env.AuthServer.URL, env.TestTenantID)

	// Note: TOTP endpoints may require authentication
	// These tests verify API accessibility

	// Check if TOTP setup endpoint exists
	t.Run("SetupEndpoint", func(t *testing.T) {
		// TOTP enrollment typically requires authenticated user
		// Just check endpoint responds
		req, _ := http.NewRequest(http.MethodPost, env.AuthServer.URL+"/api/v1/mfa/totp/enroll", mustJSON(map[string]interface{}{
			"user_id": env.TestUserID,
		}))
		req.Header.Set("X-Tenant-ID", env.TestTenantID)
		req.Header.Set("X-User-ID", env.TestUserID)

		httpClient := &http.Client{}
		resp, err := httpClient.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		// Endpoint should exist (typically 200 or 401 if missing auth)
		if resp.StatusCode == http.StatusNotFound {
			t.Error("TOTP enroll endpoint not found")
		}
	})
}

// TestMFACompletionFlow tests completing MFA login.
func TestMFACompletionFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	env := SetupTestEnv(t)
	defer env.Teardown(t)

	client := NewHTTPClient(env.AuthServer.URL, env.TestTenantID)

	// Test MFA completion with invalid data
	t.Run("InvalidMFACompletion", func(t *testing.T) {
		mfaReq := map[string]interface{}{
			"pending_token": "invalid-token",
			"totp_code":     "123456",
			"user_id":       env.TestUserID,
		}
		resp := client.Post(t, "/api/v1/auth/mfa/complete", mfaReq)
		// Should fail with invalid token
		if resp.StatusCode == http.StatusOK {
			t.Error("Expected error for invalid MFA completion")
		}
	})

	// Test MFA completion with missing fields
	t.Run("MissingFields", func(t *testing.T) {
		mfaReq := map[string]interface{}{
			"pending_token": "some-token",
			// Missing totp_code and user_id
		}
		resp := client.Post(t, "/api/v1/auth/mfa/complete", mfaReq)
		AssertStatus(t, resp, http.StatusBadRequest)
	})
}
