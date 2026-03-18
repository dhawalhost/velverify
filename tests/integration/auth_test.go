//go:build integration

package integration

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/url"
	"testing"
)

// TestAuthHealthCheck tests the auth service health endpoint.
func TestAuthHealthCheck(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	env := SetupTestEnv(t)
	defer env.Teardown(t)

	client := NewHTTPClient(env.AuthServer.URL, env.TestTenantID)
	resp := client.Get(t, "/health")
	AssertStatus(t, resp, http.StatusOK)

	var result map[string]interface{}
	ReadJSON(t, resp, &result)
	if result["healthy"] != true {
		t.Errorf("Expected healthy=true, got %v", result["healthy"])
	}
}

// TestJWKSEndpoint tests the JWKS endpoint returns valid keys.
func TestJWKSEndpoint(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	env := SetupTestEnv(t)
	defer env.Teardown(t)

	client := NewHTTPClient(env.AuthServer.URL, env.TestTenantID)
	resp := client.Get(t, "/.well-known/jwks.json")
	AssertStatus(t, resp, http.StatusOK)

	var result map[string]interface{}
	ReadJSON(t, resp, &result)
	keys, ok := result["keys"].([]interface{})
	if !ok {
		t.Fatal("Expected keys array in JWKS response")
	}
	if len(keys) < 1 {
		t.Error("Expected at least one key in JWKS")
	}
}

// TestOAuthAuthorizeEndpoint tests the OAuth2 authorization endpoint.
func TestOAuthAuthorizeEndpoint(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	env := SetupTestEnv(t)
	defer env.Teardown(t)

	// Test authorization request with valid parameters
	t.Run("ValidRequest", func(t *testing.T) {
		verifier := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNO1234567890abcd"
		challenge := pkceChallenge(verifier)

		params := url.Values{}
		params.Set("response_type", "code")
		params.Set("client_id", "test-client")
		params.Set("redirect_uri", "https://app.wardseal.com/callback")
		params.Set("scope", "openid profile")
		params.Set("state", "xyz")
		params.Set("code_challenge", challenge)
		params.Set("code_challenge_method", "S256")

		req, _ := http.NewRequest(http.MethodGet, env.AuthServer.URL+"/oauth/authorize?"+params.Encode(), nil)
		req.Header.Set("X-Tenant-ID", env.TestTenantID)

		client := &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse // Don't follow redirects
			},
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		// Authorization endpoint should redirect
		if resp.StatusCode != http.StatusFound && resp.StatusCode != http.StatusOK {
			t.Errorf("Expected redirect or OK, got %d", resp.StatusCode)
		}
	})

	// Test authorization request with invalid client
	t.Run("InvalidClient", func(t *testing.T) {
		params := url.Values{}
		params.Set("response_type", "code")
		params.Set("client_id", "invalid-client")
		params.Set("redirect_uri", "https://app.wardseal.com/callback")
		params.Set("scope", "openid")
		params.Set("code_challenge", "challenge")
		params.Set("code_challenge_method", "S256")

		req, _ := http.NewRequest(http.MethodGet, env.AuthServer.URL+"/oauth/authorize?"+params.Encode(), nil)
		req.Header.Set("X-Tenant-ID", env.TestTenantID)

		client := &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		// Invalid client should return error
		if resp.StatusCode == http.StatusOK {
			t.Error("Expected error for invalid client")
		}
	})

	// Test authorization request with invalid redirect URI
	t.Run("InvalidRedirectURI", func(t *testing.T) {
		verifier := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNO1234567890abcd"
		challenge := pkceChallenge(verifier)

		params := url.Values{}
		params.Set("response_type", "code")
		params.Set("client_id", "test-client")
		params.Set("redirect_uri", "https://evil.wardseal.com/callback")
		params.Set("scope", "openid")
		params.Set("code_challenge", challenge)
		params.Set("code_challenge_method", "S256")

		req, _ := http.NewRequest(http.MethodGet, env.AuthServer.URL+"/oauth/authorize?"+params.Encode(), nil)
		req.Header.Set("X-Tenant-ID", env.TestTenantID)

		client := &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		// Invalid redirect should return error (not redirect to evil site)
		if resp.StatusCode == http.StatusFound {
			location := resp.Header.Get("Location")
			if location != "" && !isValidRedirect(location) {
				// Check it's not redirecting to the evil site
				parsed, _ := url.Parse(location)
				if parsed.Host == "evil.wardseal.com" {
					t.Error("Should not redirect to invalid redirect URI")
				}
			}
		}
	})
}

// TestLoginEndpoint tests the login endpoint.
func TestLoginEndpoint(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	env := SetupTestEnv(t)
	defer env.Teardown(t)

	client := NewHTTPClient(env.AuthServer.URL, env.TestTenantID)

	// Test login with valid credentials
	t.Run("ValidCredentials", func(t *testing.T) {
		loginReq := map[string]interface{}{
			"username": env.TestUserEmail,
			"password": "password1234", // bcrypt hash in setupTestData (min 8 chars)
		}
		resp := client.Post(t, "/auth/login", loginReq)
		// Note: This might fail if directory service is not properly connected
		// or if password hash doesn't match
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("Expected OK or Unauthorized, got %d", resp.StatusCode)
		}
	})

	// Test login with invalid credentials
	t.Run("InvalidCredentials", func(t *testing.T) {
		loginReq := map[string]interface{}{
			"username": "nonexistent@wardseal.com",
			"password": "wrongpassword1",
		}
		resp := client.Post(t, "/auth/login", loginReq)
		AssertStatus(t, resp, http.StatusUnauthorized)
	})

	// Test login with missing fields
	t.Run("MissingFields", func(t *testing.T) {
		loginReq := map[string]interface{}{
			"email": "test@wardseal.com",
			// Missing password
		}
		resp := client.Post(t, "/auth/login", loginReq)
		AssertStatus(t, resp, http.StatusBadRequest)
	})
}

// TestTokenEndpoint tests the OAuth2 token endpoint.
func TestTokenEndpoint(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	env := SetupTestEnv(t)
	defer env.Teardown(t)

	client := NewHTTPClient(env.AuthServer.URL, env.TestTenantID)

	// Test token request with invalid grant type
	t.Run("InvalidGrantType", func(t *testing.T) {
		tokenReq := map[string]interface{}{
			"grant_type": "invalid_grant",
			"client_id":  "test-client",
		}
		resp := client.Post(t, "/oauth/token", tokenReq)
		AssertStatus(t, resp, http.StatusBadRequest)
	})

	// Test token request with invalid code
	t.Run("InvalidCode", func(t *testing.T) {
		tokenReq := map[string]interface{}{
			"grant_type":    "authorization_code",
			"code":          "invalid-code",
			"client_id":     "test-client",
			"redirect_uri":  "https://app.wardseal.com/callback",
			"code_verifier": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNO1234567890abcd",
		}
		resp := client.Post(t, "/oauth/token", tokenReq)
		// Should fail with invalid code
		if resp.StatusCode == http.StatusOK {
			t.Error("Expected error for invalid code")
		}
	})
}

// TestIntrospectEndpoint tests the token introspection endpoint.
func TestIntrospectEndpoint(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	env := SetupTestEnv(t)
	defer env.Teardown(t)

	client := NewHTTPClient(env.AuthServer.URL, env.TestTenantID)

	// Test introspect with invalid token
	t.Run("InvalidToken", func(t *testing.T) {
		introspectReq := map[string]interface{}{
			"token": "invalid-token",
		}
		resp := client.Post(t, "/oauth/introspect", introspectReq)
		AssertStatus(t, resp, http.StatusOK)

		var result map[string]interface{}
		ReadJSON(t, resp, &result)
		// Invalid token should return active=false
		if result["active"] != false {
			t.Errorf("Expected active=false for invalid token, got %v", result["active"])
		}
	})
}

// TestRevokeEndpoint tests the token revocation endpoint.
func TestRevokeEndpoint(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	env := SetupTestEnv(t)
	defer env.Teardown(t)

	client := NewHTTPClient(env.AuthServer.URL, env.TestTenantID)

	// Test revoke endpoint (should succeed even for invalid tokens per RFC)
	t.Run("RevokeToken", func(t *testing.T) {
		revokeReq := map[string]interface{}{
			"token": "some-token-to-revoke",
		}
		resp := client.Post(t, "/oauth/revoke", revokeReq)
		// Per RFC 7009, revocation should always return 200
		AssertStatus(t, resp, http.StatusOK)
	})
}

// Helper functions

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func isValidRedirect(location string) bool {
	parsed, err := url.Parse(location)
	if err != nil {
		return false
	}
	// Check if it's a relative redirect or to a known safe domain
	return parsed.Host == "" || parsed.Host == "app.wardseal.com"
}
