//go:build integration

package integration

import (
	"net/http"
	"testing"
)

// TestSSOProviderCRUD tests the full CRUD lifecycle for SSO providers.
func TestSSOProviderCRUD(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	env := SetupTestEnv(t)
	defer env.Teardown(t)

	client := NewHTTPClient(env.GovServer.URL, env.TestTenantID)
	var createdProviderID string

	// 1. Create SSO Provider
	t.Run("Create", func(t *testing.T) {
		createReq := map[string]interface{}{
			"name":               "Test OIDC Provider",
			"type":               "oidc",
			"oidc_client_id":     "test-client-id",
			"oidc_client_secret": "test-client-secret",
			"oidc_issuer_url":    "https://accounts.google.com",
			"enabled":            false,
		}
		resp := client.Post(t, "/api/v1/sso/providers", createReq)
		AssertStatus(t, resp, http.StatusCreated)

		var created map[string]interface{}
		ReadJSON(t, resp, &created)
		id, ok := created["id"].(string)
		if !ok || id == "" {
			t.Fatal("Expected provider ID in response")
		}
		createdProviderID = id
	})

	// 2. List SSO Providers
	t.Run("List", func(t *testing.T) {
		resp := client.Get(t, "/api/v1/sso/providers")
		AssertStatus(t, resp, http.StatusOK)

		var result map[string]interface{}
		ReadJSON(t, resp, &result)
		providers, ok := result["providers"].([]interface{})
		if !ok {
			t.Fatal("Expected providers array in response")
		}
		if len(providers) < 1 {
			t.Error("Expected at least one provider")
		}
	})

	// 3. Get SSO Provider
	t.Run("Get", func(t *testing.T) {
		if createdProviderID == "" {
			t.Skip("No provider ID from create step")
		}
		resp := client.Get(t, "/api/v1/sso/providers/"+createdProviderID)
		AssertStatus(t, resp, http.StatusOK)
	})

	// 4. Update SSO Provider
	t.Run("Update", func(t *testing.T) {
		if createdProviderID == "" {
			t.Skip("No provider ID from create step")
		}
		updateReq := map[string]interface{}{
			"name":               "Updated OIDC Provider",
			"type":               "oidc",
			"oidc_client_id":     "updated-client-id",
			"oidc_client_secret": "updated-secret",
			"oidc_issuer_url":    "https://accounts.google.com/updated",
		}
		resp := client.Put(t, "/api/v1/sso/providers/"+createdProviderID, updateReq)
		AssertStatus(t, resp, http.StatusOK)
	})

	// 5. Toggle SSO Provider
	t.Run("Toggle", func(t *testing.T) {
		if createdProviderID == "" {
			t.Skip("No provider ID from create step")
		}
		toggleReq := map[string]interface{}{
			"enabled": true,
		}
		resp := client.Post(t, "/api/v1/sso/providers/"+createdProviderID+"/toggle", toggleReq)
		AssertStatus(t, resp, http.StatusOK)
	})

	// 6. Delete SSO Provider
	t.Run("Delete", func(t *testing.T) {
		if createdProviderID == "" {
			t.Skip("No provider ID from create step")
		}
		resp := client.Delete(t, "/api/v1/sso/providers/"+createdProviderID)
		AssertStatus(t, resp, http.StatusNoContent)
	})
}

// TestSSOProviderTypeFilter tests filtering SSO providers by type.
func TestSSOProviderTypeFilter(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	env := SetupTestEnv(t)
	defer env.Teardown(t)

	client := NewHTTPClient(env.GovServer.URL, env.TestTenantID)

	// Filter by OIDC type
	t.Run("FilterByType", func(t *testing.T) {
		resp := client.Get(t, "/api/v1/sso/providers?type=oidc")
		AssertStatus(t, resp, http.StatusOK)

		var result map[string]interface{}
		ReadJSON(t, resp, &result)
		if _, ok := result["providers"]; !ok {
			t.Fatal("Expected providers array in response")
		}
	})
}
