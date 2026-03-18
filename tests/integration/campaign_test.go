//go:build integration

package integration

import (
	"net/http"
	"testing"
)

// TestCampaignCRUD tests the full CRUD lifecycle for access certification campaigns.
func TestCampaignCRUD(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	env := SetupTestEnv(t)
	defer env.Teardown(t)

	client := NewHTTPClient(env.GovServer.URL, env.TestTenantID)
	var createdCampaignID string

	// 1. Create Campaign
	t.Run("Create", func(t *testing.T) {
		createReq := map[string]interface{}{
			"name":        "Q1 Access Review",
			"description": "Quarterly access certification",
			"reviewer_id": env.TestUserID,
			"type":        "user_access",
		}
		resp := client.Post(t, "/api/v1/campaigns", createReq)
		AssertStatus(t, resp, http.StatusCreated)

		var created map[string]interface{}
		ReadJSON(t, resp, &created)
		id, ok := created["id"].(string)
		if !ok || id == "" {
			t.Fatal("Expected campaign ID in response")
		}
		createdCampaignID = id
	})

	// 2. List Campaigns
	t.Run("List", func(t *testing.T) {
		resp := client.Get(t, "/api/v1/campaigns")
		AssertStatus(t, resp, http.StatusOK)

		var result map[string]interface{}
		ReadJSON(t, resp, &result)
		campaigns, ok := result["campaigns"].([]interface{})
		if !ok {
			t.Fatal("Expected campaigns array in response")
		}
		if len(campaigns) < 1 {
			t.Error("Expected at least one campaign")
		}
	})

	// 3. Get Campaign
	t.Run("Get", func(t *testing.T) {
		if createdCampaignID == "" {
			t.Skip("No campaign ID from create step")
		}
		resp := client.Get(t, "/api/v1/campaigns/"+createdCampaignID)
		AssertStatus(t, resp, http.StatusOK)
	})

	// 4. Start Campaign
	t.Run("Start", func(t *testing.T) {
		if createdCampaignID == "" {
			t.Skip("No campaign ID from create step")
		}
		resp := client.Post(t, "/api/v1/campaigns/"+createdCampaignID+"/start", nil)
		AssertStatus(t, resp, http.StatusOK)
	})

	// 5. Complete Campaign
	t.Run("Complete", func(t *testing.T) {
		if createdCampaignID == "" {
			t.Skip("No campaign ID from create step")
		}
		resp := client.Post(t, "/api/v1/campaigns/"+createdCampaignID+"/complete", nil)
		AssertStatus(t, resp, http.StatusOK)
	})

	// 6. Delete Campaign (creates a new one for deletion test)
	t.Run("Delete", func(t *testing.T) {
		// Create a campaign to delete
		createReq := map[string]interface{}{
			"name":        "Delete Test Campaign",
			"description": "Campaign for deletion testing",
			"reviewer_id": env.TestUserID,
			"type":        "user_access",
		}
		createResp := client.Post(t, "/api/v1/campaigns", createReq)
		AssertStatus(t, createResp, http.StatusCreated)

		var created map[string]interface{}
		ReadJSON(t, createResp, &created)
		deleteID := created["id"].(string)

		resp := client.Delete(t, "/api/v1/campaigns/"+deleteID)
		AssertStatus(t, resp, http.StatusNoContent)
	})
}

// TestCampaignReviewItems tests campaign review item management.
func TestCampaignReviewItems(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	env := SetupTestEnv(t)
	defer env.Teardown(t)

	client := NewHTTPClient(env.GovServer.URL, env.TestTenantID)

	// Create a campaign
	createResp := client.Post(t, "/api/v1/campaigns", map[string]interface{}{
		"name":        "Review Items Test Campaign",
		"description": "Campaign for review item testing",
		"reviewer_id": env.TestUserID,
		"type":        "user_access",
	})
	AssertStatus(t, createResp, http.StatusCreated)

	var campaign map[string]interface{}
	ReadJSON(t, createResp, &campaign)
	campaignID := campaign["id"].(string)

	// Add review item
	t.Run("AddReviewItem", func(t *testing.T) {
		itemReq := map[string]interface{}{
			"user_id":       env.TestUserID,
			"resource_type": "application",
			"resource_id":   "00000000-0000-0000-0000-000000000777",
			"resource_name": "Test Application",
			"reviewer_id":   env.TestUserID,
		}
		resp := client.Post(t, "/api/v1/campaigns/"+campaignID+"/items", itemReq)
		AssertStatus(t, resp, http.StatusCreated)
	})

	// List pending items
	t.Run("ListPendingItems", func(t *testing.T) {
		resp := client.Get(t, "/api/v1/campaigns/"+campaignID+"/items")
		AssertStatus(t, resp, http.StatusOK)

		var result map[string]interface{}
		ReadJSON(t, resp, &result)
		if _, ok := result["items"]; !ok {
			t.Fatal("Expected items array in response")
		}
	})

	// List review items for reviewer
	t.Run("ListReviewItems", func(t *testing.T) {
		resp := client.Get(t, "/api/v1/campaigns/items?reviewer_id="+env.TestUserID)
		AssertStatus(t, resp, http.StatusOK)

		var result map[string]interface{}
		ReadJSON(t, resp, &result)
		if _, ok := result["items"]; !ok {
			t.Fatal("Expected items array in response")
		}
	})

	// Cleanup
	client.Delete(t, "/api/v1/campaigns/"+campaignID)
}

// TestCampaignCancel tests cancelling a campaign.
func TestCampaignCancel(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	env := SetupTestEnv(t)
	defer env.Teardown(t)

	client := NewHTTPClient(env.GovServer.URL, env.TestTenantID)

	// Create a campaign
	createResp := client.Post(t, "/api/v1/campaigns", map[string]interface{}{
		"name":        "Cancel Test Campaign",
		"description": "Campaign for cancel testing",
		"reviewer_id": env.TestUserID,
		"type":        "user_access",
	})
	AssertStatus(t, createResp, http.StatusCreated)

	var campaign map[string]interface{}
	ReadJSON(t, createResp, &campaign)
	campaignID := campaign["id"].(string)

	// Start and then cancel
	client.Post(t, "/api/v1/campaigns/"+campaignID+"/start", nil)

	t.Run("Cancel", func(t *testing.T) {
		resp := client.Post(t, "/api/v1/campaigns/"+campaignID+"/cancel", nil)
		AssertStatus(t, resp, http.StatusOK)
	})

	// Cleanup
	client.Delete(t, "/api/v1/campaigns/"+campaignID)
}
