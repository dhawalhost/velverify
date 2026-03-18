//go:build integration

package integration

import (
	"net/http"
	"testing"
)

// TestDirectoryHealthCheck tests the directory service health endpoint.
func TestDirectoryHealthCheck(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	env := SetupTestEnv(t)
	defer env.Teardown(t)

	client := NewHTTPClient(env.DirServer.URL, env.TestTenantID)
	resp := client.Get(t, "/health")
	AssertStatus(t, resp, http.StatusOK)

	var result map[string]interface{}
	ReadJSON(t, resp, &result)
	if result["healthy"] != true {
		t.Errorf("Expected healthy=true, got %v", result["healthy"])
	}
}

// TestUserCRUD tests the full CRUD lifecycle for users.
func TestUserCRUD(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	env := SetupTestEnv(t)
	defer env.Teardown(t)

	client := NewHTTPClient(env.DirServer.URL, env.TestTenantID)
	var createdUserID string

	// 1. Create User
	t.Run("Create", func(t *testing.T) {
		createReq := map[string]interface{}{
			"user": map[string]interface{}{
				"email":    "newuser@wardseal.com",
				"password": "SecurePassword123!",
				"status":   "active",
			},
		}
		resp := client.Post(t, "/users", createReq)
		AssertStatus(t, resp, http.StatusCreated)

		var created map[string]interface{}
		ReadJSON(t, resp, &created)
		id, ok := created["user_id"].(string)
		if !ok || id == "" {
			t.Fatal("Expected user_id in response")
		}
		createdUserID = id
		// Note: The directory service returns the User object nested or just fields?
		// CreateUserResponse only has user_id.
	})

	// 2. Get User by ID
	t.Run("GetByID", func(t *testing.T) {
		if createdUserID == "" {
			t.Skip("No user ID from create step")
		}
		resp := client.Get(t, "/users/"+createdUserID)
		AssertStatus(t, resp, http.StatusOK)

		var result map[string]interface{}
		ReadJSON(t, resp, &result)
		user, ok := result["user"].(map[string]interface{})
		if !ok {
			t.Fatal("Expected user object in response")
		}
		if user["id"] != createdUserID {
			t.Errorf("Expected id=%s, got %v", createdUserID, user["id"])
		}
	})

	// 3. Get User by Email
	t.Run("GetByEmail", func(t *testing.T) {
		resp := client.Get(t, "/users?email=newuser@wardseal.com")
		AssertStatus(t, resp, http.StatusOK)

		var result map[string]interface{}
		ReadJSON(t, resp, &result)
		user, ok := result["user"].(map[string]interface{})
		if !ok {
			t.Fatal("Expected user object in response")
		}
		if user["email"] != "newuser@wardseal.com" {
			t.Errorf("Expected email=newuser@wardseal.com, got %v", user["email"])
		}
	})

	// 4. Update User
	t.Run("Update", func(t *testing.T) {
		if createdUserID == "" {
			t.Skip("No user ID from create step")
		}
		updateReq := map[string]interface{}{
			"email":  "newuser@wardseal.com",
			"status": "inactive",
		}
		resp := client.Put(t, "/users/"+createdUserID, updateReq)
		AssertStatus(t, resp, http.StatusOK)

	})

	// 5. Delete User
	t.Run("Delete", func(t *testing.T) {
		if createdUserID == "" {
			t.Skip("No user ID from create step")
		}
		resp := client.Delete(t, "/users/"+createdUserID)
		AssertStatus(t, resp, http.StatusNoContent)

		// Verify deletion
		getResp := client.Get(t, "/users/"+createdUserID)
		AssertStatus(t, getResp, http.StatusNotFound)
	})
}

// TestGroupCRUD tests the full CRUD lifecycle for groups.
func TestGroupCRUD(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	env := SetupTestEnv(t)
	defer env.Teardown(t)

	client := NewHTTPClient(env.DirServer.URL, env.TestTenantID)
	var createdGroupID string

	// 1. Create Group
	t.Run("Create", func(t *testing.T) {
		createReq := map[string]interface{}{
			"group": map[string]interface{}{
				"name": "Test Group Unique",
			},
		}
		resp := client.Post(t, "/groups", createReq)
		AssertStatus(t, resp, http.StatusCreated)

		var created map[string]interface{}
		ReadJSON(t, resp, &created)
		id, ok := created["group_id"].(string)
		if !ok || id == "" {
			t.Fatal("Expected group_id in response")
		}
		createdGroupID = id
	})

	// 2. Get Group
	t.Run("Get", func(t *testing.T) {
		if createdGroupID == "" {
			t.Skip("No group ID from create step")
		}
		resp := client.Get(t, "/groups/"+createdGroupID)
		AssertStatus(t, resp, http.StatusOK)

		var result map[string]interface{}
		ReadJSON(t, resp, &result)
		// Based on the handler, it returns GetGroupByIDResponse { Group: group }
		groupRaw, ok := result["group"]
		if !ok {
			t.Fatalf("Expected group object in response, got: %v", result)
		}
		group := groupRaw.(map[string]interface{})
		if group["id"] != createdGroupID {
			t.Errorf("Expected id=%s, got %v", createdGroupID, group["id"])
		}
	})

	// 3. Update Group
	t.Run("Update", func(t *testing.T) {
		if createdGroupID == "" {
			t.Skip("No group ID from create step")
		}
		updateReq := map[string]interface{}{
			"name": "Updated Test Group",
		}
		resp := client.Put(t, "/groups/"+createdGroupID, updateReq)
		AssertStatus(t, resp, http.StatusOK)

	})

	// 4. Delete Group
	t.Run("Delete", func(t *testing.T) {
		if createdGroupID == "" {
			t.Skip("No group ID from create step")
		}
		resp := client.Delete(t, "/groups/"+createdGroupID)
		AssertStatus(t, resp, http.StatusNoContent)

		// Verify deletion
		getResp := client.Get(t, "/groups/"+createdGroupID)
		AssertStatus(t, getResp, http.StatusNotFound)
	})
}

// TestGroupMembership tests adding and removing users from groups.
func TestGroupMembership(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	env := SetupTestEnv(t)
	defer env.Teardown(t)

	client := NewHTTPClient(env.DirServer.URL, env.TestTenantID)

	// Create a user
	userResp := client.Post(t, "/users", map[string]interface{}{
		"user": map[string]interface{}{
			"email":    "member@wardseal.com",
			"password": "SecurePassword123!",
			"status":   "active",
		},
	})
	AssertStatus(t, userResp, http.StatusCreated)
	var createdUser map[string]interface{}
	ReadJSON(t, userResp, &createdUser)
	userID := createdUser["user_id"].(string)

	// Create a group
	groupResp := client.Post(t, "/groups", map[string]interface{}{
		"group": map[string]interface{}{
			"name":        "Membership Test Group Unique",
			"description": "Group for membership testing",
		},
	})
	AssertStatus(t, groupResp, http.StatusCreated)
	var createdGroup map[string]interface{}
	ReadJSON(t, groupResp, &createdGroup)
	groupID := createdGroup["group_id"].(string)

	// Add user to group
	t.Run("AddMember", func(t *testing.T) {
		resp := client.Post(t, "/groups/"+groupID+"/users", map[string]interface{}{
			"user_id": userID,
		})
		AssertStatus(t, resp, http.StatusNoContent)
	})

	// Remove user from group
	t.Run("RemoveMember", func(t *testing.T) {
		resp := client.Delete(t, "/groups/"+groupID+"/users/"+userID)
		AssertStatus(t, resp, http.StatusNoContent)
	})

	// Cleanup
	client.Delete(t, "/users/"+userID)
	client.Delete(t, "/groups/"+groupID)
}

// TestCredentialVerification tests the credential verification endpoint.
func TestCredentialVerification(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	env := SetupTestEnv(t)
	defer env.Teardown(t)

	client := NewHTTPClient(env.DirServer.URL, env.TestTenantID)

	// Create a user with known credentials
	userResp := client.Post(t, "/users", map[string]interface{}{
		"user": map[string]interface{}{
			"email":    "verify@wardseal.com",
			"password": "VerifyPass123!",
			"status":   "active",
		},
	})
	AssertStatus(t, userResp, http.StatusCreated)
	var createdUser map[string]interface{}
	ReadJSON(t, userResp, &createdUser)
	userID := createdUser["user_id"].(string)

	// Verify correct credentials
	t.Run("ValidCredentials", func(t *testing.T) {
		verifyReq, _ := http.NewRequest(http.MethodPost, env.DirServer.URL+"/internal/credentials/verify", mustJSON(map[string]interface{}{
			"email":    "verify@wardseal.com",
			"password": "VerifyPass123!",
		}))
		verifyReq.Header.Set("Content-Type", "application/json")
		verifyReq.Header.Set("X-Tenant-ID", env.TestTenantID)
		verifyReq.Header.Set("X-Internal-Service-Auth", "test-service-token")
		verifyResp, err := http.DefaultClient.Do(verifyReq)
		if err != nil {
			t.Fatalf("Failed to verify credentials: %v", err)
		}
		AssertStatus(t, verifyResp, http.StatusOK)
	})

	// Verify incorrect credentials
	t.Run("InvalidCredentials", func(t *testing.T) {
		verifyReq, _ := http.NewRequest(http.MethodPost, env.DirServer.URL+"/internal/credentials/verify", mustJSON(map[string]interface{}{
			"email":    "verify@wardseal.com",
			"password": "WrongPassword!",
		}))
		verifyReq.Header.Set("Content-Type", "application/json")
		verifyReq.Header.Set("X-Tenant-ID", env.TestTenantID)
		verifyReq.Header.Set("X-Internal-Service-Auth", "test-service-token")
		verifyResp, err := http.DefaultClient.Do(verifyReq)
		if err != nil {
			t.Fatalf("Failed to verify credentials: %v", err)
		}
		AssertStatus(t, verifyResp, http.StatusUnauthorized)
	})

	// Cleanup
	client.Delete(t, "/users/"+userID)
}
