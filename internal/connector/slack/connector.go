package slack

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/dhawalhost/wardseal/internal/connector/model"
)

// Connector implements the model.Connector interface for Slack.
type Connector struct {
	config     model.Config
	httpClient *http.Client
}

// New creates a new Slack connector.
func New(config model.Config) (model.Connector, error) {
	return &Connector{
		config: config,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}, nil
}

func (c *Connector) ID() string   { return c.config.ID }
func (c *Connector) Name() string { return c.config.Name }
func (c *Connector) Type() string { return "slack" }

func (c *Connector) Initialize(ctx context.Context, config model.Config) error {
	c.config = config
	return nil
}

func (c *Connector) HealthCheck(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://slack.com/api/auth.test", nil)
	if err != nil {
		return err
	}
	c.setHeaders(req)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	var result struct {
		OK bool `json:"ok"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&result)
	if !result.OK {
		return fmt.Errorf("slack auth.test failed")
	}
	return nil
}

func (c *Connector) Close() error { return nil }

// User operations
func (c *Connector) CreateUser(ctx context.Context, user model.User) (string, error) {
	// Slack usually uses SCIM for user creation or invitations.
	// For this specialized connector, we use the 'admin.users.invite' or similar if enterprise.
	// For standard workspaces, we might use 'users.admin.invite' (legacy).
	// Here, we'll implement a 'SCIM-like' push via Slack's SCIM API endpoint if configured,
	// or fallback to standard web API for 'lookup and verify'.

	// Implementation note: Most enterprise Slack outbound sync happens via SCIM 2.0.
	// We will implement the SCIM endpoint logic but with Slack-specific extensions.

	endpoint := "https://api.slack.com/scim/v2/Users"
	if c.config.Endpoint != "" {
		endpoint = c.config.Endpoint + "/Users"
	}

	scimUser := map[string]interface{}{
		"schemas":  []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"userName": user.Username,
		"name": map[string]string{
			"givenName":  user.FirstName,
			"familyName": user.LastName,
		},
		"emails": []map[string]interface{}{
			{"value": user.Email, "primary": true},
		},
		"active": user.Active,
	}

	body, _ := json.Marshal(scimUser)
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("slack user creation failed: %s", string(respBody))
	}

	var result struct {
		ID string `json:"id"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&result)
	return result.ID, nil
}

func (c *Connector) GetUser(ctx context.Context, id string) (model.User, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://slack.com/api/users.info?user="+id, nil)
	if err != nil {
		return model.User{}, err
	}
	c.setHeaders(req)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return model.User{}, err
	}
	defer func() { _ = resp.Body.Close() }()

	var result struct {
		OK   bool `json:"ok"`
		User struct {
			ID      string `json:"id"`
			Name    string `json:"name"`
			Profile struct {
				Email string `json:"email"`
			} `json:"profile"`
			Deleted bool `json:"deleted"`
		} `json:"user"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&result)
	if !result.OK {
		return model.User{}, fmt.Errorf("slack user info failed")
	}

	return model.User{
		ExternalID: result.User.ID,
		Username:   result.User.Name,
		Email:      result.User.Profile.Email,
		Active:     !result.User.Deleted,
	}, nil
}

func (c *Connector) UpdateUser(ctx context.Context, id string, user model.User) error {
	// Use PATCH for partial updates (standard for Slack SCIM)
	endpoint := "https://api.slack.com/scim/v2/Users/" + id

	patch := map[string]interface{}{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []map[string]interface{}{
			{
				"op": "replace",
				"value": map[string]interface{}{
					"active": user.Active,
				},
			},
		},
	}

	body, _ := json.Marshal(patch)
	req, err := http.NewRequestWithContext(ctx, "PATCH", endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	return nil
}

func (c *Connector) DeleteUser(ctx context.Context, id string) error {
	// In Slack, 'delete' usually means 'deactivate'
	return c.UpdateUser(ctx, id, model.User{Active: false})
}

func (c *Connector) ListUsers(ctx context.Context, filter string, limit, offset int) ([]model.User, int, error) {
	return nil, 0, fmt.Errorf("not implemented for slack specific connector; use SCIM base instead")
}

func (c *Connector) CreateGroup(ctx context.Context, group model.Group) (string, error) {
	return "", fmt.Errorf("use Slack Channel management for group-like operations")
}

func (c *Connector) GetGroup(ctx context.Context, id string) (model.Group, error) {
	return model.Group{}, nil
}

func (c *Connector) UpdateGroup(ctx context.Context, id string, group model.Group) error {
	return nil
}

func (c *Connector) DeleteGroup(ctx context.Context, id string) error {
	return nil
}

func (c *Connector) ListGroups(ctx context.Context, filter string, limit, offset int) ([]model.Group, int, error) {
	return nil, 0, nil
}

func (c *Connector) AddUserToGroup(ctx context.Context, userID, groupID string) error {
	// Map to 'conversations.invite' for channel management
	return nil
}

func (c *Connector) RemoveUserFromGroup(ctx context.Context, userID, groupID string) error {
	// Map to 'conversations.kick'
	return nil
}

func (c *Connector) DiscoverResources(ctx context.Context) ([]model.Resource, error) {
	// Discover Slack Channels
	return nil, nil
}

func (c *Connector) setHeaders(req *http.Request) {
	if token, ok := c.config.Credentials["token"]; ok {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
}
