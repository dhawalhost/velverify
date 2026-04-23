package scim

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

// Connector implements the model.Connector interface for SCIM 2.0 targets.
type Connector struct {
	config     model.Config
	httpClient *http.Client
}

// New creates a new SCIM connector.
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
func (c *Connector) Type() string { return "scim" }

func (c *Connector) Initialize(ctx context.Context, config model.Config) error {
	c.config = config
	return nil
}

func (c *Connector) HealthCheck(ctx context.Context) error {
	// Try to access ServiceProviderConfig
	req, err := http.NewRequestWithContext(ctx, "GET", c.config.Endpoint+"/ServiceProviderConfig", nil)
	if err != nil {
		return err
	}
	c.setHeaders(req)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("health check failed: %d", resp.StatusCode)
	}
	return nil
}

func (c *Connector) Close() error { return nil }

// User operations
func (c *Connector) CreateUser(ctx context.Context, user model.User) (string, error) {
	scimUser := toSCIMUser(user)
	body, _ := json.Marshal(scimUser)

	req, err := http.NewRequestWithContext(ctx, "POST", c.config.Endpoint+"/Users", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("create user failed: %s", string(respBody))
	}

	var result scimUserResource
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	return result.ID, nil
}

func (c *Connector) GetUser(ctx context.Context, id string) (model.User, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", c.config.Endpoint+"/Users/"+id, nil)
	if err != nil {
		return model.User{}, err
	}
	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return model.User{}, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return model.User{}, fmt.Errorf("get user failed: %d", resp.StatusCode)
	}

	var result scimUserResource
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return model.User{}, err
	}
	return fromSCIMUser(result), nil
}

func (c *Connector) UpdateUser(ctx context.Context, id string, user model.User) error {
	scimUser := toSCIMUser(user)
	body, _ := json.Marshal(scimUser)

	req, err := http.NewRequestWithContext(ctx, "PUT", c.config.Endpoint+"/Users/"+id, bytes.NewReader(body))
	if err != nil {
		return err
	}
	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("update user failed: %s", string(respBody))
	}
	return nil
}

func (c *Connector) DeleteUser(ctx context.Context, id string) error {
	req, err := http.NewRequestWithContext(ctx, "DELETE", c.config.Endpoint+"/Users/"+id, nil)
	if err != nil {
		return err
	}
	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("delete user failed: %d", resp.StatusCode)
	}
	return nil
}

func (c *Connector) ListUsers(ctx context.Context, filter string, limit, offset int) ([]model.User, int, error) {
	url := fmt.Sprintf("%s/Users?startIndex=%d&count=%d", c.config.Endpoint, offset+1, limit)
	if filter != "" {
		url += "&filter=" + filter
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, 0, err
	}
	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = resp.Body.Close() }()

	var result scimListResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, 0, err
	}

	users := make([]model.User, len(result.Resources))
	for i, r := range result.Resources {
		users[i] = fromSCIMUser(r)
	}
	return users, result.TotalResults, nil
}

// Group operations
func (c *Connector) CreateGroup(ctx context.Context, group model.Group) (string, error) {
	scimGroup := scimGroupResource{DisplayName: group.Name}
	body, _ := json.Marshal(scimGroup)

	req, err := http.NewRequestWithContext(ctx, "POST", c.config.Endpoint+"/Groups", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("create group failed: %d", resp.StatusCode)
	}

	var result scimGroupResource
	_ = json.NewDecoder(resp.Body).Decode(&result)
	return result.ID, nil
}

func (c *Connector) GetGroup(ctx context.Context, id string) (model.Group, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", c.config.Endpoint+"/Groups/"+id, nil)
	if err != nil {
		return model.Group{}, err
	}
	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return model.Group{}, err
	}
	defer func() { _ = resp.Body.Close() }()

	var result scimGroupResource
	_ = json.NewDecoder(resp.Body).Decode(&result)
	return model.Group{ExternalID: result.ID, Name: result.DisplayName}, nil
}

func (c *Connector) UpdateGroup(ctx context.Context, id string, group model.Group) error {
	scimGroup := scimGroupResource{ID: id, DisplayName: group.Name}
	body, _ := json.Marshal(scimGroup)

	req, err := http.NewRequestWithContext(ctx, "PUT", c.config.Endpoint+"/Groups/"+id, bytes.NewReader(body))
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

func (c *Connector) DeleteGroup(ctx context.Context, id string) error {
	req, err := http.NewRequestWithContext(ctx, "DELETE", c.config.Endpoint+"/Groups/"+id, nil)
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

func (c *Connector) ListGroups(ctx context.Context, filter string, limit, offset int) ([]model.Group, int, error) {
	url := fmt.Sprintf("%s/Groups?startIndex=%d&count=%d", c.config.Endpoint, offset+1, limit)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, 0, err
	}
	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = resp.Body.Close() }()

	var result struct {
		TotalResults int                 `json:"totalResults"`
		Resources    []scimGroupResource `json:"Resources"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&result)

	groups := make([]model.Group, len(result.Resources))
	for i, r := range result.Resources {
		groups[i] = model.Group{ExternalID: r.ID, Name: r.DisplayName}
	}
	return groups, result.TotalResults, nil
}

func (c *Connector) AddUserToGroup(ctx context.Context, userID, groupID string) error {
	patch := map[string]interface{}{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []map[string]interface{}{
			{
				"op":   "add",
				"path": "members",
				"value": []map[string]string{
					{"value": userID},
				},
			},
		},
	}
	body, _ := json.Marshal(patch)

	req, err := http.NewRequestWithContext(ctx, "PATCH", c.config.Endpoint+"/Groups/"+groupID, bytes.NewReader(body))
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

func (c *Connector) RemoveUserFromGroup(ctx context.Context, userID, groupID string) error {
	patch := map[string]interface{}{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []map[string]interface{}{
			{
				"op":   "remove",
				"path": fmt.Sprintf("members[value eq \"%s\"]", userID),
			},
		},
	}
	body, _ := json.Marshal(patch)

	req, err := http.NewRequestWithContext(ctx, "PATCH", c.config.Endpoint+"/Groups/"+groupID, bytes.NewReader(body))
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

func (c *Connector) GetGroupMembers(ctx context.Context, groupID string) ([]model.User, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", c.config.Endpoint+"/Groups/"+groupID, nil)
	if err != nil {
		return nil, err
	}
	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("get group members failed: %d", resp.StatusCode)
	}

	var result scimGroupResource
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	members := make([]model.User, 0, len(result.Members))
	for _, member := range result.Members {
		if member.Value == "" {
			continue
		}
		members = append(members, model.User{
			ExternalID: member.Value,
			Username:   member.Value,
			Active:     true,
		})
	}

	return members, nil
}

func (c *Connector) DiscoverResources(ctx context.Context) ([]model.Resource, error) {
	// Future implementation: Discover SCIM Groups and Entitlements as resources
	return []model.Resource{}, nil
}

func (c *Connector) setHeaders(req *http.Request) {
	req.Header.Set("Content-Type", "application/scim+json")
	req.Header.Set("Accept", "application/scim+json")

	// Bearer token auth
	if token, ok := c.config.Credentials["token"]; ok {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	// Basic auth
	if user, ok := c.config.Credentials["username"]; ok {
		if pass, ok := c.config.Credentials["password"]; ok {
			req.SetBasicAuth(user, pass)
		}
	}
}

// SCIM types
type scimUserResource struct {
	ID       string `json:"id,omitempty"`
	UserName string `json:"userName"`
	Active   bool   `json:"active"`
	Name     struct {
		GivenName  string `json:"givenName,omitempty"`
		FamilyName string `json:"familyName,omitempty"`
	} `json:"name,omitempty"`
	Emails []struct {
		Value   string `json:"value"`
		Primary bool   `json:"primary"`
	} `json:"emails,omitempty"`
	DisplayName string `json:"displayName,omitempty"`
}

type scimGroupResource struct {
	ID          string `json:"id,omitempty"`
	DisplayName string `json:"displayName"`
	Members     []struct {
		Value string `json:"value"`
	} `json:"members,omitempty"`
}

type scimListResponse struct {
	TotalResults int                `json:"totalResults"`
	Resources    []scimUserResource `json:"Resources"`
}

func toSCIMUser(u model.User) scimUserResource {
	return scimUserResource{
		UserName:    u.Username,
		Active:      u.Active,
		DisplayName: u.DisplayName,
		Name: struct {
			GivenName  string `json:"givenName,omitempty"`
			FamilyName string `json:"familyName,omitempty"`
		}{
			GivenName:  u.FirstName,
			FamilyName: u.LastName,
		},
		Emails: []struct {
			Value   string `json:"value"`
			Primary bool   `json:"primary"`
		}{{Value: u.Email, Primary: true}},
	}
}

func fromSCIMUser(r scimUserResource) model.User {
	email := ""
	if len(r.Emails) > 0 {
		email = r.Emails[0].Value
	}
	return model.User{
		ExternalID:  r.ID,
		Username:    r.UserName,
		Email:       email,
		FirstName:   r.Name.GivenName,
		LastName:    r.Name.FamilyName,
		DisplayName: r.DisplayName,
		Active:      r.Active,
	}
}
