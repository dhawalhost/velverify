package google

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/dhawalhost/wardseal/internal/connector"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const (
	adminAPIBase = "https://admin.googleapis.com/admin/directory/v1"
)

// Connector implements the connector.Connector interface for Google Workspace.
type Connector struct {
	config     connector.Config
	httpClient *http.Client
	domain     string
}

// New creates a new Google Workspace connector.
func New(config connector.Config) (connector.Connector, error) {
	return &Connector{
		config: config,
		domain: config.Settings["domain"],
	}, nil
}

func (c *Connector) ID() string   { return c.config.ID }
func (c *Connector) Name() string { return c.config.Name }
func (c *Connector) Type() string { return "google" }

func (c *Connector) Initialize(ctx context.Context, config connector.Config) error {
	c.config = config
	c.domain = config.Settings["domain"]
	return c.authenticate(ctx)
}

func (c *Connector) authenticate(ctx context.Context) error {
	// Service account JSON credentials
	credJSON := c.config.Credentials["service_account_json"]
	adminEmail := c.config.Credentials["admin_email"]

	creds, err := google.CredentialsFromJSON(ctx, []byte(credJSON),
		"https://www.googleapis.com/auth/admin.directory.user",
		"https://www.googleapis.com/auth/admin.directory.group",
	)
	if err != nil {
		return fmt.Errorf("failed to parse credentials: %w", err)
	}

	// For domain-wide delegation, we need to impersonate an admin
	if adminEmail != "" {
		config, err := google.JWTConfigFromJSON([]byte(credJSON),
			"https://www.googleapis.com/auth/admin.directory.user",
			"https://www.googleapis.com/auth/admin.directory.group",
		)
		if err != nil {
			return fmt.Errorf("failed to parse JWT config: %w", err)
		}
		config.Subject = adminEmail
		c.httpClient = config.Client(ctx)
	} else {
		c.httpClient = oauth2.NewClient(ctx, creds.TokenSource)
	}

	return nil
}

func (c *Connector) HealthCheck(ctx context.Context) error {
	req, _ := http.NewRequestWithContext(ctx, "GET",
		fmt.Sprintf("%s/users?domain=%s&maxResults=1", adminAPIBase, c.domain), nil)

	resp, err := c.httpClient.Do(req)
	defer func() { _ = resp.Body.Close() }()

	if err != nil {
		return err
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("health check failed: %d", resp.StatusCode)
	}
	return nil
}

func (c *Connector) Close() error { return nil }

// User operations
func (c *Connector) CreateUser(ctx context.Context, user connector.User) (string, error) {
	userData := map[string]interface{}{
		"primaryEmail": user.Email,
		"name": map[string]string{
			"givenName":  user.FirstName,
			"familyName": user.LastName,
		},
		"suspended": !user.Active,
		"password":  generateTempPassword(),
	}
	body, _ := json.Marshal(userData)

	req, _ := http.NewRequestWithContext(ctx, "POST", adminAPIBase+"/users", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	defer func() { _ = resp.Body.Close() }()

	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("create user failed: %s", string(respBody))
	}

	var result googleUserResponse
	_ = json.NewDecoder(resp.Body).Decode(&result)
	return result.ID, nil
}

func (c *Connector) GetUser(ctx context.Context, id string) (connector.User, error) {
	req, _ := http.NewRequestWithContext(ctx, "GET", adminAPIBase+"/users/"+id, nil)

	resp, err := c.httpClient.Do(req)
	defer func() { _ = resp.Body.Close() }()

	if err != nil {
		return connector.User{}, err
	}

	if resp.StatusCode == http.StatusNotFound {
		return connector.User{}, fmt.Errorf("user not found")
	}

	var result googleUserResponse
	_ = json.NewDecoder(resp.Body).Decode(&result)
	return fromGoogleUser(result), nil
}

func (c *Connector) UpdateUser(ctx context.Context, id string, user connector.User) error {
	userData := map[string]interface{}{}
	if user.FirstName != "" || user.LastName != "" {
		userData["name"] = map[string]string{
			"givenName":  user.FirstName,
			"familyName": user.LastName,
		}
	}
	userData["suspended"] = !user.Active

	body, _ := json.Marshal(userData)
	req, _ := http.NewRequestWithContext(ctx, "PUT", adminAPIBase+"/users/"+id, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	defer func() { _ = resp.Body.Close() }()

	if err != nil {
		return err
	}

	if resp.StatusCode >= 400 {
		return fmt.Errorf("update user failed: %d", resp.StatusCode)
	}
	return nil
}

func (c *Connector) DeleteUser(ctx context.Context, id string) error {
	req, _ := http.NewRequestWithContext(ctx, "DELETE", adminAPIBase+"/users/"+id, nil)

	resp, err := c.httpClient.Do(req)
	defer func() { _ = resp.Body.Close() }()

	if err != nil {
		return err
	}
	return nil
}

func (c *Connector) ListUsers(ctx context.Context, filter string, limit, offset int) ([]connector.User, int, error) {
	url := fmt.Sprintf("%s/users?domain=%s&maxResults=%d", adminAPIBase, c.domain, limit)
	if filter != "" {
		url += "&query=" + filter
	}

	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)

	resp, err := c.httpClient.Do(req)
	defer func() { _ = resp.Body.Close() }()
	if err != nil {
		return nil, 0, err
	}

	var result struct {
		Users []googleUserResponse `json:"users"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&result)

	users := make([]connector.User, len(result.Users))
	for i, u := range result.Users {
		users[i] = fromGoogleUser(u)
	}
	return users, len(users), nil
}

// Group operations
func (c *Connector) CreateGroup(ctx context.Context, group connector.Group) (string, error) {
	googleGroup := map[string]string{
		"email":       fmt.Sprintf("%s@%s", group.Name, c.domain),
		"name":        group.Name,
		"description": group.Description,
	}
	body, _ := json.Marshal(googleGroup)

	req, _ := http.NewRequestWithContext(ctx, "POST", adminAPIBase+"/groups", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	var result struct {
		ID string `json:"id"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&result)
	return result.ID, nil
}

func (c *Connector) GetGroup(ctx context.Context, id string) (connector.Group, error) {
	req, _ := http.NewRequestWithContext(ctx, "GET", adminAPIBase+"/groups/"+id, nil)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return connector.Group{}, err
	}
	defer func() { _ = resp.Body.Close() }()

	var result struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&result)
	return connector.Group{
		ExternalID:  result.ID,
		Name:        result.Name,
		Description: result.Description,
	}, nil
}

func (c *Connector) UpdateGroup(ctx context.Context, id string, group connector.Group) error {
	data := map[string]string{
		"name":        group.Name,
		"description": group.Description,
	}
	body, _ := json.Marshal(data)

	req, _ := http.NewRequestWithContext(ctx, "PUT", adminAPIBase+"/groups/"+id, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	defer func() { _ = resp.Body.Close() }()
	if err != nil {
		return err
	}
	return nil
}

func (c *Connector) DeleteGroup(ctx context.Context, id string) error {
	req, _ := http.NewRequestWithContext(ctx, "DELETE", adminAPIBase+"/groups/"+id, nil)

	resp, err := c.httpClient.Do(req)
	defer func() { _ = resp.Body.Close() }()
	if err != nil {
		return err
	}
	return nil
}

func (c *Connector) ListGroups(ctx context.Context, filter string, limit, offset int) ([]connector.Group, int, error) {
	url := fmt.Sprintf("%s/groups?domain=%s&maxResults=%d", adminAPIBase, c.domain, limit)

	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = resp.Body.Close() }()

	var result struct {
		Groups []struct {
			ID          string `json:"id"`
			Name        string `json:"name"`
			Description string `json:"description"`
		} `json:"groups"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&result)

	groups := make([]connector.Group, len(result.Groups))
	for i, g := range result.Groups {
		groups[i] = connector.Group{
			ExternalID:  g.ID,
			Name:        g.Name,
			Description: g.Description,
		}
	}
	return groups, len(groups), nil
}

func (c *Connector) AddUserToGroup(ctx context.Context, userID, groupID string) error {
	member := map[string]string{
		"email": userID,
		"role":  "MEMBER",
	}
	body, _ := json.Marshal(member)

	req, _ := http.NewRequestWithContext(ctx, "POST",
		fmt.Sprintf("%s/groups/%s/members", adminAPIBase, groupID),
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	defer func() { _ = resp.Body.Close() }()

	if err != nil {
		return err
	}
	return nil
}

func (c *Connector) RemoveUserFromGroup(ctx context.Context, userID, groupID string) error {
	req, _ := http.NewRequestWithContext(ctx, "DELETE",
		fmt.Sprintf("%s/groups/%s/members/%s", adminAPIBase, groupID, userID), nil)

	resp, err := c.httpClient.Do(req)
	defer func() { _ = resp.Body.Close() }()

	if err != nil {
		return err
	}
	return nil
}

func (c *Connector) GetGroupMembers(ctx context.Context, groupID string) ([]connector.User, error) {
	req, _ := http.NewRequestWithContext(ctx, "GET",
		fmt.Sprintf("%s/groups/%s/members", adminAPIBase, groupID), nil)

	resp, err := c.httpClient.Do(req)
	defer func() { _ = resp.Body.Close() }()
	if err != nil {
		return nil, err
	}

	var result struct {
		Members []struct {
			ID    string `json:"id"`
			Email string `json:"email"`
		} `json:"members"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&result)

	users := make([]connector.User, len(result.Members))
	for i, m := range result.Members {
		users[i] = connector.User{
			ExternalID: m.ID,
			Email:      m.Email,
		}
	}
	return users, nil
}

func (c *Connector) DiscoverResources(ctx context.Context) ([]connector.Resource, error) {
	// Future implementation: Discover Google Workspace Groups and Organizational Units as resources
	return []connector.Resource{}, nil
}

type googleUserResponse struct {
	ID           string `json:"id"`
	PrimaryEmail string `json:"primaryEmail"`
	Name         struct {
		GivenName  string `json:"givenName"`
		FamilyName string `json:"familyName"`
		FullName   string `json:"fullName"`
	} `json:"name"`
	Suspended bool `json:"suspended"`
}

func fromGoogleUser(u googleUserResponse) connector.User {
	return connector.User{
		ExternalID:  u.ID,
		Username:    u.PrimaryEmail,
		Email:       u.PrimaryEmail,
		FirstName:   u.Name.GivenName,
		LastName:    u.Name.FamilyName,
		DisplayName: u.Name.FullName,
		Active:      !u.Suspended,
	}
}

func generateTempPassword() string {
	return "TempP@ss123!" + fmt.Sprintf("%d", time.Now().UnixNano()%10000)
}
