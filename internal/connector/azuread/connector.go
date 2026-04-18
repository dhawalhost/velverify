package azuread

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dhawalhost/wardseal/internal/connector"
)

const (
	graphBaseURL = "https://graph.microsoft.com/v1.0"
	loginURL     = "https://login.microsoftonline.com"
)

// Connector implements the connector.Connector interface for Azure AD via Microsoft Graph.
type Connector struct {
	config      connector.Config
	httpClient  *http.Client
	accessToken string
	tokenExpiry time.Time
}

// New creates a new Azure AD connector.
func New(config connector.Config) (connector.Connector, error) {
	return &Connector{
		config: config,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}, nil
}

func (c *Connector) ID() string   { return c.config.ID }
func (c *Connector) Name() string { return c.config.Name }
func (c *Connector) Type() string { return "azure-ad" }

func (c *Connector) Initialize(ctx context.Context, config connector.Config) error {
	c.config = config
	return c.authenticate(ctx)
}

func (c *Connector) authenticate(ctx context.Context) error {
	tenantID := c.config.Credentials["tenant_id"]
	clientID := c.config.Credentials["client_id"]
	clientSecret := c.config.Credentials["client_secret"]

	tokenURL := fmt.Sprintf("%s/%s/oauth2/v2.0/token", loginURL, tenantID)

	data := url.Values{}
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)
	data.Set("scope", "https://graph.microsoft.com/.default")
	data.Set("grant_type", "client_credentials")

	req, _ := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	defer func() { _ = resp.Body.Close() }()

	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("authentication failed: %s", string(body))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return err
	}

	c.accessToken = tokenResp.AccessToken
	c.tokenExpiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn-60) * time.Second)
	return nil
}

func (c *Connector) ensureAuthenticated(ctx context.Context) error {
	if time.Now().After(c.tokenExpiry) {
		return c.authenticate(ctx)
	}
	return nil
}

func (c *Connector) HealthCheck(ctx context.Context) error {
	if err := c.ensureAuthenticated(ctx); err != nil {
		return err
	}
	req, _ := http.NewRequestWithContext(ctx, "GET", graphBaseURL+"/organization", nil)
	c.setHeaders(req)
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
	if err := c.ensureAuthenticated(ctx); err != nil {
		return "", err
	}

	userData := map[string]interface{}{
		"accountEnabled":    user.Active,
		"displayName":       user.DisplayName,
		"mailNickname":      user.Username,
		"userPrincipalName": user.Email,
		"givenName":         user.FirstName,
		"surname":           user.LastName,
		"passwordProfile": map[string]interface{}{
			"forceChangePasswordNextSignIn": true,
			"password":                      generateTempPassword(),
		},
	}
	body, _ := json.Marshal(userData)

	req, _ := http.NewRequestWithContext(ctx, "POST", graphBaseURL+"/users", bytes.NewReader(body))
	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	defer func() { _ = resp.Body.Close() }()

	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("create user failed: %s", string(respBody))
	}

	var result graphUserResponse
	_ = json.NewDecoder(resp.Body).Decode(&result)
	return result.ID, nil
}

func (c *Connector) GetUser(ctx context.Context, id string) (connector.User, error) {
	if err := c.ensureAuthenticated(ctx); err != nil {
		return connector.User{}, err
	}

	req, _ := http.NewRequestWithContext(ctx, "GET", graphBaseURL+"/users/"+id, nil)
	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	defer func() { _ = resp.Body.Close() }()

	if err != nil {
		return connector.User{}, err
	}

	if resp.StatusCode == http.StatusNotFound {
		return connector.User{}, fmt.Errorf("user not found")
	}

	var result graphUserResponse
	_ = json.NewDecoder(resp.Body).Decode(&result)
	return fromGraphUser(result), nil
}

func (c *Connector) UpdateUser(ctx context.Context, id string, user connector.User) error {
	if err := c.ensureAuthenticated(ctx); err != nil {
		return err
	}

	userData := map[string]interface{}{}
	if user.DisplayName != "" {
		userData["displayName"] = user.DisplayName
	}
	if user.FirstName != "" {
		userData["givenName"] = user.FirstName
	}
	if user.LastName != "" {
		userData["surname"] = user.LastName
	}
	userData["accountEnabled"] = user.Active

	body, _ := json.Marshal(userData)
	req, _ := http.NewRequestWithContext(ctx, "PATCH", graphBaseURL+"/users/"+id, bytes.NewReader(body))
	c.setHeaders(req)

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
	if err := c.ensureAuthenticated(ctx); err != nil {
		return err
	}

	req, _ := http.NewRequestWithContext(ctx, "DELETE", graphBaseURL+"/users/"+id, nil)
	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	defer func() { _ = resp.Body.Close() }()

	if err != nil {
		return err
	}
	return nil
}

func (c *Connector) ListUsers(ctx context.Context, filter string, limit, offset int) ([]connector.User, int, error) {
	if err := c.ensureAuthenticated(ctx); err != nil {
		return nil, 0, err
	}

	url := fmt.Sprintf("%s/users?$top=%d&$skip=%d", graphBaseURL, limit, offset)
	if filter != "" {
		url += "&$filter=" + filter
	}

	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	defer func() { _ = resp.Body.Close() }()

	if err != nil {
		return nil, 0, err
	}

	var result struct {
		Value []graphUserResponse `json:"value"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&result)

	users := make([]connector.User, len(result.Value))
	for i, u := range result.Value {
		users[i] = fromGraphUser(u)
	}
	return users, len(users), nil // Graph doesn't return total easily
}

// Group operations
func (c *Connector) CreateGroup(ctx context.Context, group connector.Group) (string, error) {
	if err := c.ensureAuthenticated(ctx); err != nil {
		return "", err
	}

	graphGroup := map[string]interface{}{
		"displayName":     group.Name,
		"description":     group.Description,
		"mailEnabled":     false,
		"mailNickname":    strings.ReplaceAll(group.Name, " ", ""),
		"securityEnabled": true,
	}
	body, _ := json.Marshal(graphGroup)

	req, _ := http.NewRequestWithContext(ctx, "POST", graphBaseURL+"/groups", bytes.NewReader(body))
	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	defer func() { _ = resp.Body.Close() }()

	if err != nil {
		return "", err
	}

	var result struct {
		ID string `json:"id"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&result)
	return result.ID, nil
}

func (c *Connector) GetGroup(ctx context.Context, id string) (connector.Group, error) {
	if err := c.ensureAuthenticated(ctx); err != nil {
		return connector.Group{}, err
	}

	req, _ := http.NewRequestWithContext(ctx, "GET", graphBaseURL+"/groups/"+id, nil)
	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	defer func() { _ = resp.Body.Close() }()

	if err != nil {
		return connector.Group{}, err
	}

	var result struct {
		ID          string `json:"id"`
		DisplayName string `json:"displayName"`
		Description string `json:"description"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&result)
	return connector.Group{
		ExternalID:  result.ID,
		Name:        result.DisplayName,
		Description: result.Description,
	}, nil
}

func (c *Connector) UpdateGroup(ctx context.Context, id string, group connector.Group) error {
	if err := c.ensureAuthenticated(ctx); err != nil {
		return err
	}

	data := map[string]interface{}{
		"displayName": group.Name,
		"description": group.Description,
	}
	body, _ := json.Marshal(data)

	req, _ := http.NewRequestWithContext(ctx, "PATCH", graphBaseURL+"/groups/"+id, bytes.NewReader(body))
	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	defer func() { _ = resp.Body.Close() }()

	if err != nil {
		return err
	}
	return nil
}

func (c *Connector) DeleteGroup(ctx context.Context, id string) error {
	if err := c.ensureAuthenticated(ctx); err != nil {
		return err
	}

	req, _ := http.NewRequestWithContext(ctx, "DELETE", graphBaseURL+"/groups/"+id, nil)
	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	defer func() { _ = resp.Body.Close() }()

	if err != nil {
		return err
	}
	return nil
}

func (c *Connector) ListGroups(ctx context.Context, filter string, limit, offset int) ([]connector.Group, int, error) {
	if err := c.ensureAuthenticated(ctx); err != nil {
		return nil, 0, err
	}

	url := fmt.Sprintf("%s/groups?$top=%d&$skip=%d", graphBaseURL, limit, offset)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	defer func() { _ = resp.Body.Close() }()

	if err != nil {
		return nil, 0, err
	}

	var result struct {
		Value []struct {
			ID          string `json:"id"`
			DisplayName string `json:"displayName"`
			Description string `json:"description"`
		} `json:"value"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&result)

	groups := make([]connector.Group, len(result.Value))
	for i, g := range result.Value {
		groups[i] = connector.Group{
			ExternalID:  g.ID,
			Name:        g.DisplayName,
			Description: g.Description,
		}
	}
	return groups, len(groups), nil
}

func (c *Connector) AddUserToGroup(ctx context.Context, userID, groupID string) error {
	if err := c.ensureAuthenticated(ctx); err != nil {
		return err
	}

	data := map[string]string{
		"@odata.id": fmt.Sprintf("%s/directoryObjects/%s", graphBaseURL, userID),
	}
	body, _ := json.Marshal(data)

	req, _ := http.NewRequestWithContext(ctx, "POST",
		fmt.Sprintf("%s/groups/%s/members/$ref", graphBaseURL, groupID),
		bytes.NewReader(body))
	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	defer func() { _ = resp.Body.Close() }()

	if err != nil {
		return err
	}
	return nil
}

func (c *Connector) RemoveUserFromGroup(ctx context.Context, userID, groupID string) error {
	if err := c.ensureAuthenticated(ctx); err != nil {
		return err
	}

	req, _ := http.NewRequestWithContext(ctx, "DELETE",
		fmt.Sprintf("%s/groups/%s/members/%s/$ref", graphBaseURL, groupID, userID), nil)
	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	defer func() { _ = resp.Body.Close() }()

	if err != nil {
		return err
	}
	return nil
}

func (c *Connector) GetGroupMembers(ctx context.Context, groupID string) ([]connector.User, error) {
	if err := c.ensureAuthenticated(ctx); err != nil {
		return nil, err
	}

	req, _ := http.NewRequestWithContext(ctx, "GET",
		fmt.Sprintf("%s/groups/%s/members", graphBaseURL, groupID), nil)
	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	defer func() { _ = resp.Body.Close() }()

	if err != nil {
		return nil, err
	}

	var result struct {
		Value []graphUserResponse `json:"value"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&result)

	users := make([]connector.User, len(result.Value))
	for i, u := range result.Value {
		users[i] = fromGraphUser(u)
	}
	return users, nil
}

func (c *Connector) DiscoverResources(ctx context.Context) ([]connector.Resource, error) {
	// Future implementation: Discover Azure AD Registered Apps and Groups as resources
	return []connector.Resource{}, nil
}

func (c *Connector) setHeaders(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+c.accessToken)
	req.Header.Set("Content-Type", "application/json")
}

type graphUserResponse struct {
	ID                string `json:"id"`
	DisplayName       string `json:"displayName"`
	GivenName         string `json:"givenName"`
	Surname           string `json:"surname"`
	UserPrincipalName string `json:"userPrincipalName"`
	Mail              string `json:"mail"`
	AccountEnabled    bool   `json:"accountEnabled"`
}

func fromGraphUser(u graphUserResponse) connector.User {
	email := u.Mail
	if email == "" {
		email = u.UserPrincipalName
	}
	return connector.User{
		ExternalID:  u.ID,
		Username:    u.UserPrincipalName,
		Email:       email,
		FirstName:   u.GivenName,
		LastName:    u.Surname,
		DisplayName: u.DisplayName,
		Active:      u.AccountEnabled,
	}
}

func generateTempPassword() string {
	return "TempP@ss123!" // In production, generate secure random password
}
