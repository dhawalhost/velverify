package governance

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// DirectoryClient provides methods to interact with the Directory Service.
type DirectoryClient interface {
	AddUserToGroup(ctx context.Context, tenantID, userID, groupID string) error
	RemoveUserFromGroup(ctx context.Context, tenantID, userID, groupID string) error
	ResolveTenantSlug(ctx context.Context, slug string) (string, error)
}

type directoryHTTPClient struct {
	baseURL    string
	httpClient *http.Client
	authHeader string
	authToken  string
}

// NewDirectoryClient creates a new client for the Directory Service.
func NewDirectoryClient(baseURL, authHeader, authToken string) DirectoryClient {
	return &directoryHTTPClient{
		baseURL:    baseURL,
		httpClient: &http.Client{Timeout: 5 * time.Second},
		authHeader: authHeader,
		authToken:  authToken,
	}
}

func (c *directoryHTTPClient) AddUserToGroup(ctx context.Context, tenantID, userID, groupID string) error {
	url := fmt.Sprintf("%s/groups/%s/users", c.baseURL, groupID)

	body, _ := json.Marshal(map[string]string{"user_id": userID})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", tenantID)
	if c.authToken != "" {
		req.Header.Set(c.authHeader, c.authToken)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request to dirsvc failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("dirsvc returned status %d", resp.StatusCode)
	}

	return nil
}

func (c *directoryHTTPClient) RemoveUserFromGroup(ctx context.Context, tenantID, userID, groupID string) error {
	url := fmt.Sprintf("%s/groups/%s/users/%s", c.baseURL, groupID, userID)

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-Tenant-ID", tenantID)
	if c.authToken != "" {
		req.Header.Set(c.authHeader, c.authToken)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request to dirsvc failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("dirsvc returned status %d", resp.StatusCode)
	}

	return nil
}

func (c *directoryHTTPClient) ResolveTenantSlug(ctx context.Context, slug string) (string, error) {
	url := fmt.Sprintf("%s/internal/tenants/resolve?slug=%s", c.baseURL, slug)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	if c.authToken != "" {
		req.Header.Set(c.authHeader, c.authToken)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("request to dirsvc failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return "", nil // Not found
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("dirsvc returned status %d", resp.StatusCode)
	}

	var res struct {
		TenantID string `json:"tenant_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	return res.TenantID, nil
}
