package governance

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// DirectoryClient provides methods to interact with the Directory Service.
type DirectoryClient interface {
	AddUserToGroup(ctx context.Context, tenantID, userID, groupID string) error
	RemoveUserFromGroup(ctx context.Context, tenantID, userID, groupID string) error
}

type directoryHTTPClient struct {
	baseURL    string
	httpClient *http.Client
}

// NewDirectoryClient creates a new client for the Directory Service.
func NewDirectoryClient(baseURL string) DirectoryClient {
	return &directoryHTTPClient{
		baseURL:    baseURL,
		httpClient: &http.Client{},
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
