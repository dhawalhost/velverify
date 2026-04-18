package governance

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/dhawalhost/gokit/circuitbreaker"
)

// DirectoryClient provides methods to interact with the Directory Service.
type DirectoryClient interface {
	// User mapping
	GetUserByID(ctx context.Context, tenantID, userID string) (User, error)
	AddUserToGroup(ctx context.Context, tenantID, userID, groupID string) error
	RemoveUserFromGroup(ctx context.Context, tenantID, userID, groupID string) error
	ResolveTenantSlug(ctx context.Context, slug string) (string, error)

	// Organization mapping
	AddUserToOrganization(ctx context.Context, tenantID, userID, orgID, role string) error
	RemoveUserFromOrganization(ctx context.Context, tenantID, userID, orgID string) error
	ListUserOrganizations(ctx context.Context, tenantID, userID string) ([]string, error)
}

type User struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

type directoryHTTPClient struct {
	baseURL    string
	httpClient *http.Client
	authHeader string
	authToken  string
	cb         *circuitbreaker.CircuitBreaker
}

// NewDirectoryClient creates a new client for the Directory Service.
func NewDirectoryClient(baseURL, authHeader, authToken string) DirectoryClient {
	return &directoryHTTPClient{
		baseURL:    baseURL,
		httpClient: &http.Client{Timeout: 5 * time.Second},
		authHeader: authHeader,
		authToken:  authToken,
		cb: circuitbreaker.New(circuitbreaker.Config{
			Name:             "directory-service",
			MaxFailures:      5,
			ResetTimeout:     30 * time.Second,
			ExecutionTimeout: 5 * time.Second,
		}),
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

	return c.cb.Execute(func() error {
		resp, err := c.httpClient.Do(req)
		if err != nil {
			return fmt.Errorf("request to dirsvc failed: %w", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode >= 300 {
			return fmt.Errorf("dirsvc returned status %d", resp.StatusCode)
		}
		return nil
	})
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

	return c.cb.Execute(func() error {
		resp, err := c.httpClient.Do(req)
		if err != nil {
			return fmt.Errorf("request to dirsvc failed: %w", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode >= 300 {
			return fmt.Errorf("dirsvc returned status %d", resp.StatusCode)
		}
		return nil
	})
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

	var resTenantID string
	err = c.cb.Execute(func() error {
		resp, err := c.httpClient.Do(req)
		if err != nil {
			return fmt.Errorf("request to dirsvc failed: %w", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode == http.StatusNotFound {
			return nil // Not found
		}

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("dirsvc returned status %d", resp.StatusCode)
		}

		var res struct {
			TenantID string `json:"tenant_id"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
			return fmt.Errorf("failed to decode response: %w", err)
		}
		resTenantID = res.TenantID
		return nil
	})

	return resTenantID, err
}

func (c *directoryHTTPClient) AddUserToOrganization(ctx context.Context, tenantID, userID, orgID, role string) error {
	url := fmt.Sprintf("%s/users/%s/organizations/%s", c.baseURL, userID, orgID)
	body, _ := json.Marshal(map[string]string{"role": role})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", tenantID)
	if c.authToken != "" {
		req.Header.Set(c.authHeader, c.authToken)
	}
	
	return c.cb.Execute(func() error {
		resp, err := c.httpClient.Do(req)
		if err != nil {
			return err
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode >= 300 {
			return fmt.Errorf("dirsvc returned status %d", resp.StatusCode)
		}
		return nil
	})
}

func (c *directoryHTTPClient) RemoveUserFromOrganization(ctx context.Context, tenantID, userID, orgID string) error {
	url := fmt.Sprintf("%s/users/%s/organizations/%s", c.baseURL, userID, orgID)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-Tenant-ID", tenantID)
	if c.authToken != "" {
		req.Header.Set(c.authHeader, c.authToken)
	}

	return c.cb.Execute(func() error {
		resp, err := c.httpClient.Do(req)
		if err != nil {
			return err
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode >= 300 {
			return fmt.Errorf("dirsvc returned status %d", resp.StatusCode)
		}
		return nil
	})
}

func (c *directoryHTTPClient) ListUserOrganizations(ctx context.Context, tenantID, userID string) ([]string, error) {
	url := fmt.Sprintf("%s/users/%s/organizations", c.baseURL, userID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Tenant-ID", tenantID)
	if c.authToken != "" {
		req.Header.Set(c.authHeader, c.authToken)
	}

	var orgIDs []string
	err = c.cb.Execute(func() error {
		resp, err := c.httpClient.Do(req)
		if err != nil {
			return err
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("dirsvc returned status %d", resp.StatusCode)
		}
		var res struct {
			OrganizationIDs []string `json:"organization_ids"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
			return err
		}
		orgIDs = res.OrganizationIDs
		return nil
	})

	return orgIDs, err
}

func (c *directoryHTTPClient) GetUserByID(ctx context.Context, tenantID, userID string) (User, error) {
	url := fmt.Sprintf("%s/users/%s", c.baseURL, userID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return User{}, err
	}
	req.Header.Set("X-Tenant-ID", tenantID)
	if c.authToken != "" {
		req.Header.Set(c.authHeader, c.authToken)
	}

	var user User
	err = c.cb.Execute(func() error {
		resp, err := c.httpClient.Do(req)
		if err != nil {
			return err
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("dirsvc returned status %d", resp.StatusCode)
		}
		if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
			return err
		}
		return nil
	})

	return user, err
}
