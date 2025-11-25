package auth

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// ClientConfig represents a registered OAuth client.
type ClientConfig struct {
	ID            string   `json:"id"`
	TenantID      string   `json:"tenant_id"`
	Name          string   `json:"name"`
	Description   string   `json:"description,omitempty"`
	ClientType    string   `json:"client_type"`
	RedirectURIs  []string `json:"redirect_uris"`
	AllowedScopes []string `json:"allowed_scopes"`
}

func (c ClientConfig) validate() error {
	if c.ID == "" {
		return errors.New("client id is required")
	}
	if c.TenantID == "" {
		return fmt.Errorf("client %s must include tenant_id", c.ID)
	}
	if len(c.RedirectURIs) == 0 {
		return fmt.Errorf("client %s must define at least one redirect URI", c.ID)
	}
	for _, uri := range c.RedirectURIs {
		if _, err := url.ParseRequestURI(uri); err != nil {
			return fmt.Errorf("client %s has invalid redirect URI %s: %w", c.ID, uri, err)
		}
	}
	if len(c.AllowedScopes) == 0 {
		return fmt.Errorf("client %s must declare at least one scope", c.ID)
	}
	if c.ClientType != "public" && c.ClientType != "confidential" {
		return fmt.Errorf("client %s has invalid client_type %s", c.ID, c.ClientType)
	}
	return nil
}

func (c ClientConfig) allowsRedirect(redirect string) bool {
	for _, uri := range c.RedirectURIs {
		if uri == redirect {
			return true
		}
	}
	return false
}

func (c ClientConfig) validateScopes(requested string) error {
	req := strings.Fields(requested)
	allowed := make(map[string]struct{}, len(c.AllowedScopes))
	for _, scope := range c.AllowedScopes {
		allowed[scope] = struct{}{}
	}
	for _, scope := range req {
		if _, ok := allowed[scope]; !ok {
			return fmt.Errorf("scope %s is not allowed", scope)
		}
	}
	return nil
}

func (c ClientConfig) withDefaults() ClientConfig {
	if c.ClientType == "" {
		c.ClientType = "public"
	}
	return c
}

type clientKey struct {
	TenantID string
	ClientID string
}

func buildClientMap(clients []ClientConfig) (map[clientKey]ClientConfig, error) {
	if len(clients) == 0 {
		return nil, errors.New("at least one oauth client must be configured")
	}
	registry := make(map[clientKey]ClientConfig, len(clients))
	for _, raw := range clients {
		client := raw.withDefaults()
		if err := client.validate(); err != nil {
			return nil, err
		}
		key := clientKey{TenantID: client.TenantID, ClientID: client.ID}
		if _, exists := registry[key]; exists {
			return nil, fmt.Errorf("duplicate oauth client id %s for tenant %s", client.ID, client.TenantID)
		}
		registry[key] = client
	}
	return registry, nil
}
