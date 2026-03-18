package sso

import (
	"context"
	"fmt"
)

// Service defines SSO provider service operations.
type Service interface {
	CreateProvider(ctx context.Context, tenantID string, p Provider) (string, error)
	GetProvider(ctx context.Context, tenantID, id string) (Provider, error)
	ListProviders(ctx context.Context, tenantID string, providerType *ProviderType) ([]Provider, error)
	UpdateProvider(ctx context.Context, tenantID string, p Provider) error
	DeleteProvider(ctx context.Context, tenantID, id string) error
	ToggleProvider(ctx context.Context, tenantID, id string, enabled bool) error
}

type service struct {
	store Repository
}

// NewService creates a new SSO service.
func NewService(store Repository) Service {
	return &service{store: store}
}

func (s *service) CreateProvider(ctx context.Context, tenantID string, p Provider) (string, error) {
	if p.Name == "" {
		return "", fmt.Errorf("provider name is required")
	}
	if p.Type != ProviderTypeOIDC && p.Type != ProviderTypeSAML {
		return "", fmt.Errorf("invalid provider type: %s", p.Type)
	}

	// Validate type-specific fields
	if p.Type == ProviderTypeOIDC {
		if p.OIDCIssuerURL == nil || *p.OIDCIssuerURL == "" {
			return "", fmt.Errorf("OIDC issuer URL is required")
		}
		if p.OIDCClientID == nil || *p.OIDCClientID == "" {
			return "", fmt.Errorf("OIDC client ID is required")
		}
	}
	if p.Type == ProviderTypeSAML {
		if p.SAMLEntityID == nil || *p.SAMLEntityID == "" {
			return "", fmt.Errorf("SAML entity ID is required")
		}
		if p.SAMLSSOURL == nil || *p.SAMLSSOURL == "" {
			return "", fmt.Errorf("SAML SSO URL is required")
		}
	}

	p.TenantID = tenantID
	p.Enabled = true
	return s.store.Create(ctx, p)
}

func (s *service) GetProvider(ctx context.Context, tenantID, id string) (Provider, error) {
	return s.store.Get(ctx, tenantID, id)
}

func (s *service) ListProviders(ctx context.Context, tenantID string, providerType *ProviderType) ([]Provider, error) {
	return s.store.List(ctx, tenantID, providerType)
}

func (s *service) UpdateProvider(ctx context.Context, tenantID string, p Provider) error {
	existing, err := s.store.Get(ctx, tenantID, p.ID)
	if err != nil {
		return fmt.Errorf("provider not found: %w", err)
	}

	// Can't change type
	if p.Type != existing.Type {
		return fmt.Errorf("cannot change provider type")
	}

	p.TenantID = tenantID
	return s.store.Update(ctx, p)
}

func (s *service) DeleteProvider(ctx context.Context, tenantID, id string) error {
	return s.store.Delete(ctx, tenantID, id)
}

func (s *service) ToggleProvider(ctx context.Context, tenantID, id string, enabled bool) error {
	p, err := s.store.Get(ctx, tenantID, id)
	if err != nil {
		return err
	}
	p.Enabled = enabled
	return s.store.Update(ctx, p)
}
