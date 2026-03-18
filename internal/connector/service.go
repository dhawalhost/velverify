package connector

import (
	"context"
	"fmt"
)

// Service defines connector service operations.
type Service interface {
	CreateConnector(ctx context.Context, tenantID string, config Config) (string, error)
	GetConnector(ctx context.Context, tenantID, id string) (Config, error)
	ListConnectors(ctx context.Context, tenantID string) ([]Config, error)
	UpdateConnector(ctx context.Context, tenantID string, config Config) error
	DeleteConnector(ctx context.Context, tenantID, id string) error
	ToggleConnector(ctx context.Context, tenantID, id string, enabled bool) error
	TestConnection(ctx context.Context, config Config) error
}

type service struct {
	store    Repository
	registry Registry
}

// NewService creates a new connector service.
func NewService(store Repository, registry Registry) Service {
	return &service{store: store, registry: registry}
}

func (s *service) CreateConnector(ctx context.Context, tenantID string, config Config) (string, error) {
	if config.Name == "" {
		return "", fmt.Errorf("connector name is required")
	}
	if config.Type == "" {
		return "", fmt.Errorf("connector type is required")
	}

	config.TenantID = tenantID
	config.Enabled = true
	id, err := s.store.Create(ctx, config)
	if err != nil {
		return "", err
	}
	config.ID = id

	// Initialize and register with registry if enabled
	if config.Enabled {
		if _, err := s.registry.Create(config.Type, config); err != nil {
			// Log error but don't fail creation - connector may be created but marked unhealthy
			_ = err // Intentionally ignored
		}
	}

	return id, nil
}

func (s *service) GetConnector(ctx context.Context, tenantID, id string) (Config, error) {
	return s.store.Get(ctx, tenantID, id)
}

func (s *service) ListConnectors(ctx context.Context, tenantID string) ([]Config, error) {
	return s.store.List(ctx, tenantID)
}

func (s *service) UpdateConnector(ctx context.Context, tenantID string, config Config) error {
	existing, err := s.store.Get(ctx, tenantID, config.ID)
	if err != nil {
		return fmt.Errorf("connector not found: %w", err)
	}

	// Preserve credentials if not updated
	if len(config.Credentials) == 0 {
		config.Credentials = existing.Credentials
	} else {
		// Merge specific credentials if partially updated
		for k, v := range existing.Credentials {
			if _, ok := config.Credentials[k]; !ok {
				config.Credentials[k] = v
			}
		}
	}

	config.TenantID = tenantID
	if err := s.store.Update(ctx, config); err != nil {
		return err
	}

	// Refresh in registry
	_ = s.registry.Remove(config.ID)
	if config.Enabled {
		_, _ = s.registry.Create(config.Type, config)
	}

	return nil
}

func (s *service) DeleteConnector(ctx context.Context, tenantID, id string) error {
	if err := s.store.Delete(ctx, tenantID, id); err != nil {
		return err
	}
	_ = s.registry.Remove(id)
	return nil
}

func (s *service) ToggleConnector(ctx context.Context, tenantID, id string, enabled bool) error {
	if err := s.store.Toggle(ctx, tenantID, id, enabled); err != nil {
		return err
	}

	if enabled {
		config, err := s.store.Get(ctx, tenantID, id)
		if err == nil {
			_, _ = s.registry.Create(config.Type, config)
		}
	} else {
		_ = s.registry.Remove(id)
	}
	return nil
}

func (s *service) TestConnection(ctx context.Context, config Config) error {
	// Create a temporary connector instance
	conn, err := s.registry.Create(config.Type, config)
	if err != nil {
		return fmt.Errorf("failed to create connector: %w", err)
	}
	// Don't keep it in the registry
	defer func() { _ = s.registry.Remove(config.ID) }()

	return conn.HealthCheck(ctx)
}
