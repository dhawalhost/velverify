package auth

import "context"

func (s *authService) GetBranding(ctx context.Context, tenantID string) (BrandingConfig, error) {
	if s.brandingStore == nil {
		// Fallback for when store is not initialized (e.g. tests)
		return BrandingConfig{TenantID: tenantID}, nil
	}
	
	config, err := s.brandingStore.Get(ctx, tenantID)
	if err != nil {
		return BrandingConfig{}, err
	}

	// Enrich with tenant details if store is available
	if s.tenantStore != nil {
		slug, name, err := s.tenantStore.GetDetailsByID(ctx, tenantID)
		if err == nil {
			config.TenantSlug = slug
			config.TenantName = name
		}
	}

	return config, nil
}

func (s *authService) UpdateBranding(ctx context.Context, config BrandingConfig) error {
	if s.brandingStore == nil {
		return nil
	}
	return s.brandingStore.Upsert(ctx, config)
}
