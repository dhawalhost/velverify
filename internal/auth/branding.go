package auth

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/jmoiron/sqlx"
)

// BrandingConfig represents the visual customization for a tenant.
type BrandingConfig struct {
	TenantID        string    `json:"tenant_id" db:"tenant_id"`
	LogoURL         string    `json:"logo_url" db:"logo_url"`
	PrimaryColor    string    `json:"primary_color" db:"primary_color"`
	BackgroundColor string    `json:"background_color" db:"background_color"`
	CSSOverride     string    `json:"css_override" db:"css_override"`
	Config          JSON      `json:"config" db:"config"`
	CreatedAt       time.Time `json:"created_at" db:"created_at"`
	UpdatedAt       time.Time `json:"updated_at" db:"updated_at"`
}

// BrandingRepository defines storage operations for branding.
type BrandingRepository interface {
	Get(ctx context.Context, tenantID string) (BrandingConfig, error)
	Upsert(ctx context.Context, config BrandingConfig) error
}

type sqlBrandingRepository struct {
	db *sqlx.DB
}

// NewBrandingRepository creates a new BrandingRepository.
func NewBrandingRepository(db *sqlx.DB) BrandingRepository {
	return &sqlBrandingRepository{db: db}
}

func (s *sqlBrandingRepository) Get(ctx context.Context, tenantID string) (BrandingConfig, error) {
	var b BrandingConfig
	err := s.db.GetContext(ctx, &b, `SELECT * FROM tenant_branding WHERE tenant_id = $1`, tenantID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// Return default config if not found
			return BrandingConfig{TenantID: tenantID}, nil
		}
		return BrandingConfig{}, err
	}
	return b, nil
}

func (s *sqlBrandingRepository) Upsert(ctx context.Context, config BrandingConfig) error {
	query := `
		INSERT INTO tenant_branding (tenant_id, logo_url, primary_color, background_color, css_override, config, updated_at)
		VALUES (:tenant_id, :logo_url, :primary_color, :background_color, :css_override, :config::jsonb, NOW())
		ON CONFLICT (tenant_id) DO UPDATE SET
			logo_url = EXCLUDED.logo_url,
			primary_color = EXCLUDED.primary_color,
			background_color = EXCLUDED.background_color,
			css_override = EXCLUDED.css_override,
			config = EXCLUDED.config,
			updated_at = NOW()
	`
	_, err := s.db.NamedExecContext(ctx, query, config)
	return err
}
