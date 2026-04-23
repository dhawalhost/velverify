package sso

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jmoiron/sqlx"
)

// ProviderType represents the SSO protocol type.
type ProviderType string

const (
	ProviderTypeOIDC ProviderType = "oidc"
	ProviderTypeSAML ProviderType = "saml"
)

// Provider represents an SSO identity provider configuration.
type Provider struct {
	ID       string       `json:"id" db:"id"`
	TenantID string       `json:"tenant_id" db:"tenant_id"`
	Name     string       `json:"name" db:"name"`
	Type     ProviderType `json:"type" db:"type"`
	Enabled  bool         `json:"enabled" db:"enabled"`

	// OIDC Configuration
	OIDCIssuerURL    *string `json:"oidc_issuer_url,omitempty" db:"oidc_issuer_url"`
	OIDCClientID     *string `json:"oidc_client_id,omitempty" db:"oidc_client_id"`
	OIDCClientSecret *string `json:"oidc_client_secret,omitempty" db:"oidc_client_secret"`
	OIDCScopes       *string `json:"oidc_scopes,omitempty" db:"oidc_scopes"`

	// SAML Configuration
	SAMLEntityID          *string `json:"saml_entity_id,omitempty" db:"saml_entity_id"`
	SAMLSSOURL            *string `json:"saml_sso_url,omitempty" db:"saml_sso_url"`
	SAMLSLOURL            *string `json:"saml_slo_url,omitempty" db:"saml_slo_url"`
	SAMLCertificate       *string `json:"saml_certificate,omitempty" db:"saml_certificate"`
	SAMLSignRequests      bool    `json:"saml_sign_requests" db:"saml_sign_requests"`
	SAMLSignAssertions    bool    `json:"saml_sign_assertions" db:"saml_sign_assertions"`
	SAMLEncryptAssertions bool    `json:"saml_encrypt_assertions" db:"saml_encrypt_assertions"`

	// Common settings
	AutoCreateUsers   bool            `json:"auto_create_users" db:"auto_create_users"`
	DefaultRoleID     *string         `json:"default_role_id,omitempty" db:"default_role_id"`
	AttributeMappings json.RawMessage `json:"attribute_mappings,omitempty" db:"attribute_mappings"`

	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// Repository defines SSO provider storage operations.
type Repository interface {
	Create(ctx context.Context, p Provider) (string, error)
	Get(ctx context.Context, tenantID, id string) (Provider, error)
	GetByName(ctx context.Context, tenantID, name string) (Provider, error)
	List(ctx context.Context, tenantID string, providerType *ProviderType) ([]Provider, error)
	Update(ctx context.Context, p Provider) error
	Delete(ctx context.Context, tenantID, id string) error
}

type sqlRepository struct {
	db *sqlx.DB
}

// NewRepository creates a new SSO provider repository.
func NewRepository(db *sqlx.DB) Repository {
	return &sqlRepository{db: db}
}

func (s *sqlRepository) Create(ctx context.Context, p Provider) (string, error) {
	var id string
	err := s.db.QueryRowxContext(ctx,
		`INSERT INTO sso_providers (tenant_id, name, type, enabled,
			oidc_issuer_url, oidc_client_id, oidc_client_secret, oidc_scopes,
			saml_entity_id, saml_sso_url, saml_slo_url, saml_certificate, saml_sign_requests, saml_sign_assertions, saml_encrypt_assertions,
			auto_create_users, default_role_id, attribute_mappings)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18) RETURNING id`,
		p.TenantID, p.Name, p.Type, p.Enabled,
		p.OIDCIssuerURL, p.OIDCClientID, p.OIDCClientSecret, p.OIDCScopes,
		p.SAMLEntityID, p.SAMLSSOURL, p.SAMLSLOURL, p.SAMLCertificate, p.SAMLSignRequests, p.SAMLSignAssertions, p.SAMLEncryptAssertions,
		p.AutoCreateUsers, p.DefaultRoleID, p.AttributeMappings,
	).Scan(&id)
	return id, err
}

func (s *sqlRepository) Get(ctx context.Context, tenantID, id string) (Provider, error) {
	var p Provider
	err := s.db.GetContext(ctx, &p,
		`SELECT * FROM sso_providers WHERE id = $1 AND tenant_id = $2`, id, tenantID)
	return p, err
}

func (s *sqlRepository) GetByName(ctx context.Context, tenantID, name string) (Provider, error) {
	var p Provider
	err := s.db.GetContext(ctx, &p,
		`SELECT * FROM sso_providers WHERE name = $1 AND tenant_id = $2`, name, tenantID)
	return p, err
}

func (s *sqlRepository) List(ctx context.Context, tenantID string, providerType *ProviderType) ([]Provider, error) {
	var providers []Provider
	query := `SELECT * FROM sso_providers WHERE tenant_id = $1`
	args := []interface{}{tenantID}

	if providerType != nil {
		query += ` AND type = $2`
		args = append(args, *providerType)
	}
	query += ` ORDER BY name`

	err := s.db.SelectContext(ctx, &providers, query, args...)
	return providers, err
}

func (s *sqlRepository) Update(ctx context.Context, p Provider) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE sso_providers SET 
			name = $1, enabled = $2,
			oidc_issuer_url = $3, oidc_client_id = $4, oidc_client_secret = $5, oidc_scopes = $6,
			saml_entity_id = $7, saml_sso_url = $8, saml_slo_url = $9, saml_certificate = $10, 
			saml_sign_requests = $11, saml_sign_assertions = $12, saml_encrypt_assertions = $13,
			auto_create_users = $14, default_role_id = $15, attribute_mappings = $16,
			updated_at = NOW()
		WHERE id = $17 AND tenant_id = $18`,
		p.Name, p.Enabled,
		p.OIDCIssuerURL, p.OIDCClientID, p.OIDCClientSecret, p.OIDCScopes,
		p.SAMLEntityID, p.SAMLSSOURL, p.SAMLSLOURL, p.SAMLCertificate, p.SAMLSignRequests, p.SAMLSignAssertions, p.SAMLEncryptAssertions,
		p.AutoCreateUsers, p.DefaultRoleID, p.AttributeMappings,
		p.ID, p.TenantID)
	return err
}

func (s *sqlRepository) Delete(ctx context.Context, tenantID, id string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM sso_providers WHERE id = $1 AND tenant_id = $2`, id, tenantID)
	return err
}
