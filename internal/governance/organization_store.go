package governance

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/jmoiron/sqlx"
)

// Organization represents an enterprise customer of a tenant.
type Organization struct {
	ID                          string          `db:"id" json:"id"`
	TenantID                    string          `db:"tenant_id" json:"tenant_id"`
	Name                        string          `db:"name" json:"name"`
	DisplayName                 *string         `db:"display_name" json:"display_name,omitempty"`
	Domain                      *string         `db:"domain" json:"domain,omitempty"`
	DomainVerified              bool            `db:"domain_verified" json:"domain_verified"`
	DomainVerificationToken     *string         `db:"domain_verification_token" json:"-"`
	DomainVerificationExpiresAt *time.Time      `db:"domain_verification_expires_at" json:"-"`
	Metadata                    json.RawMessage `db:"metadata" json:"metadata"`
	Settings                    json.RawMessage `db:"settings" json:"settings"`
	CreatedAt                   time.Time       `db:"created_at" json:"created_at"`
	UpdatedAt                   time.Time       `db:"updated_at" json:"updated_at"`
}

// OrganizationStore defines the interface for organization storage.
type OrganizationStore interface {
	Create(ctx context.Context, org *Organization) error
	Get(ctx context.Context, tenantID, orgID string) (*Organization, error)
	GetByName(ctx context.Context, tenantID, name string) (*Organization, error)
	List(ctx context.Context, tenantID string, limit, offset int) ([]Organization, error)
	Update(ctx context.Context, org *Organization) error
	Delete(ctx context.Context, tenantID, orgID string) error
}

type orgRepo struct {
	db *sqlx.DB
}

// NewOrganizationStore creates a new organization store.
func NewOrganizationStore(db *sqlx.DB) OrganizationStore {
	return &orgRepo{db: db}
}

func (r *orgRepo) Create(ctx context.Context, org *Organization) error {
	query := `
		INSERT INTO organizations (tenant_id, name, display_name, domain, domain_verified, metadata, settings)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, created_at, updated_at
	`
	metadata := org.Metadata
	if metadata == nil {
		metadata = json.RawMessage("{}")
	}
	settings := org.Settings
	if settings == nil {
		settings = json.RawMessage("{}")
	}
	return r.db.QueryRowxContext(ctx, query,
		org.TenantID, org.Name, org.DisplayName, org.Domain, org.DomainVerified,
		metadata, settings,
	).Scan(&org.ID, &org.CreatedAt, &org.UpdatedAt)
}

func (r *orgRepo) Get(ctx context.Context, tenantID, orgID string) (*Organization, error) {
	var org Organization
	query := `SELECT * FROM organizations WHERE tenant_id = $1 AND id = $2`
	err := r.db.GetContext(ctx, &org, query, tenantID, orgID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &org, nil
}

func (r *orgRepo) GetByName(ctx context.Context, tenantID, name string) (*Organization, error) {
	var org Organization
	query := `SELECT * FROM organizations WHERE tenant_id = $1 AND name = $2`
	err := r.db.GetContext(ctx, &org, query, tenantID, name)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &org, nil
}

func (r *orgRepo) List(ctx context.Context, tenantID string, limit, offset int) ([]Organization, error) {
	if limit <= 0 {
		limit = 50
	}
	var orgs []Organization
	query := `SELECT * FROM organizations WHERE tenant_id = $1 ORDER BY name ASC LIMIT $2 OFFSET $3`
	err := r.db.SelectContext(ctx, &orgs, query, tenantID, limit, offset)
	if err != nil {
		return nil, err
	}
	return orgs, nil
}

func (r *orgRepo) Update(ctx context.Context, org *Organization) error {
	query := `
		UPDATE organizations 
		SET name = $1, display_name = $2, domain = $3, domain_verified = $4, 
		    metadata = $5, settings = $6, updated_at = NOW()
		WHERE tenant_id = $7 AND id = $8
	`
	_, err := r.db.ExecContext(ctx, query,
		org.Name, org.DisplayName, org.Domain, org.DomainVerified,
		org.Metadata, org.Settings, org.TenantID, org.ID,
	)
	return err
}

func (r *orgRepo) Delete(ctx context.Context, tenantID, orgID string) error {
	query := `DELETE FROM organizations WHERE tenant_id = $1 AND id = $2`
	_, err := r.db.ExecContext(ctx, query, tenantID, orgID)
	return err
}
