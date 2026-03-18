package auth

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/jmoiron/sqlx"
)

// FederatedIdentity represents a link between a local user and an external identity provider.
type FederatedIdentity struct {
	ID          string    `db:"id"`
	IdentityID  string    `db:"identity_id"`
	TenantID    string    `db:"tenant_id"`
	Provider    string    `db:"provider"`
	ExternalID  string    `db:"external_id"`
	ProfileData JSON      `db:"profile_data"`
	CreatedAt   time.Time `db:"created_at"`
	UpdatedAt   time.Time `db:"updated_at"`
}

// FederationRepository defines storage for federated identities.
type FederationRepository interface {
	Get(ctx context.Context, tenantID, provider, externalID string) (*FederatedIdentity, error)
	Create(ctx context.Context, identity FederatedIdentity) error
	List(ctx context.Context, identityID string) ([]FederatedIdentity, error)
	Delete(ctx context.Context, id string) error
}

type sqlFederationRepository struct {
	db *sqlx.DB
}

// NewFederationRepository creates a new FederationRepository.
func NewFederationRepository(db *sqlx.DB) FederationRepository {
	return &sqlFederationRepository{db: db}
}

func (s *sqlFederationRepository) Get(ctx context.Context, tenantID, provider, externalID string) (*FederatedIdentity, error) {
	var f FederatedIdentity
	err := s.db.GetContext(ctx, &f, `
		SELECT * FROM federated_identities 
		WHERE tenant_id = $1 AND provider = $2 AND external_id = $3
	`, tenantID, provider, externalID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &f, nil
}

func (s *sqlFederationRepository) Create(ctx context.Context, identity FederatedIdentity) error {
	query := `
		INSERT INTO federated_identities (tenant_id, identity_id, provider, external_id, profile_data, created_at, updated_at)
		VALUES (:tenant_id, :identity_id, :provider, :external_id, :profile_data, NOW(), NOW())
		RETURNING id
	`
	rows, err := s.db.NamedQueryContext(ctx, query, identity)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	if rows.Next() {
		return rows.Scan(&identity.ID)
	}
	return nil
}

func (s *sqlFederationRepository) List(ctx context.Context, identityID string) ([]FederatedIdentity, error) {
	var identities []FederatedIdentity
	err := s.db.SelectContext(ctx, &identities, `SELECT * FROM federated_identities WHERE identity_id = $1`, identityID)
	return identities, err
}

func (s *sqlFederationRepository) Delete(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM federated_identities WHERE id = $1`, id)
	return err
}
