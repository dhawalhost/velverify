package discovery

import (
	"context"

	"github.com/jmoiron/sqlx"
)

type sqlRepository struct {
	db *sqlx.DB
}

// NewRepository creates a new discovery repository.
func NewRepository(db *sqlx.DB) Repository {
	return &sqlRepository{db: db}
}

func (r *sqlRepository) Upsert(ctx context.Context, res DiscoveredResource) error {
	query := `
		INSERT INTO discovered_resources (tenant_id, connector_id, type, name, external_id, metadata, status, last_discovered_at)
		VALUES (:tenant_id, :connector_id, :type, :name, :external_id, :metadata, :status, :last_discovered_at)
		ON CONFLICT (tenant_id, type, external_id) DO UPDATE SET
			connector_id = EXCLUDED.connector_id,
			name = EXCLUDED.name,
			metadata = EXCLUDED.metadata,
			status = EXCLUDED.status,
			last_discovered_at = EXCLUDED.last_discovered_at,
			updated_at = NOW()
	`
	_, err := r.db.NamedExecContext(ctx, query, res)
	return err
}

func (r *sqlRepository) List(ctx context.Context, tenantID string, filter string) ([]DiscoveredResource, error) {
	var resources []DiscoveredResource

	// Explicit column selection is more robust than SELECT *
	query := `
		SELECT 
			id, tenant_id, connector_id, type, name, external_id, metadata, status, last_discovered_at, created_at, updated_at 
		FROM discovered_resources 
		WHERE tenant_id = $1 
		ORDER BY last_discovered_at DESC`
	
	err := r.db.SelectContext(ctx, &resources, query, tenantID)

	return resources, err
}
