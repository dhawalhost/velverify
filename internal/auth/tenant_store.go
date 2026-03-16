package auth

import (
	"context"
	"database/sql"
	"errors"

	"github.com/jmoiron/sqlx"
)

// TenantStore defines the interface for tenant-related database operations.
type TenantStore interface {
	GetIDBySlug(ctx context.Context, slug string) (string, error)
	GetSlugByID(ctx context.Context, id string) (string, error)
}

// tenantRepo implements TenantStore using sqlx.
type tenantRepo struct {
	db *sqlx.DB
}

// NewTenantStore creates a new TenantStore.
func NewTenantStore(db *sqlx.DB) TenantStore {
	return &tenantRepo{db: db}
}

func (r *tenantRepo) GetIDBySlug(ctx context.Context, slug string) (string, error) {
	var id string
	query := `SELECT id FROM tenants WHERE slug = $1`
	err := r.db.GetContext(ctx, &id, query, slug)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", nil
		}
		return "", err
	}
	return id, nil
}

func (r *tenantRepo) GetSlugByID(ctx context.Context, id string) (string, error) {
	var slug string
	query := `SELECT slug FROM tenants WHERE id = $1`
	err := r.db.GetContext(ctx, &slug, query, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", nil
		}
		return "", err
	}
	return slug, nil
}
