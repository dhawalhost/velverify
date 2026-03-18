package auth

import (
	"context"
	"database/sql"
	"errors"

	"github.com/jmoiron/sqlx"
)

// TenantRepository defines the interface for tenant-related database operations.
type TenantRepository interface {
	GetIDBySlug(ctx context.Context, slug string) (string, error)
	GetSlugByID(ctx context.Context, id string) (string, error)
}

// sqlTenantRepository implements TenantRepository using sqlx.
type sqlTenantRepository struct {
	db *sqlx.DB
}

// NewTenantRepository creates a new TenantRepository.
func NewTenantRepository(db *sqlx.DB) TenantRepository {
	return &sqlTenantRepository{db: db}
}

func (r *sqlTenantRepository) GetIDBySlug(ctx context.Context, slug string) (string, error) {
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

func (r *sqlTenantRepository) GetSlugByID(ctx context.Context, id string) (string, error) {
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
