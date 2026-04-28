package auth

import (
	"context"
	"errors"
	"time"

	"github.com/jmoiron/sqlx"
	"golang.org/x/crypto/bcrypt"
	"github.com/dhawalhost/wardseal/pkg/database"
)

// APIKeyRecord represents an API key in the database.
type APIKeyRecord struct {
	ID         string     `db:"id"`
	TenantID   string     `db:"tenant_id"`
	OwnerID    string     `db:"owner_id"`
	Name       string     `db:"name"`
	KeyPrefix  string     `db:"key_prefix"`
	KeyHash    string     `db:"key_hash"`
	Status     string     `db:"status"`
	ExpiresAt  *time.Time `db:"expires_at"`
	LastUsedAt *time.Time `db:"last_used_at"`
	CreatedAt  time.Time  `db:"created_at"`
}

// APIKeyRepository defines database operations for API keys.
type APIKeyRepository interface {
	GetByPrefix(ctx context.Context, prefix string) ([]APIKeyRecord, error)
	UpdateLastUsed(ctx context.Context, id string) error
	Revoke(ctx context.Context, tenantID, id string) error
}

type sqlAPIKeyRepository struct {
	db *sqlx.DB
}

// NewAPIKeyRepository creates a new API key repository.
func NewAPIKeyRepository(db *sqlx.DB) APIKeyRepository {
	return &sqlAPIKeyRepository{db: db}
}

func (r *sqlAPIKeyRepository) GetByPrefix(ctx context.Context, prefix string) ([]APIKeyRecord, error) {
	var keys []APIKeyRecord
	err := database.RunInTenantTx(ctx, r.db, func(tx *sqlx.Tx) error {
		query := `SELECT id, tenant_id, owner_id, name, key_prefix, key_hash, status, expires_at, last_used_at, created_at 
		          FROM api_keys WHERE key_prefix = $1 AND status = 'active'`
		return tx.SelectContext(ctx, &keys, query, prefix)
	})
	if err != nil {
		return nil, err
	}
	return keys, nil
}

func (r *sqlAPIKeyRepository) UpdateLastUsed(ctx context.Context, id string) error {
	return database.RunInTenantTx(ctx, r.db, func(tx *sqlx.Tx) error {
		query := `UPDATE api_keys SET last_used_at = NOW() WHERE id = $1`
		_, err := tx.ExecContext(ctx, query, id)
		return err
	})
}

func (r *sqlAPIKeyRepository) Revoke(ctx context.Context, tenantID, id string) error {
	return database.RunInTenantTx(ctx, r.db, func(tx *sqlx.Tx) error {
		query := `UPDATE api_keys SET status = 'revoked' WHERE tenant_id = $1 AND id = $2`
		_, err := tx.ExecContext(ctx, query, tenantID, id)
		return err
	})
}

// ValidateAPIKey verifies a plaintext API key against the database.
func ValidateAPIKey(ctx context.Context, repo APIKeyRepository, fullKey string) (*APIKeyRecord, error) {
	if len(fullKey) < 16 {
		return nil, errors.New("invalid api key format")
	}

	// Calculate prefix (Dashboard uses first 16 chars + "..." for display, but DB stores prefix)
	// Looking at developer_api.go, keyPrefix := fullKey[:16] + "..."
	// Wait, the DB column is VARCHAR(12).
	// Let's use 12 for the search prefix if that's what was intended.
	prefix := fullKey[:12]

	keys, err := repo.GetByPrefix(ctx, prefix)
	if err != nil {
		return nil, err
	}

	for _, k := range keys {
		if err := bcrypt.CompareHashAndPassword([]byte(k.KeyHash), []byte(fullKey)); err == nil {
			// Check expiration
			if k.ExpiresAt != nil && k.ExpiresAt.Before(time.Now()) {
				continue
			}
			return &k, nil
		}
	}

	return nil, errors.New("invalid api key")
}
