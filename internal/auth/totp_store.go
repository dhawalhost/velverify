package auth

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/jmoiron/sqlx"
)

// TOTPSecret represents a stored TOTP secret for a user.
type TOTPSecret struct {
	ID         string     `db:"id" json:"id"`
	IdentityID string     `db:"identity_id" json:"identity_id"`
	TenantID   string     `db:"tenant_id" json:"tenant_id"`
	Secret     string     `db:"secret" json:"-"` // Never expose in JSON
	Verified   bool       `db:"verified" json:"verified"`
	CreatedAt  time.Time  `db:"created_at" json:"created_at"`
	VerifiedAt *time.Time `db:"verified_at" json:"verified_at,omitempty"`
}

// TOTPRepository defines the interface for TOTP secret storage.
type TOTPRepository interface {
	Create(ctx context.Context, secret *TOTPSecret) error
	GetByIdentity(ctx context.Context, tenantID, identityID string) (*TOTPSecret, error)
	MarkVerified(ctx context.Context, id string) error
	Delete(ctx context.Context, tenantID, identityID string) error
}

type sqlTOTPRepository struct {
	db *sqlx.DB
}

// NewTOTPRepository creates a new TOTP repository.
func NewTOTPRepository(db *sqlx.DB) TOTPRepository {
	return &sqlTOTPRepository{db: db}
}

func (r *sqlTOTPRepository) Create(ctx context.Context, secret *TOTPSecret) error {
	query := `
		INSERT INTO totp_secrets (identity_id, tenant_id, secret, verified)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (identity_id, tenant_id) 
		DO UPDATE SET secret = EXCLUDED.secret, verified = FALSE, verified_at = NULL
		RETURNING id, created_at
	`
	return r.db.QueryRowxContext(ctx, query,
		secret.IdentityID,
		secret.TenantID,
		secret.Secret,
		false,
	).Scan(&secret.ID, &secret.CreatedAt)
}

func (r *sqlTOTPRepository) GetByIdentity(ctx context.Context, tenantID, identityID string) (*TOTPSecret, error) {
	var secret TOTPSecret
	query := `SELECT id, identity_id, tenant_id, secret, verified, created_at, verified_at FROM totp_secrets WHERE tenant_id = $1 AND identity_id = $2`
	err := r.db.GetContext(ctx, &secret, query, tenantID, identityID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &secret, nil
}

func (r *sqlTOTPRepository) MarkVerified(ctx context.Context, id string) error {
	query := `UPDATE totp_secrets SET verified = TRUE, verified_at = NOW() WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, id)
	return err
}

func (r *sqlTOTPRepository) Delete(ctx context.Context, tenantID, identityID string) error {
	query := `DELETE FROM totp_secrets WHERE tenant_id = $1 AND identity_id = $2`
	_, err := r.db.ExecContext(ctx, query, tenantID, identityID)
	return err
}
