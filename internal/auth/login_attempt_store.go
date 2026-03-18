package auth

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/jmoiron/sqlx"
)

const (
	MaxFailedAttempts = 5
	LockoutDuration   = 15 * time.Minute
	AttemptWindow     = 15 * time.Minute
)

// LoginAttemptRepository handles tracking login attempts and lockouts.
type LoginAttemptRepository interface {
	RecordAttempt(ctx context.Context, tenantID, username, ip string, success bool) error
	GetRecentFailures(ctx context.Context, tenantID, username string) (int, error)
	IsLocked(ctx context.Context, tenantID, username string) (bool, time.Time, error)
	LockAccount(ctx context.Context, tenantID, username string) error
	UnlockAccount(ctx context.Context, tenantID, username string) error
}

type sqlLoginAttemptRepository struct {
	db *sqlx.DB
}

// NewLoginAttemptRepository creates a new login attempt repository.
func NewLoginAttemptRepository(db *sqlx.DB) LoginAttemptRepository {
	return &sqlLoginAttemptRepository{db: db}
}

func (r *sqlLoginAttemptRepository) RecordAttempt(ctx context.Context, tenantID, username, ip string, success bool) error {
	query := `INSERT INTO login_attempts (tenant_id, username, ip_address, success) VALUES ($1, $2, $3, $4)`
	_, err := r.db.ExecContext(ctx, query, tenantID, username, ip, success)
	return err
}

func (r *sqlLoginAttemptRepository) GetRecentFailures(ctx context.Context, tenantID, username string) (int, error) {
	var count int
	query := `
		SELECT COUNT(*) FROM login_attempts 
		WHERE tenant_id = $1 AND username = $2 AND success = FALSE 
		AND attempted_at > NOW() - INTERVAL '15 minutes'
	`
	err := r.db.GetContext(ctx, &count, query, tenantID, username)
	return count, err
}

func (r *sqlLoginAttemptRepository) IsLocked(ctx context.Context, tenantID, username string) (bool, time.Time, error) {
	var lockedUntil time.Time
	query := `SELECT locked_until FROM account_lockouts WHERE tenant_id = $1 AND username = $2`
	err := r.db.GetContext(ctx, &lockedUntil, query, tenantID, username)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, time.Time{}, nil
		}
		return false, time.Time{}, err
	}

	if time.Now().After(lockedUntil) {
		// Lockout has expired, remove it
		_ = r.UnlockAccount(ctx, tenantID, username)
		return false, time.Time{}, nil
	}

	return true, lockedUntil, nil
}

func (r *sqlLoginAttemptRepository) LockAccount(ctx context.Context, tenantID, username string) error {
	lockedUntil := time.Now().Add(LockoutDuration)
	query := `
		INSERT INTO account_lockouts (tenant_id, username, locked_until)
		VALUES ($1, $2, $3)
		ON CONFLICT (tenant_id, username) 
		DO UPDATE SET locked_at = NOW(), locked_until = EXCLUDED.locked_until
	`
	_, err := r.db.ExecContext(ctx, query, tenantID, username, lockedUntil)
	return err
}

func (r *sqlLoginAttemptRepository) UnlockAccount(ctx context.Context, tenantID, username string) error {
	query := `DELETE FROM account_lockouts WHERE tenant_id = $1 AND username = $2`
	_, err := r.db.ExecContext(ctx, query, tenantID, username)
	return err
}
