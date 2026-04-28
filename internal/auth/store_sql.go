package auth

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/dhawalhost/wardseal/pkg/database"
)

// ========== Authorization Code Store ==========

type sqlAuthorizationCodeRepository struct {
	db *sqlx.DB
}

func NewAuthorizationCodeRepository(db *sqlx.DB) AuthorizationCodeRepository {
	return &sqlAuthorizationCodeRepository{db: db}
}

func (s *sqlAuthorizationCodeRepository) Save(ctx context.Context, code authorizationCode) error {
	return database.RunInTenantTx(ctx, s.db, func(tx *sqlx.Tx) error {
		query := `
			INSERT INTO authorization_codes (code, client_id, redirect_uri, scope, tenant_id, nonce, code_challenge, code_challenge_method, expires_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		`
		_, err := tx.ExecContext(ctx, query,
			code.Code,
			code.ClientID,
			code.RedirectURI,
			code.Scope,
			code.TenantID,
			code.Nonce,
			code.CodeChallenge,
			code.CodeChallengeMethod,
			code.ExpiresAt,
		)
		return err
	})
}

func (s *sqlAuthorizationCodeRepository) Get(ctx context.Context, code string) (authorizationCode, bool, error) {
	var entry authorizationCode
	var found bool
	err := database.RunInTenantTx(ctx, s.db, func(tx *sqlx.Tx) error {
		query := `SELECT code, client_id, redirect_uri, scope, tenant_id, nonce, code_challenge, code_challenge_method, expires_at FROM authorization_codes WHERE code = $1`
		err := tx.GetContext(ctx, &entry, query, code)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				found = false
				return nil
			}
			return err
		}
		found = true
		return nil
	})
	if err != nil {
		return authorizationCode{}, false, err
	}
	return entry, found, nil
}

func (s *sqlAuthorizationCodeRepository) Delete(ctx context.Context, code string) error {
	return database.RunInTenantTx(ctx, s.db, func(tx *sqlx.Tx) error {
		query := `DELETE FROM authorization_codes WHERE code = $1`
		_, err := tx.ExecContext(ctx, query, code)
		return err
	})
}

func (s *sqlAuthorizationCodeRepository) CleanupExpired(ctx context.Context) error {
	return database.RunInTenantTx(ctx, s.db, func(tx *sqlx.Tx) error {
		query := `DELETE FROM authorization_codes WHERE expires_at < $1`
		_, err := tx.ExecContext(ctx, query, time.Now())
		return err
	})
}

// ========== Refresh Token Store ==========

type sqlRefreshTokenRepository struct {
	db *sqlx.DB
}

func NewRefreshTokenRepository(db *sqlx.DB) RefreshTokenRepository {
	return &sqlRefreshTokenRepository{db: db}
}

func (s *sqlRefreshTokenRepository) Save(ctx context.Context, entry refreshTokenEntry) error {
	return database.RunInTenantTx(ctx, s.db, func(tx *sqlx.Tx) error {
		query := `
			INSERT INTO refresh_tokens (token, client_id, tenant_id, scope, subject_type, expires_at)
			VALUES ($1, $2, $3, $4, $5, $6)
		`
		_, err := tx.ExecContext(ctx, query,
			entry.Token,
			entry.ClientID,
			entry.TenantID,
			entry.Scope,
			entry.SubjectType,
			entry.ExpiresAt,
		)
		return err
	})
}

func (s *sqlRefreshTokenRepository) Get(ctx context.Context, token string) (refreshTokenEntry, bool, error) {
	var entry refreshTokenEntry
	var found bool
	err := database.RunInTenantTx(ctx, s.db, func(tx *sqlx.Tx) error {
		query := `SELECT token, client_id, tenant_id, scope, subject_type, expires_at FROM refresh_tokens WHERE token = $1`
		err := tx.GetContext(ctx, &entry, query, token)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				found = false
				return nil
			}
			return err
		}
		found = true
		return nil
	})
	if err != nil {
		return refreshTokenEntry{}, false, err
	}
	return entry, found, nil
}

func (s *sqlRefreshTokenRepository) Delete(ctx context.Context, token string) error {
	return database.RunInTenantTx(ctx, s.db, func(tx *sqlx.Tx) error {
		query := `DELETE FROM refresh_tokens WHERE token = $1`
		_, err := tx.ExecContext(ctx, query, token)
		return err
	})
}

func (s *sqlRefreshTokenRepository) CleanupExpired(ctx context.Context) error {
	return database.RunInTenantTx(ctx, s.db, func(tx *sqlx.Tx) error {
		query := `DELETE FROM refresh_tokens WHERE expires_at < $1`
		_, err := tx.ExecContext(ctx, query, time.Now())
		return err
	})
}

// ========== Token Revocation Store ==========

type sqlRevocationRepository struct {
	db *sqlx.DB
}

func NewRevocationRepository(db *sqlx.DB) RevocationRepository {
	return &sqlRevocationRepository{db: db}
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func (s *sqlRevocationRepository) Revoke(ctx context.Context, token string) error {
	return database.RunInTenantTx(ctx, s.db, func(tx *sqlx.Tx) error {
		hash := hashToken(token)
		query := `INSERT INTO revoked_tokens (token_hash) VALUES ($1) ON CONFLICT DO NOTHING`
		_, err := tx.ExecContext(ctx, query, hash)
		return err
	})
}

func (s *sqlRevocationRepository) IsRevoked(ctx context.Context, token string) (bool, error) {
	var exists int
	var found bool
	err := database.RunInTenantTx(ctx, s.db, func(tx *sqlx.Tx) error {
		hash := hashToken(token)
		query := `SELECT 1 FROM revoked_tokens WHERE token_hash = $1 LIMIT 1`
		err := tx.GetContext(ctx, &exists, query, hash)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				found = false
				return nil
			}
			return err
		}
		found = true
		return nil
	})
	if err != nil {
		return false, err
	}
	return found, nil
}

func (s *sqlRevocationRepository) CleanupOld(ctx context.Context, olderThan time.Duration) error {
	return database.RunInTenantTx(ctx, s.db, func(tx *sqlx.Tx) error {
		cutoff := time.Now().Add(-olderThan)
		query := `DELETE FROM revoked_tokens WHERE revoked_at < $1`
		_, err := tx.ExecContext(ctx, query, cutoff)
		return err
	})
}
