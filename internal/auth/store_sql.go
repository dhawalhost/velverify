package auth

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"

	"github.com/jmoiron/sqlx"
)

// ========== Authorization Code Store ==========

// SQLAuthorizationCodeStore implements persistent storage for authorization codes.
type SQLAuthorizationCodeStore struct {
	db *sqlx.DB
}

// NewSQLAuthorizationCodeStore creates a new SQL-backed authorization code store.
func NewSQLAuthorizationCodeStore(db *sqlx.DB) *SQLAuthorizationCodeStore {
	return &SQLAuthorizationCodeStore{db: db}
}

func (s *SQLAuthorizationCodeStore) Save(ctx context.Context, code authorizationCode) error {
	query := `
		INSERT INTO authorization_codes (code, client_id, redirect_uri, scope, tenant_id, nonce, code_challenge, code_challenge_method, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`
	_, err := s.db.ExecContext(ctx, query,
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
}

func (s *SQLAuthorizationCodeStore) Get(ctx context.Context, code string) (authorizationCode, bool, error) {
	var entry authorizationCode
	query := `SELECT code, client_id, redirect_uri, scope, tenant_id, nonce, code_challenge, code_challenge_method, expires_at FROM authorization_codes WHERE code = $1`
	err := s.db.GetContext(ctx, &entry, query, code)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return authorizationCode{}, false, nil
		}
		return authorizationCode{}, false, err
	}
	return entry, true, nil
}

func (s *SQLAuthorizationCodeStore) Delete(ctx context.Context, code string) error {
	query := `DELETE FROM authorization_codes WHERE code = $1`
	_, err := s.db.ExecContext(ctx, query, code)
	return err
}

// CleanupExpired removes expired codes (can be run periodically).
func (s *SQLAuthorizationCodeStore) CleanupExpired(ctx context.Context) error {
	query := `DELETE FROM authorization_codes WHERE expires_at < $1`
	_, err := s.db.ExecContext(ctx, query, time.Now())
	return err
}

// ========== Refresh Token Store ==========

// SQLRefreshTokenStore implements persistent storage for refresh tokens.
type SQLRefreshTokenStore struct {
	db *sqlx.DB
}

// NewSQLRefreshTokenStore creates a new SQL-backed refresh token store.
func NewSQLRefreshTokenStore(db *sqlx.DB) *SQLRefreshTokenStore {
	return &SQLRefreshTokenStore{db: db}
}

func (s *SQLRefreshTokenStore) Save(ctx context.Context, entry refreshTokenEntry) error {
	query := `
		INSERT INTO refresh_tokens (token, client_id, tenant_id, scope, subject_type, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`
	_, err := s.db.ExecContext(ctx, query,
		entry.Token,
		entry.ClientID,
		entry.TenantID,
		entry.Scope,
		entry.SubjectType,
		entry.ExpiresAt,
	)
	return err
}

func (s *SQLRefreshTokenStore) Get(ctx context.Context, token string) (refreshTokenEntry, bool, error) {
	var entry refreshTokenEntry
	query := `SELECT token, client_id, tenant_id, scope, subject_type, expires_at FROM refresh_tokens WHERE token = $1`
	err := s.db.GetContext(ctx, &entry, query, token)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return refreshTokenEntry{}, false, nil
		}
		return refreshTokenEntry{}, false, err
	}
	return entry, true, nil
}

func (s *SQLRefreshTokenStore) Delete(ctx context.Context, token string) error {
	query := `DELETE FROM refresh_tokens WHERE token = $1`
	_, err := s.db.ExecContext(ctx, query, token)
	return err
}

// CleanupExpired removes expired tokens.
func (s *SQLRefreshTokenStore) CleanupExpired(ctx context.Context) error {
	query := `DELETE FROM refresh_tokens WHERE expires_at < $1`
	_, err := s.db.ExecContext(ctx, query, time.Now())
	return err
}

// ========== Token Revocation Store ==========

// SQLRevocationStore implements persistent storage for revoked tokens.
type SQLRevocationStore struct {
	db *sqlx.DB
}

// NewSQLRevocationStore creates a new SQL-backed revocation store.
func NewSQLRevocationStore(db *sqlx.DB) *SQLRevocationStore {
	return &SQLRevocationStore{db: db}
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func (s *SQLRevocationStore) Revoke(ctx context.Context, token string) error {
	hash := hashToken(token)
	query := `INSERT INTO revoked_tokens (token_hash) VALUES ($1) ON CONFLICT DO NOTHING`
	_, err := s.db.ExecContext(ctx, query, hash)
	return err
}

func (s *SQLRevocationStore) IsRevoked(ctx context.Context, token string) (bool, error) {
	hash := hashToken(token)
	var exists int
	query := `SELECT 1 FROM revoked_tokens WHERE token_hash = $1 LIMIT 1`
	err := s.db.GetContext(ctx, &exists, query, hash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// CleanupOld removes old revocation records (e.g., older than 30 days).
func (s *SQLRevocationStore) CleanupOld(ctx context.Context, olderThan time.Duration) error {
	cutoff := time.Now().Add(-olderThan)
	query := `DELETE FROM revoked_tokens WHERE revoked_at < $1`
	_, err := s.db.ExecContext(ctx, query, cutoff)
	return err
}
