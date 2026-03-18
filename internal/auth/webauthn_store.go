package auth

import (
	"context"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

// WebAuthnUser adapts our internal user concept to the webauthn library's User interface.
type WebAuthnUser struct {
	ID          string // UUID
	Name        string // Email/Username
	DisplayName string
	Credentials []webauthn.Credential // Loaded for the user
}

func (u *WebAuthnUser) WebAuthnID() []byte {
	return []byte(u.ID)
}

func (u *WebAuthnUser) WebAuthnName() string {
	return u.Name
}

func (u *WebAuthnUser) WebAuthnDisplayName() string {
	return u.DisplayName
}

func (u *WebAuthnUser) WebAuthnIcon() string {
	return "" // Optional
}

func (u *WebAuthnUser) WebAuthnCredentials() []webauthn.Credential {
	return u.Credentials
}

// WebAuthnCredentialEntity matches the database schema.
type WebAuthnCredentialEntity struct {
	ID              string    `db:"id"`
	TenantID        string    `db:"tenant_id"`
	UserID          string    `db:"user_id"`
	CredentialID    []byte    `db:"credential_id"`
	PublicKey       []byte    `db:"public_key"`
	AttestationType string    `db:"attestation_type"`
	AAGUID          []byte    `db:"aaguid"`
	SignCount       uint32    `db:"sign_count"`
	CloneWarning    bool      `db:"clone_warning"`
	FriendlyName    string    `db:"friendly_name"`
	CreatedAt       time.Time `db:"created_at"`
	UpdatedAt       time.Time `db:"updated_at"`
}

// WebAuthnRepository handles database operations for WebAuthn credentials.
type WebAuthnRepository interface {
	SaveCredential(ctx context.Context, tenantID, userID string, cred *webauthn.Credential) error
	ListCredentials(ctx context.Context, userID string) ([]webauthn.Credential, error)
	UpdateCredential(ctx context.Context, cred *webauthn.Credential) error
}

type sqlWebAuthnRepository struct {
	db *sqlx.DB
}

func NewWebAuthnRepository(db *sqlx.DB) WebAuthnRepository {
	return &sqlWebAuthnRepository{db: db}
}

func (r *sqlWebAuthnRepository) SaveCredential(ctx context.Context, tenantID, userID string, cred *webauthn.Credential) error {
	query := `
		INSERT INTO webauthn_credentials (
			id, tenant_id, user_id, credential_id, public_key, attestation_type, aaguid, sign_count, clone_warning, updated_at
		) VALUES (
			:id, :tenant_id, :user_id, :credential_id, :public_key, :attestation_type, :aaguid, :sign_count, :clone_warning, :updated_at
		)
	`
	entity := map[string]interface{}{
		"id":               uuid.New().String(),
		"tenant_id":        tenantID,
		"user_id":          userID,
		"credential_id":    cred.ID,
		"public_key":       cred.PublicKey,
		"attestation_type": cred.AttestationType,
		"aaguid":           cred.Authenticator.AAGUID,
		"sign_count":       cred.Authenticator.SignCount,
		"clone_warning":    cred.Authenticator.CloneWarning,
		"updated_at":       time.Now(),
	}
	_, err := r.db.NamedExecContext(ctx, query, entity)
	return err
}

func (r *sqlWebAuthnRepository) ListCredentials(ctx context.Context, userID string) ([]webauthn.Credential, error) {
	var entities []WebAuthnCredentialEntity
	query := `SELECT * FROM webauthn_credentials WHERE user_id = $1`
	err := r.db.SelectContext(ctx, &entities, query, userID)
	if err != nil {
		return nil, err
	}

	creds := make([]webauthn.Credential, len(entities))
	for i, e := range entities {
		creds[i] = webauthn.Credential{
			ID:              e.CredentialID,
			PublicKey:       e.PublicKey,
			AttestationType: e.AttestationType,
			Authenticator: webauthn.Authenticator{
				AAGUID:       e.AAGUID,
				SignCount:    e.SignCount,
				CloneWarning: e.CloneWarning,
			},
		}
	}
	return creds, nil
}

func (r *sqlWebAuthnRepository) UpdateCredential(ctx context.Context, cred *webauthn.Credential) error {
	query := `
		UPDATE webauthn_credentials 
		SET sign_count = :sign_count, clone_warning = :clone_warning, updated_at = :updated_at
		WHERE credential_id = :credential_id
	`
	params := map[string]interface{}{
		"sign_count":    cred.Authenticator.SignCount,
		"clone_warning": cred.Authenticator.CloneWarning,
		"updated_at":    time.Now(),
		"credential_id": cred.ID,
	}
	_, err := r.db.NamedExecContext(ctx, query, params)
	return err
}
