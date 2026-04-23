package saml

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"

	"github.com/dhawalhost/wardseal/pkg/kms"
)

// IdPConfig represents the SAML Identity Provider configuration for a tenant.
type IdPConfig struct {
	TenantID     string    `db:"tenant_id"`
	EntityID     string    `db:"entity_id"`
	Certificate  string    `db:"certificate"`   // PEM encoded
	EncryptedKey []byte    `db:"encrypted_key"` // Encrypted via KMS
	CreatedAt    time.Time `db:"created_at"`
	UpdatedAt    time.Time `db:"updated_at"`
}

// IdPRepository defines the interface for managing tenant SAML IdP configurations.
type IdPRepository interface {
	GetByTenantID(ctx context.Context, tenantID string) (*IdPConfig, error)
	GetByEntityID(ctx context.Context, entityID string) (*IdPConfig, error)
	Upsert(ctx context.Context, config *IdPConfig) error
}

type sqlIdPRepository struct {
	db     *sqlx.DB
	cipher kms.Cipher
}

func NewIdPRepository(db *sqlx.DB, cipher kms.Cipher) IdPRepository {
	return &sqlIdPRepository{db: db, cipher: cipher}
}

func (r *sqlIdPRepository) GetByTenantID(ctx context.Context, tenantID string) (*IdPConfig, error) {
	var cfg IdPConfig
	err := r.db.GetContext(ctx, &cfg, "SELECT * FROM saml_idp_configs WHERE tenant_id = $1", tenantID)
	if err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (r *sqlIdPRepository) GetByEntityID(ctx context.Context, entityID string) (*IdPConfig, error) {
	var cfg IdPConfig
	err := r.db.GetContext(ctx, &cfg, "SELECT * FROM saml_idp_configs WHERE entity_id = $1", entityID)
	if err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (r *sqlIdPRepository) Upsert(ctx context.Context, cfg *IdPConfig) error {
	query := `
		INSERT INTO saml_idp_configs (tenant_id, entity_id, certificate, encrypted_key, updated_at)
		VALUES (:tenant_id, :entity_id, :certificate, :encrypted_key, NOW())
		ON CONFLICT (tenant_id) DO UPDATE SET
			entity_id = EXCLUDED.entity_id,
			certificate = EXCLUDED.certificate,
			encrypted_key = EXCLUDED.encrypted_key,
			updated_at = NOW()
	`
	_, err := r.db.NamedExecContext(ctx, query, cfg)
	return err
}

// ParseCredentials extracts the crypto primitives from the IdPConfig.
func (cfg *IdPConfig) ParseCredentials(ctx context.Context, cipher kms.Cipher) (*x509.Certificate, *rsa.PrivateKey, error) {
	// 1. Decode Certificate
	block, _ := pem.Decode([]byte(cfg.Certificate))
	if block == nil {
		return nil, nil, errors.New("failed to decode certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// 2. Decrypt Private Key
	decryptedKey, err := cipher.Decrypt(ctx, cfg.EncryptedKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decrypt private key: %w", err)
	}

	// 3. Parse RSA Private Key
	keyBlock, _ := pem.Decode(decryptedKey)
	if keyBlock == nil {
		return nil, nil, errors.New("failed to decode private key PEM")
	}
	privKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return cert, privKey, nil
}
