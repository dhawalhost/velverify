package connector

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jmoiron/sqlx"

	"github.com/dhawalhost/wardseal/pkg/kms"
)

// Repository defines connector storage operations.
type Repository interface {
	Create(ctx context.Context, config Config) (string, error)
	Get(ctx context.Context, tenantID, id string) (Config, error)
	List(ctx context.Context, tenantID string) ([]Config, error)
	Update(ctx context.Context, config Config) error
	Delete(ctx context.Context, tenantID, id string) error
	Toggle(ctx context.Context, tenantID, id string, enabled bool) error
}

type sqlRepository struct {
	db     *sqlx.DB
	cipher kms.Cipher
}

// NewRepository creates a new connector repository with encryption support.
func NewRepository(db *sqlx.DB, cipher kms.Cipher) Repository {
	return &sqlRepository{
		db:     db,
		cipher: cipher,
	}
}

func (s *sqlRepository) Create(ctx context.Context, config Config) (string, error) {
	var id string

	credsJSON, _ := json.Marshal(config.Credentials)
	credentials, err := s.cipher.Encrypt(ctx, credsJSON)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt credentials: %w", err)
	}

	settings, _ := json.Marshal(config.Settings)

	err = s.db.QueryRowxContext(ctx,
		`INSERT INTO connectors (tenant_id, name, type, enabled, endpoint, credentials, settings)
		VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
		config.TenantID, config.Name, config.Type, config.Enabled, config.Endpoint, credentials, settings,
	).Scan(&id)
	return id, err
}

func (s *sqlRepository) Get(ctx context.Context, tenantID, id string) (Config, error) {
	var c struct {
		Config
		CredentialsRaw []byte `db:"credentials"`
		SettingsRaw    []byte `db:"settings"`
	}
	err := s.db.GetContext(ctx, &c,
		`SELECT * FROM connectors WHERE id = $1 AND tenant_id = $2`, id, tenantID)
	if err != nil {
		return Config{}, err
	}

	c.Credentials = make(map[string]string)
	c.Settings = make(map[string]string)

	if len(c.CredentialsRaw) > 0 {
		decrypted, err := s.cipher.Decrypt(ctx, c.CredentialsRaw)
		if err == nil {
			_ = json.Unmarshal(decrypted, &c.Credentials)
		}
	}
	_ = json.Unmarshal(c.SettingsRaw, &c.Settings)

	return c.Config, nil
}

func (s *sqlRepository) List(ctx context.Context, tenantID string) ([]Config, error) {
	var rows []struct {
		Config
		CredentialsRaw []byte `db:"credentials"`
		SettingsRaw    []byte `db:"settings"`
	}
	err := s.db.SelectContext(ctx, &rows,
		`SELECT * FROM connectors WHERE tenant_id = $1 ORDER BY name`, tenantID)
	if err != nil {
		return nil, err
	}

	configs := make([]Config, len(rows))
	for i, r := range rows {
		r.Credentials = make(map[string]string)
		r.Settings = make(map[string]string)

		if len(r.CredentialsRaw) > 0 {
			decrypted, err := s.cipher.Decrypt(ctx, r.CredentialsRaw)
			if err == nil {
				_ = json.Unmarshal(decrypted, &r.Credentials)
			}
		}
		_ = json.Unmarshal(r.SettingsRaw, &r.Settings)
		configs[i] = r.Config
	}
	return configs, nil
}

func (s *sqlRepository) Update(ctx context.Context, config Config) error {
	credsJSON, _ := json.Marshal(config.Credentials)
	credentials, err := s.cipher.Encrypt(ctx, credsJSON)
	if err != nil {
		return fmt.Errorf("failed to encrypt credentials: %w", err)
	}

	settings, _ := json.Marshal(config.Settings)

	_, err = s.db.ExecContext(ctx,
		`UPDATE connectors SET 
			name = $1, enabled = $2, endpoint = $3, credentials = $4, settings = $5, updated_at = NOW()
		WHERE id = $6 AND tenant_id = $7`,
		config.Name, config.Enabled, config.Endpoint, credentials, settings, config.ID, config.TenantID)
	return err
}

func (s *sqlRepository) Delete(ctx context.Context, tenantID, id string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM connectors WHERE id = $1 AND tenant_id = $2`, id, tenantID)
	return err
}

func (s *sqlRepository) Toggle(ctx context.Context, tenantID, id string, enabled bool) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE connectors SET enabled = $1, updated_at = NOW() WHERE id = $2 AND tenant_id = $3`,
		enabled, id, tenantID)
	return err
}
