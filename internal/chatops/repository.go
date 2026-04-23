package chatops

import (
	"context"
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"

	"github.com/dhawalhost/wardseal/pkg/kms"
)

// SlackIntegration represents a tenant's connection to a Slack workspace.
type SlackIntegration struct {
	ID               string    `db:"id"`
	TenantID         string    `db:"tenant_id"`
	TeamID           string    `db:"team_id"` // Slack's internal workspace ID
	AppID            string    `db:"app_id"`
	BotTokenEnc      []byte    `db:"bot_token_enc"`
	SigningSecretEnc []byte    `db:"signing_secret_enc"`
	WebhookURL       string    `db:"webhook_url"`
	IsEnabled        bool      `db:"is_enabled"`
	CreatedAt        time.Time `db:"created_at"`
	UpdatedAt        time.Time `db:"updated_at"`

	// Decrypted fields (not persisted)
	BotToken      string `db:"-"`
	SigningSecret string `db:"-"`
}

// Repository defines storage operations for Slack integrations.
type Repository interface {
	Upsert(ctx context.Context, si SlackIntegration) error
	GetByTenant(ctx context.Context, tenantID string) (SlackIntegration, error)
	GetByTeamID(ctx context.Context, teamID string) (SlackIntegration, error)
	Delete(ctx context.Context, tenantID string) error
}

type sqlRepository struct {
	db     *sqlx.DB
	cipher kms.Cipher
}

// NewRepository creates a new Slack integration repository.
func NewRepository(db *sqlx.DB, cipher kms.Cipher) Repository {
	return &sqlRepository{db: db, cipher: cipher}
}

func (r *sqlRepository) Upsert(ctx context.Context, si SlackIntegration) error {
	// Encrypt sensitive fields
	if si.BotToken != "" {
		enc, err := r.cipher.Encrypt(ctx, []byte(si.BotToken))
		if err != nil {
			return fmt.Errorf("failed to encrypt bot token: %w", err)
		}
		si.BotTokenEnc = enc
	}

	if si.SigningSecret != "" {
		enc, err := r.cipher.Encrypt(ctx, []byte(si.SigningSecret))
		if err != nil {
			return fmt.Errorf("failed to encrypt signing secret: %w", err)
		}
		si.SigningSecretEnc = enc
	}

	query := `
		INSERT INTO chatops_slack_integrations (tenant_id, team_id, app_id, bot_token_enc, signing_secret_enc, webhook_url, is_enabled)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (tenant_id) DO UPDATE SET
			team_id = EXCLUDED.team_id,
			app_id = EXCLUDED.app_id,
			bot_token_enc = COALESCE(NULLIF(EXCLUDED.bot_token_enc, ''), chatops_slack_integrations.bot_token_enc),
			signing_secret_enc = COALESCE(NULLIF(EXCLUDED.signing_secret_enc, ''), chatops_slack_integrations.signing_secret_enc),
			webhook_url = EXCLUDED.webhook_url,
			is_enabled = EXCLUDED.is_enabled,
			updated_at = NOW()`

	_, err := r.db.ExecContext(ctx, query,
		si.TenantID, si.TeamID, si.AppID, si.BotTokenEnc, si.SigningSecretEnc, si.WebhookURL, si.IsEnabled)
	return err
}

func (r *sqlRepository) GetByTenant(ctx context.Context, tenantID string) (SlackIntegration, error) {
	var si SlackIntegration
	err := r.db.GetContext(ctx, &si, "SELECT * FROM chatops_slack_integrations WHERE tenant_id = $1", tenantID)
	if err != nil {
		return si, err
	}
	return r.decryptFields(ctx, si)
}

func (r *sqlRepository) GetByTeamID(ctx context.Context, teamID string) (SlackIntegration, error) {
	var si SlackIntegration
	err := r.db.GetContext(ctx, &si, "SELECT * FROM chatops_slack_integrations WHERE team_id = $1", teamID)
	if err != nil {
		return si, err
	}
	return r.decryptFields(ctx, si)
}

func (r *sqlRepository) Delete(ctx context.Context, tenantID string) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM chatops_slack_integrations WHERE tenant_id = $1", tenantID)
	return err
}

func (r *sqlRepository) decryptFields(ctx context.Context, si SlackIntegration) (SlackIntegration, error) {
	if len(si.BotTokenEnc) > 0 {
		dec, err := r.cipher.Decrypt(ctx, si.BotTokenEnc)
		if err != nil {
			return si, fmt.Errorf("failed to decrypt bot token: %w", err)
		}
		si.BotToken = string(dec)
	}

	if len(si.SigningSecretEnc) > 0 {
		dec, err := r.cipher.Decrypt(ctx, si.SigningSecretEnc)
		if err != nil {
			return si, fmt.Errorf("failed to decrypt signing secret: %w", err)
		}
		si.SigningSecret = string(dec)
	}

	return si, nil
}
