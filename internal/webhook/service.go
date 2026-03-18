package webhook

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

type service struct {
	db *sqlx.DB
}

// NewService creates a new webhooks service.
func NewService(db *sqlx.DB) Service {
	return &service{db: db}
}

func (s *service) CreateWebhook(ctx context.Context, tenantID, url, secret string, events []string) (string, error) {
	var id string
	err := s.db.QueryRowContext(ctx,
		`INSERT INTO webhooks (tenant_id, url, secret, events, active) 
		 VALUES ($1, $2, $3, $4, $5) RETURNING id`,
		tenantID, url, secret, pq.Array(events), true).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("create webhook: %w", err)
	}
	return id, nil
}

func (s *service) GetWebhook(ctx context.Context, tenantID, id string) (*Webhook, error) {
	var w Webhook
	err := s.db.GetContext(ctx, &w, `SELECT * FROM webhooks WHERE id = $1 AND tenant_id = $2`, id, tenantID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get webhook: %w", err)
	}
	return &w, nil
}

func (s *service) ListWebhooks(ctx context.Context, tenantID string) ([]Webhook, error) {
	var webhooks []Webhook
	err := s.db.SelectContext(ctx, &webhooks, `SELECT * FROM webhooks WHERE tenant_id = $1 ORDER BY created_at DESC`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list webhooks: %w", err)
	}
	return webhooks, nil
}

func (s *service) DeleteWebhook(ctx context.Context, tenantID, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM webhooks WHERE id = $1 AND tenant_id = $2`, id, tenantID)
	if err != nil {
		return fmt.Errorf("delete webhook: %w", err)
	}
	return nil
}

func (s *service) GetWebhooksForEvent(ctx context.Context, tenantID, event string) ([]Webhook, error) {
	var webhooks []Webhook
	// Postgres array containment operator @> or explicit check
	// Using ANY operator for better compatibility with pq.Array
	err := s.db.SelectContext(ctx, &webhooks,
		`SELECT * FROM webhooks WHERE tenant_id = $1 AND active = true AND $2 = ANY(events)`,
		tenantID, event)
	if err != nil {
		return nil, fmt.Errorf("get webhooks for event: %w", err)
	}
	return webhooks, nil
}
