package webhook

import (
	"context"
	"time"

	"github.com/lib/pq"
)

// Webhook represents a registered event listener.
type Webhook struct {
	ID        string         `json:"id" db:"id"`
	TenantID  string         `json:"tenant_id" db:"tenant_id"`
	URL       string         `json:"url" db:"url"`
	Secret    string         `json:"secret" db:"secret"`
	Events    pq.StringArray `json:"events" db:"events"`
	Active    bool           `json:"active" db:"active"`
	CreatedAt time.Time      `json:"created_at" db:"created_at"`
	UpdatedAt time.Time      `json:"updated_at" db:"updated_at"`
}

// Service defines the interface for managing webhooks.
type Service interface {
	CreateWebhook(ctx context.Context, tenantID, url, secret string, events []string) (string, error)
	GetWebhook(ctx context.Context, tenantID, id string) (*Webhook, error)
	ListWebhooks(ctx context.Context, tenantID string) ([]Webhook, error)
	DeleteWebhook(ctx context.Context, tenantID, id string) error
	GetWebhooksForEvent(ctx context.Context, tenantID, event string) ([]Webhook, error)
}
