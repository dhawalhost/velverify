package oauthclients

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/lib/pq"
)

// Client represents an OAuth client registration stored in Postgres.
type Client struct {
	ID               string         `db:"id"`
	TenantID         string         `db:"tenant_id"`
	ClientID         string         `db:"client_id"`
	ClientType       string         `db:"client_type"`
	Name             string         `db:"name"`
	Description      sql.NullString `db:"description"`
	RedirectURIs     pq.StringArray `db:"redirect_uris"`
	AllowedScopes    pq.StringArray `db:"allowed_scopes"`
	ClientSecretHash []byte         `db:"client_secret_hash"`
	CreatedAt        time.Time      `db:"created_at"`
	UpdatedAt        time.Time      `db:"updated_at"`
}

// ErrNotFound indicates the requested client does not exist.
var ErrNotFound = errors.New("oauth client not found")

// Store defines the repository contract for OAuth clients.
type Store interface {
	ListClients(ctx context.Context) ([]Client, error)
	ListClientsByTenant(ctx context.Context, tenantID string) ([]Client, error)
	GetClient(ctx context.Context, tenantID, clientID string) (Client, error)
	CreateClient(ctx context.Context, params CreateClientParams) (Client, error)
	UpdateClient(ctx context.Context, tenantID, clientID string, params UpdateClientParams) (Client, error)
	DeleteClient(ctx context.Context, tenantID, clientID string) error
}

// CreateClientParams captures the fields required to create a client.
type CreateClientParams struct {
	TenantID         string
	ClientID         string
	ClientType       string
	Name             string
	Description      *string
	RedirectURIs     []string
	AllowedScopes    []string
	ClientSecretHash []byte
}

// UpdateClientParams captures the fields that can be changed for an existing client.
type UpdateClientParams struct {
	Name             *string
	Description      *string
	RedirectURIs     []string
	AllowedScopes    []string
	ClientType       *string
	ClientSecretHash *[]byte
}
