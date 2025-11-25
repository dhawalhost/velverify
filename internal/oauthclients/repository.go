package oauthclients

import (
	"context"
	"database/sql"

	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

// Repository provides CRUD helpers for oauth_clients.
type Repository struct {
	db *sqlx.DB
}

// NewRepository creates a new Repository instance.
func NewRepository(db *sqlx.DB) *Repository {
	return &Repository{db: db}
}

// ListClients returns all OAuth clients across tenants.
func (r *Repository) ListClients(ctx context.Context) ([]Client, error) {
	var clients []Client
	err := r.db.SelectContext(ctx, &clients, `SELECT id, tenant_id, client_id, client_type, name, description,
        redirect_uris, allowed_scopes, client_secret_hash, created_at, updated_at FROM oauth_clients`)
	return clients, err
}

// ListClientsByTenant returns all clients for a tenant.
func (r *Repository) ListClientsByTenant(ctx context.Context, tenantID string) ([]Client, error) {
	var clients []Client
	err := r.db.SelectContext(ctx, &clients, `SELECT id, tenant_id, client_id, client_type, name, description,
        redirect_uris, allowed_scopes, client_secret_hash, created_at, updated_at
        FROM oauth_clients WHERE tenant_id = $1`, tenantID)
	return clients, err
}

// GetClient fetches a client by tenant and client_id.
func (r *Repository) GetClient(ctx context.Context, tenantID, clientID string) (Client, error) {
	var client Client
	err := r.db.GetContext(ctx, &client, `SELECT id, tenant_id, client_id, client_type, name, description,
        redirect_uris, allowed_scopes, client_secret_hash, created_at, updated_at
        FROM oauth_clients WHERE tenant_id = $1 AND client_id = $2`, tenantID, clientID)
	if err != nil {
		if err == sql.ErrNoRows {
			return Client{}, ErrNotFound
		}
		return Client{}, err
	}
	return client, nil
}

// CreateClient inserts a new OAuth client.
func (r *Repository) CreateClient(ctx context.Context, params CreateClientParams) (Client, error) {
	var client Client
	err := r.db.GetContext(ctx, &client, `INSERT INTO oauth_clients
        (tenant_id, client_id, client_type, name, description, redirect_uris, allowed_scopes, client_secret_hash)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        RETURNING id, tenant_id, client_id, client_type, name, description, redirect_uris,
                  allowed_scopes, client_secret_hash, created_at, updated_at`,
		params.TenantID, params.ClientID, params.ClientType, params.Name,
		nullableString(params.Description), pq.StringArray(params.RedirectURIs),
		pq.StringArray(params.AllowedScopes), params.ClientSecretHash)
	return client, err
}

// UpdateClient updates mutable fields on an OAuth client.

func (r *Repository) UpdateClient(ctx context.Context, tenantID, clientID string, params UpdateClientParams) (Client, error) {
	_, err := r.db.ExecContext(ctx, `UPDATE oauth_clients
        SET name = COALESCE($1, name),
            description = COALESCE($2, description),
            redirect_uris = COALESCE($3::text[], redirect_uris),
            allowed_scopes = COALESCE($4::text[], allowed_scopes),
            client_type = COALESCE($5, client_type),
            client_secret_hash = COALESCE($6::bytea, client_secret_hash),
            updated_at = NOW()
        WHERE tenant_id = $7 AND client_id = $8`,
		params.Name, nullableString(params.Description), nullableStringArray(params.RedirectURIs),
		nullableStringArray(params.AllowedScopes), params.ClientType, nullableBytea(params.ClientSecretHash), tenantID, clientID)
	if err != nil {
		return Client{}, err
	}
	return r.GetClient(ctx, tenantID, clientID)
}

// DeleteClient removes an OAuth client registration.
func (r *Repository) DeleteClient(ctx context.Context, tenantID, clientID string) error {
	result, err := r.db.ExecContext(ctx, `DELETE FROM oauth_clients WHERE tenant_id = $1 AND client_id = $2`, tenantID, clientID)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

func nullableString(value *string) sql.NullString {
	if value == nil {
		return sql.NullString{Valid: false}
	}
	return sql.NullString{String: *value, Valid: true}
}

func nullableStringArray(values []string) interface{} {
	if values == nil {
		return nil
	}
	return pq.StringArray(values)
}

func nullableBytea(value *[]byte) interface{} {
	if value == nil {
		return nil
	}
	return *value
}
