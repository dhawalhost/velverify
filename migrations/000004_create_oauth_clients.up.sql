-- 000004_create_oauth_clients.up.sql
-- Store OAuth client registrations per tenant.

CREATE TABLE IF NOT EXISTS oauth_clients (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(255) NOT NULL,
    client_id TEXT NOT NULL,
    client_type TEXT NOT NULL DEFAULT 'public',
    name TEXT NOT NULL,
    description TEXT,
    redirect_uris TEXT[] NOT NULL,
    allowed_scopes TEXT[] NOT NULL,
    client_secret_hash BYTEA,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

DO $$ 
BEGIN 
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'oauth_clients_tenant_client_id_key') THEN 
        ALTER TABLE oauth_clients ADD CONSTRAINT oauth_clients_tenant_client_id_key UNIQUE (tenant_id, client_id); 
    END IF; 
END $$;

CREATE INDEX IF NOT EXISTS idx_oauth_clients_tenant_id ON oauth_clients(tenant_id);
