-- Developer Apps table for self-service app registration
CREATE TABLE IF NOT EXISTS developer_apps (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(255) NOT NULL,
    owner_id VARCHAR(255) NOT NULL,          -- User who created the app
    name VARCHAR(255) NOT NULL,
    description TEXT,
    client_id VARCHAR(64) NOT NULL UNIQUE,
    client_secret_hash VARCHAR(255) NOT NULL,
    redirect_uris JSONB DEFAULT '[]',
    grant_types JSONB DEFAULT '["authorization_code", "refresh_token"]',
    scopes JSONB DEFAULT '["openid", "profile", "email"]',
    app_type VARCHAR(50) DEFAULT 'web',      -- web, spa, native, machine
    logo_url TEXT,
    homepage_url TEXT,
    privacy_url TEXT,
    tos_url TEXT,
    status VARCHAR(50) DEFAULT 'active',     -- active, suspended, deleted
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_developer_apps_tenant ON developer_apps(tenant_id);
CREATE INDEX idx_developer_apps_owner ON developer_apps(tenant_id, owner_id);
CREATE INDEX idx_developer_apps_client_id ON developer_apps(client_id);
