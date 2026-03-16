-- 000001_create_initial_tables.up.sql
CREATE TABLE IF NOT EXISTS identities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(255) NOT NULL,
    status VARCHAR(20) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    attributes JSONB
);

CREATE TABLE IF NOT EXISTS accounts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    identity_id UUID NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    login VARCHAR(255) UNIQUE NOT NULL,
    credential_meta JSONB,
    last_login TIMESTAMPTZ
);

CREATE INDEX idx_identities_tenant_id ON identities(tenant_id);
CREATE INDEX idx_accounts_identity_id ON accounts(identity_id);
