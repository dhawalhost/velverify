-- 000002_add_groups_and_password_hash.up.sql
ALTER TABLE accounts ADD COLUMN password_hash VARCHAR(255);

CREATE TABLE IF NOT EXISTS groups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metadata JSONB,
    UNIQUE(tenant_id, name)
);

CREATE TABLE IF NOT EXISTS identity_groups (
    identity_id UUID NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    PRIMARY KEY (identity_id, group_id)
);

CREATE INDEX idx_groups_tenant_id ON groups(tenant_id);
