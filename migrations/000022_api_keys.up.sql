-- API Keys / Personal Access Tokens
CREATE TABLE IF NOT EXISTS api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(255) NOT NULL,
    owner_id VARCHAR(255) NOT NULL,          -- User who created the key
    name VARCHAR(255) NOT NULL,
    key_prefix VARCHAR(12) NOT NULL,         -- First 12 chars for display (vv_live_xxx)
    key_hash VARCHAR(255) NOT NULL,          -- bcrypt hash of full key
    scopes JSONB DEFAULT '["read"]',
    expires_at TIMESTAMP WITH TIME ZONE,     -- NULL = never expires
    last_used_at TIMESTAMP WITH TIME ZONE,
    status VARCHAR(50) DEFAULT 'active',     -- active, revoked
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_api_keys_tenant ON api_keys(tenant_id);
CREATE INDEX idx_api_keys_owner ON api_keys(tenant_id, owner_id);
CREATE INDEX idx_api_keys_prefix ON api_keys(key_prefix);
