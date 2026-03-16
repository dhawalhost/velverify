CREATE TABLE IF NOT EXISTS webhooks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(255) NOT NULL,
    url TEXT NOT NULL,
    secret TEXT NOT NULL, -- HMAC secret
    events TEXT[] NOT NULL, -- Array of event names e.g. ['user.created', 'login.success']
    active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_webhooks_tenant_id ON webhooks(tenant_id);
