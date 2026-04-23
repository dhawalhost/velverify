CREATE TABLE IF NOT EXISTS ip_policy (
    id UUID PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    type VARCHAR(10) NOT NULL CHECK (type IN ('ALLOW', 'BLOCK')),
    cidr VARCHAR(50),
    country VARCHAR(2),
    reason TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_ip_policy_tenant ON ip_policy(tenant_id);
