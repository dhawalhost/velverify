CREATE TABLE IF NOT EXISTS devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(255) NOT NULL,
    user_id UUID NOT NULL,
    device_identifier VARCHAR(255) NOT NULL,
    os VARCHAR(50) NOT NULL,
    os_version VARCHAR(50),
    is_managed BOOLEAN DEFAULT FALSE,
    is_compliant BOOLEAN DEFAULT TRUE,
    last_seen_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    risk_score INT DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(tenant_id, device_identifier)
);

CREATE INDEX idx_devices_user_id ON devices(user_id);
CREATE INDEX idx_devices_tenant_id ON devices(tenant_id);
