-- Provisioning tasks queue
CREATE TABLE IF NOT EXISTS provisioning_tasks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(255) NOT NULL,
    connector_id UUID NOT NULL,
    operation VARCHAR(100) NOT NULL, -- create_user, delete_user, add_to_group, etc.
    resource_type VARCHAR(50) NOT NULL,
    resource_id UUID,
    payload JSONB NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'pending', -- pending, processing, completed, failed
    error_message TEXT,
    retry_count INT NOT NULL DEFAULT 0,
    max_retries INT NOT NULL DEFAULT 3,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    processed_at TIMESTAMP WITH TIME ZONE,
    scheduled_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Connector configurations
CREATE TABLE IF NOT EXISTS connectors (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    type VARCHAR(50) NOT NULL, -- ldap, azure-ad, google, scim
    enabled BOOLEAN NOT NULL DEFAULT true,
    endpoint VARCHAR(500),
    credentials BYTEA, -- Encrypted credentials
    settings JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(tenant_id, name)
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_tasks_tenant_status ON provisioning_tasks(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_tasks_scheduled ON provisioning_tasks(scheduled_at) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_connectors_tenant ON connectors(tenant_id);
CREATE INDEX IF NOT EXISTS idx_connectors_type ON connectors(type);
