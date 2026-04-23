-- Enterprise Discovery & Multi-Tenant Policy Migrations

-- 1. Resource Discovery Registry
CREATE TABLE IF NOT EXISTS discovered_resources (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id TEXT NOT NULL,
    connector_id UUID,
    type TEXT NOT NULL, -- 'app', 'server', 'database', 'group'
    name TEXT NOT NULL,
    external_id TEXT NOT NULL,
    metadata JSONB DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'discovered', -- 'discovered', 'managed', 'ignored'
    last_discovered_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(tenant_id, type, external_id)
);
CREATE INDEX IF NOT EXISTS idx_discovered_resources_tenant ON discovered_resources(tenant_id);
CREATE INDEX IF NOT EXISTS idx_discovered_resources_type ON discovered_resources(type);

-- 2. Multi-Tenant Policy Management
CREATE TABLE IF NOT EXISTS tenant_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id TEXT NOT NULL,
    name TEXT NOT NULL,
    rule_type TEXT NOT NULL, -- 'mfa_required', 'geo_fencing', 'device_trust'
    rule_data JSONB NOT NULL,
    is_enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_tenant_policies_tenant ON tenant_policies(tenant_id);
