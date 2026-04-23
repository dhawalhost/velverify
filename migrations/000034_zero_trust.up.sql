-- Zero Trust Contextual Perimeter Migrations

-- 1. Temporal RBAC expansion
ALTER TABLE user_roles ADD COLUMN IF NOT EXISTS expires_at TIMESTAMP WITH TIME ZONE;
CREATE INDEX IF NOT EXISTS idx_user_roles_expires_at ON user_roles(expires_at);

-- 2. Endpoint Identity Registry
CREATE TABLE IF NOT EXISTS devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    serial TEXT NOT NULL,
    platform TEXT NOT NULL,
    os_version TEXT NOT NULL,
    trust_status TEXT NOT NULL DEFAULT 'pending',
    last_scan_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(tenant_id, serial)
);
CREATE INDEX IF NOT EXISTS idx_devices_tenant_id ON devices(tenant_id);
CREATE INDEX IF NOT EXISTS idx_devices_user_id ON devices(user_id);

-- 3. Access Request Duration & Device support
ALTER TABLE access_requests ADD COLUMN IF NOT EXISTS duration TEXT;
ALTER TABLE access_requests ADD COLUMN IF NOT EXISTS device_id TEXT;
