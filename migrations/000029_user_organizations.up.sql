-- Mapping table for users and sub-organizations within a tenant
CREATE TABLE IF NOT EXISTS user_organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(255) NOT NULL,
    user_id UUID NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    role VARCHAR(50) DEFAULT 'member',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(tenant_id, user_id, org_id)
);

CREATE INDEX IF NOT EXISTS idx_user_orgs_tenant_user ON user_organizations(tenant_id, user_id);
CREATE INDEX IF NOT EXISTS idx_user_orgs_tenant_org ON user_organizations(tenant_id, org_id);

COMMENT ON TABLE user_organizations IS 'Mapping between users and sub-organizations within a tenant';
