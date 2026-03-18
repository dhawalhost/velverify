-- Organizations table for B2B SaaS model
-- Organization = Tenant's customer (enterprise account)
CREATE TABLE IF NOT EXISTS organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    display_name VARCHAR(255),
    domain VARCHAR(255),
    domain_verified BOOLEAN DEFAULT FALSE,
    metadata JSONB DEFAULT '{}',
    settings JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(tenant_id, name)
);

CREATE INDEX IF NOT EXISTS idx_organizations_tenant ON organizations(tenant_id);
CREATE INDEX IF NOT EXISTS idx_organizations_domain ON organizations(domain) WHERE domain IS NOT NULL;

-- Add org_id to existing tables for org-scoping (optional, for future use)
-- This can be added later to users, saml_providers, etc.

COMMENT ON TABLE organizations IS 'Enterprise customer accounts belonging to a tenant (B2B SaaS model)';
