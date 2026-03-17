-- SSO Identity Providers configuration
CREATE TABLE IF NOT EXISTS sso_providers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    type VARCHAR(50) NOT NULL, -- oidc, saml
    enabled BOOLEAN NOT NULL DEFAULT true,
    
    -- OIDC Configuration
    oidc_issuer_url VARCHAR(500),
    oidc_client_id VARCHAR(255),
    oidc_client_secret BYTEA, -- Encrypted
    oidc_scopes TEXT, -- Comma-separated
    
    -- SAML Configuration
    saml_entity_id VARCHAR(500),
    saml_sso_url VARCHAR(500),
    saml_slo_url VARCHAR(500),
    saml_certificate TEXT, -- PEM format
    saml_sign_requests BOOLEAN DEFAULT false,
    saml_sign_assertions BOOLEAN DEFAULT true,
    
    -- Common settings
    auto_create_users BOOLEAN DEFAULT true,
    default_role_id UUID,
    attribute_mappings JSONB, -- Map IdP attributes to user fields
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    UNIQUE(tenant_id, name)
);

CREATE INDEX IF NOT EXISTS idx_sso_providers_tenant ON sso_providers(tenant_id);
CREATE INDEX IF NOT EXISTS idx_sso_providers_type ON sso_providers(type);
