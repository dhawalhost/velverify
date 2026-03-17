CREATE TABLE IF NOT EXISTS saml_providers (
    entity_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    metadata_url TEXT,
    acs_url TEXT,
    certificate TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_saml_providers_tenant_id ON saml_providers(tenant_id);
