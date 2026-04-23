-- [UP] Create saml_idp_configs table
CREATE TABLE IF NOT EXISTS saml_idp_configs (
    tenant_id VARCHAR(255) PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    entity_id VARCHAR(500) NOT NULL UNIQUE,
    certificate TEXT NOT NULL,
    encrypted_key BYTEA NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_saml_idp_configs_entity_id ON saml_idp_configs(entity_id);

-- [DOWN] Drop saml_idp_configs table
-- DROP TABLE IF EXISTS saml_idp_configs;
