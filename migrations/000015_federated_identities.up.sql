CREATE TABLE IF NOT EXISTS federated_identities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    identity_id UUID NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    tenant_id VARCHAR(255) NOT NULL,
    provider TEXT NOT NULL,
    external_id TEXT NOT NULL,
    profile_data JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, provider, external_id)
);

CREATE INDEX IF NOT EXISTS idx_federated_identities_lookup ON federated_identities(tenant_id, provider, external_id);
CREATE INDEX IF NOT EXISTS idx_federated_identities_user ON federated_identities(identity_id);
