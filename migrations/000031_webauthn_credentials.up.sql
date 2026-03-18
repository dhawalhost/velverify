-- WebAuthn Credentials
CREATE TABLE IF NOT EXISTS webauthn_credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(255) NOT NULL,
    user_id UUID NOT NULL,
    credential_id BYTEA NOT NULL,
    public_key BYTEA NOT NULL,
    attestation_type VARCHAR(50),
    aaguid BYTEA,
    sign_count BIGINT NOT NULL DEFAULT 0,
    clone_warning BOOLEAN NOT NULL DEFAULT FALSE,
    friendly_name VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_webauthn_user ON webauthn_credentials(user_id);
CREATE INDEX IF NOT EXISTS idx_webauthn_tenant ON webauthn_credentials(tenant_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_webauthn_credential_id ON webauthn_credentials(credential_id);
