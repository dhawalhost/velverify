-- TOTP MFA secrets table
CREATE TABLE IF NOT EXISTS totp_secrets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    identity_id VARCHAR(255) NOT NULL,  -- Email or username
    tenant_id VARCHAR(255) NOT NULL,
    secret VARCHAR(64) NOT NULL,
    verified BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    verified_at TIMESTAMP WITH TIME ZONE,
    UNIQUE(identity_id, tenant_id)
);

CREATE INDEX idx_totp_secrets_identity ON totp_secrets(identity_id);
CREATE INDEX idx_totp_secrets_tenant ON totp_secrets(tenant_id);
