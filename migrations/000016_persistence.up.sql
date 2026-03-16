-- Persistent storage for OAuth2 tokens and authorization codes
-- This ensures sessions survive server restarts

CREATE TABLE IF NOT EXISTS authorization_codes (
    code VARCHAR(255) PRIMARY KEY,
    client_id VARCHAR(255) NOT NULL,
    redirect_uri TEXT NOT NULL,
    scope TEXT,
    tenant_id VARCHAR(255) NOT NULL,
    code_challenge VARCHAR(255) NOT NULL,
    code_challenge_method VARCHAR(10) DEFAULT 'S256',
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_auth_codes_expires ON authorization_codes(expires_at);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    token VARCHAR(255) PRIMARY KEY,
    client_id VARCHAR(255) NOT NULL,
    tenant_id VARCHAR(255) NOT NULL,
    scope TEXT,
    subject_type VARCHAR(50) DEFAULT 'user',
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_refresh_tokens_expires ON refresh_tokens(expires_at);
CREATE INDEX idx_refresh_tokens_client ON refresh_tokens(client_id);

CREATE TABLE IF NOT EXISTS revoked_tokens (
    token_hash VARCHAR(64) PRIMARY KEY,
    revoked_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_revoked_tokens_revoked_at ON revoked_tokens(revoked_at);
