CREATE TABLE IF NOT EXISTS tenant_branding (
    tenant_id VARCHAR(255) PRIMARY KEY,
    logo_url TEXT,
    primary_color VARCHAR(7), -- Hex code e.g. #FFFFFF
    background_color VARCHAR(7),
    css_override TEXT,
    config JSONB, -- Future proofing
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
