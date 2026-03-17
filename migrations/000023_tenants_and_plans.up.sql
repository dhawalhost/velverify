CREATE TABLE IF NOT EXISTS tenants (
    id VARCHAR(255) PRIMARY KEY,
    name VARCHAR(255) NOT NULL DEFAULT 'My Organization',
    plan VARCHAR(50) NOT NULL DEFAULT 'free',
    license_key TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Backfill existing tenants from identities
INSERT INTO tenants (id, created_at, updated_at)
SELECT DISTINCT tenant_id, NOW(), NOW()
FROM identities
ON CONFLICT (id) DO NOTHING;

-- Optional: Add FK constraint now that we have the parent table
-- ALTER TABLE identities ADD CONSTRAINT fk_identities_tenant_id FOREIGN KEY (tenant_id) REFERENCES tenants(id);
-- ALTER TABLE accounts ADD CONSTRAINT fk_accounts_tenant_id FOREIGN KEY (tenant_id) REFERENCES tenants(id);
