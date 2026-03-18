-- 000003_enforce_tenant_isolation.up.sql
-- Strengthen multi-tenant isolation by ensuring supporting tables carry tenant identifiers.

DO $$ 
BEGIN 
    IF NOT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = 'accounts'::regclass AND attname = 'tenant_id') THEN 
        ALTER TABLE accounts ADD COLUMN tenant_id VARCHAR(255); 
    END IF; 
END $$;

UPDATE accounts
SET tenant_id = identities.tenant_id
FROM identities
WHERE accounts.identity_id = identities.id;

ALTER TABLE accounts ALTER COLUMN tenant_id SET NOT NULL;

ALTER TABLE accounts DROP CONSTRAINT IF EXISTS accounts_login_key;
DO $$ 
BEGIN 
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'accounts_tenant_login_key') THEN 
        ALTER TABLE accounts ADD CONSTRAINT accounts_tenant_login_key UNIQUE (tenant_id, login); 
    END IF; 
END $$;

CREATE INDEX IF NOT EXISTS idx_accounts_tenant_id ON accounts(tenant_id);

DO $$ 
BEGIN 
    IF NOT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = 'identity_groups'::regclass AND attname = 'tenant_id') THEN 
        ALTER TABLE identity_groups ADD COLUMN tenant_id VARCHAR(255); 
    END IF; 
END $$;

UPDATE identity_groups
SET tenant_id = groups.tenant_id
FROM groups
WHERE identity_groups.group_id = groups.id;

ALTER TABLE identity_groups ALTER COLUMN tenant_id SET NOT NULL;

CREATE INDEX IF NOT EXISTS idx_identity_groups_tenant_id ON identity_groups(tenant_id);
