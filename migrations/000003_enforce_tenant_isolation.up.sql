-- 000003_enforce_tenant_isolation.up.sql
-- Strengthen multi-tenant isolation by ensuring supporting tables carry tenant identifiers.

ALTER TABLE accounts ADD COLUMN tenant_id UUID;

UPDATE accounts
SET tenant_id = identities.tenant_id
FROM identities
WHERE accounts.identity_id = identities.id;

ALTER TABLE accounts ALTER COLUMN tenant_id SET NOT NULL;

ALTER TABLE accounts DROP CONSTRAINT IF EXISTS accounts_login_key;
ALTER TABLE accounts ADD CONSTRAINT accounts_tenant_login_key UNIQUE (tenant_id, login);

CREATE INDEX IF NOT EXISTS idx_accounts_tenant_id ON accounts(tenant_id);

ALTER TABLE identity_groups ADD COLUMN tenant_id UUID;

UPDATE identity_groups
SET tenant_id = groups.tenant_id
FROM groups
WHERE identity_groups.group_id = groups.id;

ALTER TABLE identity_groups ALTER COLUMN tenant_id SET NOT NULL;

CREATE INDEX IF NOT EXISTS idx_identity_groups_tenant_id ON identity_groups(tenant_id);
