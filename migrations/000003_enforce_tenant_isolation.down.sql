-- 000003_enforce_tenant_isolation.down.sql
-- Revert tenant isolation additions from migration 000003.

DROP INDEX IF EXISTS idx_identity_groups_tenant_id;
ALTER TABLE identity_groups DROP COLUMN IF EXISTS tenant_id;

ALTER TABLE accounts DROP CONSTRAINT IF EXISTS accounts_tenant_login_key;
DROP INDEX IF EXISTS idx_accounts_tenant_id;
ALTER TABLE accounts DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE accounts ADD CONSTRAINT accounts_login_key UNIQUE (login);
