-- Enforce global email uniqueness on accounts table
BEGIN;

-- Drop the tenant-scoped unique constraint
ALTER TABLE accounts DROP CONSTRAINT IF EXISTS accounts_tenant_login_key;

-- Add a global unique constraint on the login (email) column
ALTER TABLE accounts ADD CONSTRAINT accounts_login_key UNIQUE (login);

COMMIT;
