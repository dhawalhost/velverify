-- 000044_rls_enforcement.up.sql
-- Enable PostgreSQL Row-Level Security (RLS) across multi-tenant tables.

DO $$ 
BEGIN
    -- 1. Identities
    ALTER TABLE identities ENABLE ROW LEVEL SECURITY;
    DROP POLICY IF EXISTS tenant_isolation_policy ON identities;
    CREATE POLICY tenant_isolation_policy ON identities 
        USING (tenant_id = current_setting('app.current_tenant_id', true));

    -- 2. Accounts
    ALTER TABLE accounts ENABLE ROW LEVEL SECURITY;
    DROP POLICY IF EXISTS tenant_isolation_policy ON accounts;
    CREATE POLICY tenant_isolation_policy ON accounts 
        USING (tenant_id = current_setting('app.current_tenant_id', true));

    -- 3. Organizations
    ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
    DROP POLICY IF EXISTS tenant_isolation_policy ON organizations;
    CREATE POLICY tenant_isolation_policy ON organizations 
        USING (tenant_id = current_setting('app.current_tenant_id', true));

    -- 4. OAuth Clients
    ALTER TABLE oauth_clients ENABLE ROW LEVEL SECURITY;
    DROP POLICY IF EXISTS tenant_isolation_policy ON oauth_clients;
    CREATE POLICY tenant_isolation_policy ON oauth_clients 
        USING (tenant_id = current_setting('app.current_tenant_id', true));

    -- 5. Devices
    ALTER TABLE devices ENABLE ROW LEVEL SECURITY;
    DROP POLICY IF EXISTS tenant_isolation_policy ON devices;
    CREATE POLICY tenant_isolation_policy ON devices 
        USING (tenant_id = current_setting('app.current_tenant_id', true));

END $$;
