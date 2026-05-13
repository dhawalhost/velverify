-- 000046_performance_optimizations.up.sql

-- Composite indexes for frequent queries with ordering (cursor pagination / latest lookups)
CREATE INDEX IF NOT EXISTS idx_identities_tenant_created ON identities(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_groups_tenant_created ON groups(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_api_logs_tenant_client_created ON api_logs(tenant_id, client_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_access_requests_tenant_created ON access_requests(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant_timestamp ON audit_logs(tenant_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_workloads_tenant_created ON workloads(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_developer_apps_owner_created ON developer_apps(tenant_id, owner_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_webhooks_tenant_created ON webhooks(tenant_id, created_at DESC);

-- Indexes for Foreign Keys to avoid sequential scans on DELETE or JOINs
CREATE INDEX IF NOT EXISTS idx_identity_groups_group_id ON identity_groups(group_id);
CREATE INDEX IF NOT EXISTS idx_identity_groups_identity_id ON identity_groups(identity_id);
CREATE INDEX IF NOT EXISTS idx_approvals_request_id ON approvals(request_id);
CREATE INDEX IF NOT EXISTS idx_approvals_approver_id ON approvals(approver_id);
CREATE INDEX IF NOT EXISTS idx_role_permissions_role_id ON role_permissions(role_id);
CREATE INDEX IF NOT EXISTS idx_role_permissions_permission_id ON role_permissions(permission_id);
CREATE INDEX IF NOT EXISTS idx_user_organizations_user_id ON user_organizations(user_id);
CREATE INDEX IF NOT EXISTS idx_user_organizations_org_id ON user_organizations(org_id);
CREATE INDEX IF NOT EXISTS idx_developer_app_assignments_app_id ON developer_app_assignments(app_id);

-- Optional: Index on identities attributes (JSONB) for filtering
CREATE INDEX IF NOT EXISTS idx_identities_attributes_gin ON identities USING GIN (attributes);
