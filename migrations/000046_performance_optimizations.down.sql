-- 000046_performance_optimizations.down.sql

DROP INDEX IF EXISTS idx_identities_tenant_created;
DROP INDEX IF EXISTS idx_groups_tenant_created;
DROP INDEX IF EXISTS idx_api_logs_tenant_client_created;
DROP INDEX IF EXISTS idx_access_requests_tenant_created;
DROP INDEX IF EXISTS idx_audit_logs_tenant_timestamp;
DROP INDEX IF EXISTS idx_workloads_tenant_created;
DROP INDEX IF EXISTS idx_developer_apps_owner_created;
DROP INDEX IF EXISTS idx_webhooks_tenant_created;

DROP INDEX IF EXISTS idx_identity_groups_group_id;
DROP INDEX IF EXISTS idx_identity_groups_identity_id;
DROP INDEX IF EXISTS idx_approvals_request_id;
DROP INDEX IF EXISTS idx_approvals_approver_id;
DROP INDEX IF EXISTS idx_role_permissions_role_id;
DROP INDEX IF EXISTS idx_role_permissions_permission_id;
DROP INDEX IF EXISTS idx_user_organizations_user_id;
DROP INDEX IF EXISTS idx_user_organizations_org_id;
DROP INDEX IF EXISTS idx_developer_app_assignments_app_id;

DROP INDEX IF EXISTS idx_identities_attributes_gin;
