-- Migration: Revert tenant_id columns to UUID
-- Path: migrations/000041_fix_tenant_id_uuid.down.sql

ALTER TABLE ip_policy ALTER COLUMN tenant_id TYPE UUID USING tenant_id::uuid;
ALTER TABLE chatops_slack_integrations ALTER COLUMN tenant_id TYPE UUID USING tenant_id::uuid;
ALTER TABLE user_risk_levels ALTER COLUMN tenant_id TYPE UUID USING tenant_id::uuid;
ALTER TABLE workloads ALTER COLUMN tenant_id TYPE UUID USING tenant_id::uuid;
