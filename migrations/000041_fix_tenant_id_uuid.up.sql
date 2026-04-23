-- Migration: Fix tenant_id UUID columns to VARCHAR(255) to support string-based cross-tenant routing
-- Path: migrations/000041_fix_tenant_id_uuid.up.sql

ALTER TABLE ip_policy ALTER COLUMN tenant_id TYPE VARCHAR(255) USING tenant_id::varchar;
ALTER TABLE chatops_slack_integrations ALTER COLUMN tenant_id TYPE VARCHAR(255) USING tenant_id::varchar;
ALTER TABLE user_risk_levels ALTER COLUMN tenant_id TYPE VARCHAR(255) USING tenant_id::varchar;
ALTER TABLE workloads ALTER COLUMN tenant_id TYPE VARCHAR(255) USING tenant_id::varchar;
