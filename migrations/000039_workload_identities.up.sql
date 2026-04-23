-- Migration: Create workloads table for non-human identity
-- Path: migrations/20260419_workload_identities.sql

CREATE TABLE IF NOT EXISTS workloads (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(255) NOT NULL,
    name TEXT NOT NULL,
    service_handle TEXT NOT NULL, -- e.g. "service:authsvc" or "agent:qa-automation"
    client_id TEXT NOT NULL UNIQUE,
    client_secret_hash TEXT NOT NULL,
    metadata JSONB DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'active', -- active, suspended, rotated
    last_used_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_workloads_tenant ON workloads(tenant_id);
CREATE INDEX idx_workloads_client_id ON workloads(client_id);
CREATE INDEX idx_workloads_handle ON workloads(service_handle);

-- Composite index for tenant-scoped handle lookups
CREATE UNIQUE INDEX idx_workloads_tenant_handle ON workloads(tenant_id, service_handle);
