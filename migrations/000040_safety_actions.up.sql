-- Migration: Create safety_actions table for governance
-- Path: migrations/000040_safety_actions.up.sql

CREATE TABLE IF NOT EXISTS safety_actions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id TEXT NOT NULL,
    action_type TEXT NOT NULL,
    target_id TEXT NOT NULL,
    metadata JSONB DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'pending',
    reason TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_safety_actions_tenant_id ON safety_actions(tenant_id);
CREATE INDEX IF NOT EXISTS idx_safety_actions_status ON safety_actions(status);
