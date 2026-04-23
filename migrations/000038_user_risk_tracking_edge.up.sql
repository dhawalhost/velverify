-- Migration: Track user risk levels for autonomous response
-- Path: migrations/20260419_user_risk_tracking_edge.sql

CREATE TABLE IF NOT EXISTS user_risk_levels (
    user_id UUID PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    score INTEGER NOT NULL DEFAULT 0,
    level TEXT NOT NULL DEFAULT 'LOW', -- LOW, MEDIUM, HIGH
    factors JSONB DEFAULT '[]',
    last_evaluated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_user_risk_tenant ON user_risk_levels(tenant_id);
CREATE INDEX idx_user_risk_level ON user_risk_levels(level) WHERE level = 'HIGH';
