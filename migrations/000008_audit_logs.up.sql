-- Immutable audit log
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(255) NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
    actor_id UUID, -- User who performed the action (null for system)
    actor_type VARCHAR(50) NOT NULL DEFAULT 'user', -- user, system, service
    action VARCHAR(100) NOT NULL, -- e.g., 'user.created', 'role.assigned', 'access.approved'
    resource_type VARCHAR(100) NOT NULL, -- e.g., 'user', 'role', 'campaign', 'access_request'
    resource_id UUID,
    resource_name VARCHAR(255),
    details JSONB, -- Additional context for the event
    ip_address INET,
    user_agent TEXT,
    outcome VARCHAR(50) NOT NULL DEFAULT 'success' -- success, failure
);

-- Partitioning-ready indexes for efficient querying
CREATE INDEX idx_audit_tenant_time ON audit_logs(tenant_id, timestamp DESC);
CREATE INDEX idx_audit_actor ON audit_logs(actor_id);
CREATE INDEX idx_audit_action ON audit_logs(action);
CREATE INDEX idx_audit_resource ON audit_logs(resource_type, resource_id);
CREATE INDEX idx_audit_outcome ON audit_logs(outcome);

-- GIN index for JSONB details queries
CREATE INDEX idx_audit_details ON audit_logs USING GIN(details);
