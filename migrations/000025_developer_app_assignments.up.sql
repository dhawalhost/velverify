CREATE TABLE IF NOT EXISTS developer_app_assignments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(255) NOT NULL,
    app_id UUID NOT NULL REFERENCES developer_apps(id) ON DELETE CASCADE,
    user_id VARCHAR(255) NOT NULL, -- The user assigned to the app
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(tenant_id, app_id, user_id)
);

CREATE INDEX idx_developer_app_assignments_tenant ON developer_app_assignments(tenant_id);
CREATE INDEX idx_developer_app_assignments_app ON developer_app_assignments(app_id);
CREATE INDEX idx_developer_app_assignments_user ON developer_app_assignments(tenant_id, user_id);
