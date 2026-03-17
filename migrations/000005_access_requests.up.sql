CREATE TABLE IF NOT EXISTS access_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(255) NOT NULL,
    requester_id UUID NOT NULL REFERENCES identities(id),
    resource_type VARCHAR(50) NOT NULL, -- 'group' or 'app'
    resource_id UUID NOT NULL,          -- group_id or app_id
    status VARCHAR(20) NOT NULL DEFAULT 'pending', -- 'pending', 'approved', 'rejected'
    reason TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS approvals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id UUID NOT NULL REFERENCES access_requests(id) ON DELETE CASCADE,
    approver_id UUID REFERENCES identities(id), -- Nullable if system auto-approval
    status VARCHAR(20) NOT NULL, -- 'approved', 'rejected'
    comment TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_access_requests_tenant ON access_requests(tenant_id);
CREATE INDEX IF NOT EXISTS idx_access_requests_requester ON access_requests(requester_id);
CREATE INDEX IF NOT EXISTS idx_access_requests_status ON access_requests(status);
