-- Certification Campaigns
CREATE TABLE IF NOT EXISTS certification_campaigns (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    status VARCHAR(50) NOT NULL DEFAULT 'draft', -- draft, active, completed, cancelled
    reviewer_id UUID NOT NULL, -- User who will review
    start_date TIMESTAMP WITH TIME ZONE,
    end_date TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Campaign Review Items (what needs to be reviewed)
CREATE TABLE IF NOT EXISTS certification_items (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    campaign_id UUID NOT NULL REFERENCES certification_campaigns(id) ON DELETE CASCADE,
    tenant_id VARCHAR(255) NOT NULL,
    user_id UUID NOT NULL, -- User whose access is being reviewed
    resource_type VARCHAR(50) NOT NULL, -- 'group', 'app', 'role'
    resource_id UUID NOT NULL,
    resource_name VARCHAR(255),
    decision VARCHAR(50), -- 'approve', 'revoke', null (pending)
    decision_at TIMESTAMP WITH TIME ZONE,
    decision_comment TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for efficient queries
CREATE INDEX idx_campaigns_tenant ON certification_campaigns(tenant_id);
CREATE INDEX idx_campaigns_status ON certification_campaigns(status);
CREATE INDEX idx_campaigns_reviewer ON certification_campaigns(reviewer_id);
CREATE INDEX idx_items_campaign ON certification_items(campaign_id);
CREATE INDEX idx_items_decision ON certification_items(decision);
