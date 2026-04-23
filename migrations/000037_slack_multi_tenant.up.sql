-- Migration for multi-tenant Slack integration
CREATE TABLE IF NOT EXISTS chatops_slack_integrations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(255) NOT NULL UNIQUE,
    team_id TEXT NOT NULL,
    app_id TEXT NOT NULL,
    bot_token_enc BYTEA,
    signing_secret_enc BYTEA,
    webhook_url TEXT,
    is_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Index for Slack callback resolution (team_id -> tenant_id)
CREATE INDEX idx_chatops_slack_team_id ON chatops_slack_integrations(team_id);
