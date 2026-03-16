CREATE TABLE IF NOT EXISTS api_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(255) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id VARCHAR(100), -- Can be OAuth client_id or API key prefix
    method VARCHAR(10) NOT NULL,
    path VARCHAR(500) NOT NULL,
    status_code INTEGER NOT NULL,
    latency_ms INTEGER NOT NULL,
    ip_address VARCHAR(50),
    request_payload JSONB,
    response_payload JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_api_logs_tenant_id_created_at ON api_logs(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_api_logs_client_id_created_at ON api_logs(client_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_api_logs_tenant_method_status ON api_logs(tenant_id, method, status_code);
