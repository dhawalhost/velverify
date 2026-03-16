-- 000026_add_tenant_slugs.up.sql
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS slug VARCHAR(255) UNIQUE;

-- Since the DB is fresh, we don't need to backfill with 'my-org' if we want 'admin-system'
-- But we should ensure the 'admin-system' exists if it's the system tenant.

INSERT INTO tenants (id, name, slug, plan, created_at, updated_at) 
VALUES ('admin-system', 'System Admin', 'admin', 'enterprise', NOW(), NOW())
ON CONFLICT (id) DO NOTHING;

-- Create index for faster lookups
CREATE INDEX IF NOT EXISTS idx_tenants_slug ON tenants(slug);
