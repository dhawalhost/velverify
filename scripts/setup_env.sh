#!/bin/bash
set -e

# Colors for output
GREEN='\033[0;32m'
NC='\033[0m' # No Color

echo -e "${GREEN}>>> Starting Identity Platform Setup...${NC}"

# 1. Start Infrastructure
echo -e "${GREEN}>>> Starting Postgres and Redis...${NC}"
docker compose up -d postgres redis

echo -e "${GREEN}>>> Waiting for Database to be ready...${NC}"
sleep 5
until docker exec -i identity_platform_postgres pg_isready -U user -d identity_platform > /dev/null 2>&1; do
  echo "Waiting for Postgres..."
  sleep 2
done

# 2. Apply Migrations
echo -e "${GREEN}>>> Applying Database Migrations...${NC}"
go run cmd/migrate_patch/main.go

# 3. Generate Hashes
echo -e "${GREEN}>>> Generating Credentials...${NC}"
USER_PASS="password123"
CLIENT_SECRET="secret"

# We use a temporary go helper to generate bcrypt hashes
USER_HASH=$(go run cmd/tools/hashgen/main.go "$USER_PASS")
CLIENT_HASH=$(go run cmd/tools/hashgen/main.go "$CLIENT_SECRET")

TENANT_ID="admin-system"
USER_ID=$(uuidgen || echo "00000000-0000-0000-0000-000000000001") # Fallback if uuidgen missing
CLIENT_ID="admin-ui"

# 4. Seed Data
echo -e "${GREEN}>>> Seeding Data (Tenant, User, OAuth Client)...${NC}"

docker exec -i identity_platform_postgres psql -U user -d identity_platform <<EOF
-- 1. Create Tenant (via Account/Identity is implicit, but let's ensure the identity exists)
-- We treat 'accounts' table as the user store. The tenant is technically just an ID we tag things with.

-- 2. Create Admin User
INSERT INTO identities (id, tenant_id, status)
VALUES ('$USER_ID', '$TENANT_ID', 'active')
ON CONFLICT DO NOTHING;

INSERT INTO accounts (identity_id, login, password_hash, tenant_id)
VALUES ('$USER_ID', 'admin@wardseal.com', '$USER_HASH', '$TENANT_ID')
ON CONFLICT (tenant_id, login) 
DO UPDATE SET password_hash = EXCLUDED.password_hash;

-- 3. Create OAuth Client
INSERT INTO oauth_clients (tenant_id, client_id, client_type, name, description, redirect_uris, allowed_scopes, client_secret_hash)
VALUES (
    '$TENANT_ID',
    '$CLIENT_ID',
    'public',
    'Admin Console',
    'Primary Admin UI',
    ARRAY['http://localhost:5173/callback', 'http://localhost:5173'],
    ARRAY['openid', 'profile', 'email', 'offline_access'],
    '$CLIENT_HASH'::bytea
)
ON CONFLICT (tenant_id, client_id) 
DO UPDATE SET client_secret_hash = EXCLUDED.client_secret_hash;

-- 4. Create Default Branding
INSERT INTO tenant_branding (tenant_id, logo_url, primary_color, background_color, css_override, config)
VALUES (
    '$TENANT_ID',
    'https://via.placeholder.com/150x50?text=WardSeal',
    '#007bff',
    '#f4f6f9',
    '',
    '{}'
)
ON CONFLICT (tenant_id)
DO NOTHING;

EOF

echo -e "${GREEN}>>> Setup Complete!${NC}"
echo "Tenant ID:     $TENANT_ID"
echo "Admin Login:   admin@wardseal.com"
echo "Admin Pass:    $USER_PASS"
echo "Client ID:     $CLIENT_ID"
echo "Client Secret: $CLIENT_SECRET"
echo ""
echo "You can now run the services using: ./scripts/run_local.sh"
