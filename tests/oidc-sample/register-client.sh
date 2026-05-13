#!/bin/bash

# Configuration
TENANT_ID="ws-11qvqA3LGq" # Shield Corp
TENANT_SLUG="shield-corp"
CLIENT_ID="sample-oidc-client"
CLIENT_SECRET="sample-client-secret"
# Bcrypt hash of 'sample-client-secret'
CLIENT_SECRET_HASH='$2a$10$sxJxgvHAHdnBkxHy6KDyIeH2vJ.Shs56yyqUYh0u6LFFAoWg1QJNm'
NAME="Sample OIDC App"
REDIRECT_URIS="{\"http://localhost:8080/callback\"}"
ALLOWED_SCOPES="{\"openid\",\"profile\",\"email\"}"

echo "Registering OIDC client '$CLIENT_ID' for tenant '$TENANT_SLUG' ($TENANT_ID)..."

docker exec wardseal-postgres psql -U user -d identity_platform -c "
INSERT INTO oauth_clients 
(tenant_id, client_id, client_type, name, redirect_uris, allowed_scopes, client_secret_hash)
VALUES 
('$TENANT_ID', '$CLIENT_ID', 'confidential', '$NAME', '$REDIRECT_URIS', '$ALLOWED_SCOPES', '$CLIENT_SECRET_HASH')
ON CONFLICT (tenant_id, client_id) DO UPDATE SET
name = EXCLUDED.name,
redirect_uris = EXCLUDED.redirect_uris,
allowed_scopes = EXCLUDED.allowed_scopes,
client_secret_hash = EXCLUDED.client_secret_hash;
"

echo "Done! You can now use the following credentials in your OIDC client:"
echo "------------------------------------------------------------------"
echo "Issuer:         http://auth.wardseal.local/t/$TENANT_SLUG"
echo "Client ID:      $CLIENT_ID"
echo "Client Secret:  $CLIENT_SECRET"
echo "Redirect URL:   http://localhost:8080/callback"
echo "------------------------------------------------------------------"
