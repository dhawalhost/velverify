# Production Deployment Runbook (Vault + Keys + Full Config)

This runbook documents the required production configuration to run WardSeal end-to-end with Vault-backed JWT signing.

## Scope

Covers:
- Vault Transit key setup for JWT signing
- Vault AppRole setup for `authsvc`
- Required Kubernetes secrets and keys
- Helm deployment for production values
- Verification, rotation, and troubleshooting

## 1) Prerequisites

- Kubernetes cluster with production capacity
- `kubectl`, `helm`, `jq`, `vault` CLIs available
- Ingress controller installed (Traefik expected by chart values)
- DNS records configured:
  - `auth.wardseal.com`
  - `api.wardseal.com`
  - `manage.wardseal.com`
  - `wardseal.com`
- TLS cert strategy ready (cert-manager or pre-provisioned cert secret)
- Namespace: `wardseal-production`

## 2) Required Helm Configuration Contract

Current production contract (enforced by runtime validation + lint):
- `AUTH_SERVICE_URL=https://auth.wardseal.com`
- `UI_URL=https://manage.wardseal.com`
- `KMS_PROVIDER=vault`
- `authsvc.vaultAppRole.existingSecret=wardseal-vault-kms-production`

Reference values file:
- `deploy/charts/wardseal/values-production.yaml`

## 3) Vault Setup for JWT Signing

### 3.1 Enable Transit and create signing key (RSA for RS256)

```bash
export VAULT_ADDR="https://vault.example.com:8200"
vault login

# Enable transit if not already enabled
vault secrets enable transit || true

# Create RS256-compatible key (idempotent if already exists)
vault write -f transit/keys/wardseal-signing-key-production \
  type=rsa-2048 \
  exportable=false \
  allow_plaintext_backup=false

# Optional: set rotation period (example: 90 days)
vault write transit/keys/wardseal-signing-key-production/config \
  auto_rotate_period=2160h
```

### 3.2 Create policy for auth service

```bash
vault policy write wardseal-auth-production - <<'EOF'
path "transit/sign/wardseal-signing-key-production" {
  capabilities = ["create", "update"]
}

path "transit/verify/wardseal-signing-key-production" {
  capabilities = ["create", "update"]
}

path "transit/keys/wardseal-signing-key-production" {
  capabilities = ["read"]
}
EOF
```

### 3.3 Create AppRole and fetch credentials

```bash
vault auth enable approle || true

vault write auth/approle/role/wardseal-auth-production \
  token_policies="wardseal-auth-production" \
  token_ttl=1h \
  token_max_ttl=24h \
  bind_secret_id=true \
  secret_id_ttl=0 \
  secret_id_num_uses=0

ROLE_ID=$(vault read -field=role_id auth/approle/role/wardseal-auth-production/role-id)
SECRET_ID=$(vault write -field=secret_id -f auth/approle/role/wardseal-auth-production/secret-id)
```

## 4) Required Kubernetes Secrets

Create these in namespace `wardseal-production`.

### 4.1 Database secret

Secret name: `wardseal-db-credentials-production`

Required keys:
- `host`
- `port`
- `username`
- `password`
- `database`

### 4.2 Service auth secret

Secret name: `wardseal-service-auth-production`

Required keys:
- `token`
- `header` (recommended: `X-Service-Auth`)

### 4.3 Vault KMS secret (critical for JWT signing)

Secret name: `wardseal-vault-kms-production`

Required keys:
- `VAULT_ADDR`
- `VAULT_ROLE_ID`
- `VAULT_SECRET_ID`
- `VAULT_KEY_NAME` (example: `wardseal-signing-key-production`)

Recommended key:
- `VAULT_KEY_PATH` (default `transit`)

Create/update command:

```bash
kubectl create namespace wardseal-production --dry-run=client -o yaml | kubectl apply -f -

kubectl create secret generic wardseal-vault-kms-production \
  -n wardseal-production \
  --from-literal=VAULT_ADDR="https://vault.example.com:8200" \
  --from-literal=VAULT_ROLE_ID="$ROLE_ID" \
  --from-literal=VAULT_SECRET_ID="$SECRET_ID" \
  --from-literal=VAULT_KEY_NAME="wardseal-signing-key-production" \
  --from-literal=VAULT_KEY_PATH="transit" \
  --dry-run=client -o yaml | kubectl apply -f -
```

### 4.4 License secret (if enterprise license required)

Secret name: `wardseal-license-production`

Required keys:
- `LICENSE_KEY`

## 5) Deploy WardSeal (Production)

```bash
cd deploy/charts/wardseal
helm dependency update

# Base production
helm upgrade --install wardseal . \
  -n wardseal-production \
  -f values.yaml \
  -f values-production.yaml

# If using cert-manager overlay
helm upgrade --install wardseal . \
  -n wardseal-production \
  -f values.yaml \
  -f values-production.yaml \
  -f values-production-certmanager.yaml
```

## 6) Verify End-to-End

### 6.1 Manifest policy checks

```bash
bash scripts/validate_env_config.sh
```

### 6.2 Pods and health

```bash
kubectl get pods -n wardseal-production
kubectl logs -n wardseal-production deployment/wardseal-authsvc --tail=200
```

Look for successful Vault auth and no signer initialization errors.

### 6.3 OIDC endpoints

```bash
curl -s https://auth.wardseal.com/.well-known/jwks.json | jq .
curl -s https://auth.wardseal.com/t/<tenant-slug>/.well-known/openid-configuration | jq .
```

## 7) Rotation Runbook

### 7.1 Rotate Vault key version (Transit)

```bash
vault write -f transit/keys/wardseal-signing-key-production/rotate
```

Then verify JWKS still resolves and tokens continue validating.

### 7.2 Rotate AppRole secret ID

```bash
NEW_SECRET_ID=$(vault write -field=secret_id -f auth/approle/role/wardseal-auth-production/secret-id)

kubectl create secret generic wardseal-vault-kms-production \
  -n wardseal-production \
  --from-literal=VAULT_ADDR="https://vault.example.com:8200" \
  --from-literal=VAULT_ROLE_ID="$ROLE_ID" \
  --from-literal=VAULT_SECRET_ID="$NEW_SECRET_ID" \
  --from-literal=VAULT_KEY_NAME="wardseal-signing-key-production" \
  --from-literal=VAULT_KEY_PATH="transit" \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl rollout restart deployment/wardseal-authsvc -n wardseal-production
```

## 8) Troubleshooting

### `authsvc` fails to start with signer/Vault errors

- Check secret exists and has all required keys:

```bash
kubectl get secret wardseal-vault-kms-production -n wardseal-production -o yaml
```

- Confirm Helm values point to correct secret:
  - `authsvc.vaultAppRole.existingSecret=wardseal-vault-kms-production`

- Confirm Transit key exists:

```bash
vault list transit/keys
vault read transit/keys/wardseal-signing-key-production
```

### JWT/JWKS mismatch issues

- Ensure key type is RSA (`rsa-2048`) for RS256 signing.
- Confirm `VAULT_KEY_NAME` in Kubernetes secret matches actual Transit key.

## 9) GitOps / External Secrets Option

If using External Secrets Operator + ArgoCD, use:
- `deploy/argocd/external-secrets-production.yaml`
- `deploy/argocd/application-production.yaml`

Ensure Vault path `secret/wardseal/production/kms` includes:
- `vault_addr`, `role_id`, `secret_id`, `key_name` (and optionally key path in your secret model).
