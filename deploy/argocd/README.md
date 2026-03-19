# WardSeal + Vault Integration

This guide explains how WardSeal integrates with your existing HashiCorp Vault deployment.

## Overview

Your Vault is deployed at:
- **External URL:** https://vault.dhawalhost.com
- **Internal K8s Service:** http://vault.vault.svc.cluster.local:8200
- **Namespace:** `vault`
- **Mode:** Standalone
- **TLS:** Terminated at ingress (HTTP internally)

WardSeal uses **External Secrets Operator** to sync secrets from Vault to Kubernetes automatically.

## Service-wise Versioning and Manual Promotion

WardSeal now supports independent service image versioning by environment.

### Version Files

- Staging versions: `deploy/charts/wardseal/values-staging-versions.yaml`
- Production versions: `deploy/charts/wardseal/values-production-versions.yaml`

Each file contains independent image tags for:

- `authsvc`
- `dirsvc`
- `govsvc`
- `policysvc`
- `provsvc`
- `adminui`
- `landingui`

Update only the service you want to promote; leave others unchanged.

### Build/Push Workflow (Single Service)

Use the `CI/CD` workflow in GitHub Actions with **Run workflow** and provide:

- `service`: service to build (`authsvc`, `dirsvc`, `govsvc`, `policysvc`, `provsvc`, `adminui`, `landingui`)
- `version`: base semantic version (example: `v1.2.3` or `1.2.3`; workflow normalizes to `v*`)
- `tag_suffix`: optional extra suffix (example: `rc1`)
- `push_latest`: whether to also push `latest`
- `skip_if_exists`: skip build if the computed tag already exists in GHCR

This builds and pushes only the selected service image to GHCR.

### Tag Strategy

**Docker image tag** (pushed to GHCR) — plain version only:

- `v1.2.3` (example: `ghcr.io/org/wardseal-authsvc:v1.2.3`)
- `latest` (if `push_latest=true`)

**Git commit tag** (uniquely identifies which service and version was released):

- Default: `<version>-<service>` (example: `v1.2.3-authsvc`)
- With suffix: `<version>-<service>-<tag_suffix>` (example: `v1.2.3-authsvc-rc1`)

The git tag is the skip-if-exists key — if `v1.2.3-authsvc` already exists in git, the build is skipped when `skip_if_exists=true`.

**Values files** store the plain docker tag (e.g. `v1.2.3`). Different services can carry independent versions.

### Deployment via Argo CD UI

1. Update the relevant environment version file for the target service tag.
2. Commit and push the change.
3. In Argo CD UI, sync the application for that environment.

`ApplyOutOfSyncOnly=true` is enabled in the Argo CD app manifests, so only out-of-sync resources are applied.

## Deployment Runbook (Staging and Production)

This runbook covers first-time bootstrap, ongoing releases, full-environment rollouts, and rollback for both environments.

### 0. Preconditions

- Kubernetes cluster and Argo CD are installed and healthy.
- External Secrets Operator is installed.
- Vault policies and AppRoles are created for staging and production.
- GHCR push permissions are configured for GitHub Actions.

Validate local repo config before any rollout:

```bash
make config-lint
```

### 1. One-time bootstrap per environment

#### 1.1 Create namespaces

```bash
kubectl create namespace wardseal-staging --dry-run=client -o yaml | kubectl apply -f -
kubectl create namespace wardseal-production --dry-run=client -o yaml | kubectl apply -f -
```

#### 1.2 Create Vault AppRole bootstrap secret in each namespace

```bash
# staging
kubectl create secret generic wardseal-vault-approle \
  --namespace wardseal-staging \
  --from-literal=role_id="<STAGING_ROLE_ID>" \
  --from-literal=secret_id="<STAGING_SECRET_ID>" \
  --dry-run=client -o yaml | kubectl apply -f -

# production
kubectl create secret generic wardseal-vault-approle \
  --namespace wardseal-production \
  --from-literal=role_id="<PROD_ROLE_ID>" \
  --from-literal=secret_id="<PROD_SECRET_ID>" \
  --dry-run=client -o yaml | kubectl apply -f -
```

#### 1.3 Apply External Secrets manifests

```bash
kubectl apply -f deploy/argocd/external-secrets-staging.yaml
kubectl apply -f deploy/argocd/external-secrets-production.yaml
```

#### 1.4 Verify synced Kubernetes secrets

```bash
kubectl get externalsecrets -n wardseal-staging
kubectl get externalsecrets -n wardseal-production

kubectl get secrets -n wardseal-staging | grep wardseal
kubectl get secrets -n wardseal-production | grep wardseal
```

Expected key secrets:

- Staging: `wardseal-db-credentials-staging`, `wardseal-service-auth-staging`, `wardseal-vault-kms-staging`
- Production: `wardseal-db-credentials-production`, `wardseal-service-auth-production`, `wardseal-vault-kms-production`, `wardseal-license-production`

#### 1.5 Register Argo CD applications

Use either application manifest set:

- General app manifests: `deploy/argocd/application-staging.yaml`, `deploy/argocd/application-production.yaml`
- Alternative app manifests: `deploy/argocd/wardseal-staging.yaml`, `deploy/argocd/wardseal-production.yaml`

```bash
kubectl apply -n argocd -f deploy/argocd/application-staging.yaml
kubectl apply -n argocd -f deploy/argocd/application-production.yaml
```

### 2. Regular release workflow (single service)

#### 2.1 Build and push the selected service image

In GitHub Actions, run `CI/CD` workflow manually with:

- `service`: one of `authsvc`, `dirsvc`, `govsvc`, `policysvc`, `provsvc`, `adminui`, `landingui`
- `version`: semver (for example `0.1.1` or `v0.1.1`)
- `tag_suffix`: optional (for example `rc1`)
- `push_latest`: optional latest image push
- `platforms`: target architectures (default `linux/amd64,linux/arm64`)
- `skip_if_exists`: skip when git release tag already exists

Output behavior:

- Docker image tag pushed to GHCR: version only (for example `v0.1.1`)
- Git release tag created: service-specific (for example `v0.1.1-authsvc`)

#### 2.2 Promote to staging or production by updating only one service tag

Update one service in:

- Staging file: `deploy/charts/wardseal/values-staging-versions.yaml`
- Production file: `deploy/charts/wardseal/values-production-versions.yaml`

Example:

```yaml
authsvc:
  image:
    tag: "v0.1.1"
```

Commit and push.

#### 2.3 Sync Argo CD

- Staging app: sync `wardseal-staging`
- Production app: sync `wardseal-production`

Production should be manually approved/synced.

### 3. Full environment rollout (all services)

Use this when you intentionally want every service updated.

1. Build/push each service with the target version via workflow runs.
2. Update all service tags in the target environment versions file.
3. Commit and push one PR with all tag updates.
4. Sync the target Argo CD app once.

## Service-isolated Argo CD Applications

To track and sync services independently, use the new manifests under:

- `deploy/argocd/services/`

### What is added

For each environment, there are separate apps for:

- `authsvc`, `dirsvc`, `govsvc`, `policysvc`, `provsvc`, `adminui`, `landingui`, `ingress`

Each service app uses its own chart path (`deploy/charts/<service>`) and local values files:

- `values-staging.yaml` or `values-production.yaml`
- `version-staging.yaml` or `version-production.yaml`

`ingress` remains a dedicated app on the umbrella chart and uses `services/ingress/selector.yaml`.

### Apply service-isolated apps

```bash
# staging
kubectl apply -n argocd -f deploy/argocd/services/staging-authsvc.yaml
kubectl apply -n argocd -f deploy/argocd/services/staging-dirsvc.yaml
kubectl apply -n argocd -f deploy/argocd/services/staging-govsvc.yaml
kubectl apply -n argocd -f deploy/argocd/services/staging-policysvc.yaml
kubectl apply -n argocd -f deploy/argocd/services/staging-provsvc.yaml
kubectl apply -n argocd -f deploy/argocd/services/staging-adminui.yaml
kubectl apply -n argocd -f deploy/argocd/services/staging-landingui.yaml
kubectl apply -n argocd -f deploy/argocd/services/staging-ingress.yaml

# production
kubectl apply -n argocd -f deploy/argocd/services/production-authsvc.yaml
kubectl apply -n argocd -f deploy/argocd/services/production-dirsvc.yaml
kubectl apply -n argocd -f deploy/argocd/services/production-govsvc.yaml
kubectl apply -n argocd -f deploy/argocd/services/production-policysvc.yaml
kubectl apply -n argocd -f deploy/argocd/services/production-provsvc.yaml
kubectl apply -n argocd -f deploy/argocd/services/production-adminui.yaml
kubectl apply -n argocd -f deploy/argocd/services/production-landingui.yaml
kubectl apply -n argocd -f deploy/argocd/services/production-ingress.yaml
```

### Important migration note

Do not keep the old umbrella apps (`wardseal-staging` / `wardseal-production` or `application-staging` / `application-production`) active at the same time as service-isolated apps in the same namespace, or Argo CD resource ownership conflicts can occur.

### 4. Post-deploy verification checklist

```bash
kubectl get pods -n wardseal-staging
kubectl get pods -n wardseal-production

kubectl get ingress -n wardseal-staging
kubectl get ingress -n wardseal-production

kubectl get externalsecrets -n wardseal-staging
kubectl get externalsecrets -n wardseal-production
```

Recommended smoke checks:

- `https://auth-staging.wardseal.com/health/ready`
- `https://api-staging.wardseal.com/health/ready`
- `https://auth.wardseal.com/health/ready`
- `https://api.wardseal.com/health/ready`

### 5. Rollback procedure

1. Edit environment versions file and revert only impacted services to prior known-good image tags.
2. Commit and push rollback change.
3. Sync corresponding Argo CD application.

Fast rollback is version-file based; no image rebuild is required.

## Architecture

```
┌──────────────────────────────────────────────────────┐
│  Kubernetes Cluster                                   │
│                                                       │
│  ┌─────────────────┐       ┌────────────────────┐   │
│  │  External       │       │  Vault Server      │   │
│  │  Secrets        │◄──────┤  vault.vault:8200  │   │
│  │  Operator       │       │                    │   │
│  └────────┬────────┘       └────────────────────┘   │
│           │                                          │
│           │ Creates K8s Secrets                      │
│           ▼                                          │
│  ┌─────────────────────────────────┐                │
│  │  K8s Secrets (auto-synced)      │                │
│  │  - wardseal-db-credentials      │                │
│  │  - wardseal-service-auth        │                │
│  │  - wardseal-vault-kms           │                │
│  └────────┬────────────────────────┘                │
│           │                                          │
│           │ Mounted as env vars                      │
│           ▼                                          │
│  ┌─────────────────────────────────┐                │
│  │  WardSeal Pods                  │                │
│  │  - authsvc                      │                │
│  │  - dirsvc                       │                │
│  │  - govsvc                       │                │
│  └─────────────────────────────────┘                │
│                                                       │
└──────────────────────────────────────────────────────┘
```

## Vault Configuration Required

Based on your existing Vault setup, you need to configure:

### 1. Enable KV v2 Secrets Engine

```bash
# Port-forward to Vault (if accessing from local)
kubectl port-forward -n vault svc/vault 8200:8200

# Set Vault address
export VAULT_ADDR='http://localhost:8200'

# Login to Vault
vault login

# Enable KV v2 secrets engine (if not already enabled)
vault secrets enable -path=secret kv-v2
```

### 2. Create Vault Policies

Create policies for WardSeal to read secrets:

```bash
# Staging policy
cat <<EOF | vault policy write wardseal-staging-policy -
# Allow reading staging secrets
path "secret/data/wardseal/staging/*" {
  capabilities = ["read", "list"]
}

path "secret/metadata/wardseal/staging/*" {
  capabilities = ["list"]
}
EOF

# Production policy
cat <<EOF | vault policy write wardseal-production-policy -
# Allow reading production secrets
path "secret/data/wardseal/production/*" {
  capabilities = ["read", "list"]
}

path "secret/metadata/wardseal/production/*" {
  capabilities = ["list"]
}
EOF
```

### 3. Configure AppRole Authentication

```bash
# Enable AppRole (if not already enabled)
vault auth enable approle

# Create AppRole for staging
vault write auth/approle/role/wardseal-staging \
  token_ttl=1h \
  token_max_ttl=4h \
  token_policies="wardseal-staging-policy" \
  bind_secret_id=true \
  secret_id_num_uses=0 \
  secret_id_ttl=0

# Create AppRole for production
vault write auth/approle/role/wardseal-production \
  token_ttl=1h \
  token_max_ttl=4h \
  token_policies="wardseal-production-policy" \
  bind_secret_id=true \
  secret_id_num_uses=0 \
  secret_id_ttl=0
```

### 4. Get AppRole Credentials

```bash
# Get staging credentials
STAGING_ROLE_ID=$(vault read -field=role_id auth/approle/role/wardseal-staging/role-id)
STAGING_SECRET_ID=$(vault write -field=secret_id -f auth/approle/role/wardseal-staging/secret-id)

echo "Staging Role ID: ${STAGING_ROLE_ID}"
echo "Staging Secret ID: ${STAGING_SECRET_ID}"

# Get production credentials
PROD_ROLE_ID=$(vault read -field=role_id auth/approle/role/wardseal-production/role-id)
PROD_SECRET_ID=$(vault write -field=secret_id -f auth/approle/role/wardseal-production/secret-id)

echo "Production Role ID: ${PROD_ROLE_ID}"
echo "Production Secret ID: ${PROD_SECRET_ID}"
```

## Setting Up WardSeal Integration

### Step 1: Add Secrets to Vault

Use the interactive script:

```bash
# For staging
./deploy/argocd/setup-vault-secrets.sh staging

# For production
./deploy/argocd/setup-vault-secrets.sh production
```

Or manually create secrets following [VAULT_SETUP.md](VAULT_SETUP.md).

### Step 2: Create Bootstrap Secrets in Kubernetes

These secrets allow External Secrets Operator to authenticate with Vault:

```bash
# Staging
kubectl create namespace wardseal-staging
kubectl create secret generic wardseal-vault-approle \
  --namespace wardseal-staging \
  --from-literal=role_id="${STAGING_ROLE_ID}" \
  --from-literal=secret_id="${STAGING_SECRET_ID}"

# Production
kubectl create namespace wardseal-production
kubectl create secret generic wardseal-vault-approle \
  --namespace wardseal-production \
  --from-literal=role_id="${PROD_ROLE_ID}" \
  --from-literal=secret_id="${PROD_SECRET_ID}"
```

### Step 3: Deploy External Secrets Configuration

```bash
# Apply staging external secrets
kubectl apply -f deploy/argocd/external-secrets-staging.yaml

# Apply production external secrets
kubectl apply -f deploy/argocd/external-secrets-production.yaml
```

### Step 4: Verify Secret Sync

```bash
# Check ExternalSecret resources
kubectl get externalsecrets -n wardseal-staging
kubectl get externalsecrets -n wardseal-production

# Check if secrets were created
kubectl get secrets -n wardseal-staging | grep wardseal
kubectl get secrets -n wardseal-production | grep wardseal

# Describe an ExternalSecret to see sync status
kubectl describe externalsecret wardseal-db-credentials-staging -n wardseal-staging
```

### Step 5: Deploy WardSeal via ArgoCD

```bash
# Apply staging
kubectl apply -f deploy/argocd/application-staging.yaml -n argocd

# Apply production (manual sync)
kubectl apply -f deploy/argocd/application-production.yaml -n argocd
argocd app sync wardseal-production
```

## Configuration Details

### Vault Paths Used by WardSeal

| Environment | Vault Path | Purpose |
|-------------|------------|---------|
| Staging | `secret/wardseal/staging/database` | PostgreSQL credentials |
| Staging | `secret/wardseal/staging/service-auth` | Service-to-service auth token |
| Staging | `secret/wardseal/staging/kms` | Vault KMS config for encryption |
| Production | `secret/wardseal/production/database` | PostgreSQL credentials |
| Production | `secret/wardseal/production/service-auth` | Service-to-service auth token |
| Production | `secret/wardseal/production/kms` | Vault KMS config for encryption |
| Production | `secret/wardseal/production/license` | Enterprise license key |

### Kubernetes Secrets Created by ESO

| Secret Name | Vault Source | Namespace |
|-------------|--------------|-----------|
| `wardseal-db-credentials-staging` | `secret/wardseal/staging/database` | `wardseal-staging` |
| `wardseal-service-auth-staging` | `secret/wardseal/staging/service-auth` | `wardseal-staging` |
| `wardseal-vault-kms-staging` | `secret/wardseal/staging/kms` | `wardseal-staging` |
| `wardseal-db-credentials-production` | `secret/wardseal/production/database` | `wardseal-production` |
| `wardseal-service-auth-production` | `secret/wardseal/production/service-auth` | `wardseal-production` |
| `wardseal-vault-kms-production` | `secret/wardseal/production/kms` | `wardseal-production` |
| `wardseal-license-production` | `secret/wardseal/production/license` | `wardseal-production` |

## Accessing Vault

### From Local Machine

```bash
# Via port-forward
kubectl port-forward -n vault svc/vault 8200:8200
export VAULT_ADDR='http://localhost:8200'
vault login
```

### From Within Cluster

```bash
# Pods in the cluster can access Vault at:
# http://vault.vault.svc.cluster.local:8200
```

### Via Web UI

Access the Vault UI at: https://vault.dhawalhost.com

## Troubleshooting

### ExternalSecret not syncing

```bash
# Check ESO logs
kubectl logs -n external-secrets-system deployment/external-secrets -f

# Check ExternalSecret status
kubectl describe externalsecret wardseal-db-credentials-staging -n wardseal-staging

# Verify bootstrap secret exists
kubectl get secret wardseal-vault-approle -n wardseal-staging -o yaml
```

### Cannot authenticate to Vault

```bash
# Test AppRole authentication
vault write auth/approle/login \
  role_id="${STAGING_ROLE_ID}" \
  secret_id="${STAGING_SECRET_ID}"

# Verify policy is attached
vault read auth/approle/role/wardseal-staging
```

### Secret not updating in pods

```bash
# Check secret content
kubectl get secret wardseal-db-credentials-staging -n wardseal-staging -o yaml

# Force pod restart to pick up new values
kubectl rollout restart deployment/wardseal-authsvc -n wardseal-staging
```

## Security Considerations

1. **Bootstrap Secrets**: The `wardseal-vault-approle` secrets are the only secrets stored in K8s directly. Keep these secure.

2. **Vault Unsealing**: Your Vault is in standalone mode. Ensure you have a process to unseal it after pod restarts.

3. **Rotation**: Regularly rotate:
   - Database passwords: Every 90 days
   - Service tokens: Every 30 days
   - AppRole Secret IDs: Every 180 days

4. **Network Policies**: Consider adding network policies to restrict which pods can access Vault.

5. **Audit Logging**: Enable Vault audit logs:
   ```bash
   vault audit enable file file_path=/vault/logs/audit.log
   ```

## Next Steps

1. ✅ Set up Vault secrets following [VAULT_SETUP.md](VAULT_SETUP.md)
2. ✅ Create AppRole authentication and policies
3. ✅ Create bootstrap secrets in Kubernetes
4. ✅ Deploy External Secrets configuration
5. ✅ Verify secret sync
6. ✅ Deploy WardSeal via ArgoCD

## Reference Documentation

- [VAULT_SETUP.md](VAULT_SETUP.md) - Complete Vault setup guide
- [SECRETS_REFERENCE.md](SECRETS_REFERENCE.md) - Quick reference for all secrets
- [Existing Vault Deployment](/Users/dhawal.dyavanpalli/go/src/argocd-infra/vault/README.md) - Your Vault infrastructure docs
- [Vault-WardSeal Integration Guide](/Users/dhawal.dyavanpalli/go/src/argocd-infra/vault/VAULT_WARDSEAL_INTEGRATION.md) - Detailed integration guide
