# Staging Deployment Guide

This guide explains how to deploy wardseal with HashiCorp Vault integration to a staging Kubernetes cluster.

## Overview

The staging environment setup consists of two main scripts:
1. **setup_vault_staging.sh** - Deploys and configures HashiCorp Vault
2. **deploy_wardseal_staging.sh** - Deploys the Wardseal application

## Prerequisites

### Required Tools
- **Kubernetes Cluster**: Staging cluster with appropriate resources
- **kubectl**: Configured to access your staging cluster
- **Helm 3**: Package manager for Kubernetes
- **jq**: JSON processor for parsing Vault credentials
- **cert-manager** (recommended): For automatic TLS certificate management

### Verify Prerequisites

```bash
# Check Kubernetes cluster
kubectl cluster-info

# Check Helm
helm version

# Check jq
jq --version

# Check cert-manager (optional but recommended)
kubectl get pods -n cert-manager
```

### Install Missing Tools

```bash
# macOS
brew install kubectl helm jq

# Linux
# kubectl: https://kubernetes.io/docs/tasks/tools/
# helm: https://helm.sh/docs/intro/install/
# jq: apt-get install jq or yum install jq
```

### Install cert-manager (Recommended)

```bash
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.13.0/cert-manager.yaml
```

## Quick Start

The easiest way to get started is to run the deployment scripts in order:

```bash
# 1. Deploy and configure Vault
./scripts/setup_vault_staging.sh

# 2. Deploy Wardseal application
./scripts/deploy_wardseal_staging.sh
```

## Step-by-Step Deployment

### 1. Prepare TLS Certificates for Vault

Staging requires TLS for Vault. You have two options:

#### Option A: Using cert-manager (Recommended)

```bash
cat <<EOF | kubectl apply -f -
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: vault-staging
  namespace: vault-staging
spec:
  secretName: vault-staging-tls
  issuerRef:
    name: letsencrypt-prod
    kind: ClusterIssuer
  dnsNames:
    - vault-staging.dhawalhost.com
EOF
```

#### Option B: Self-Signed Certificate (Testing Only)

```bash
# Generate self-signed certificate
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout tls.key -out tls.crt \
  -subj "/CN=vault-staging.dhawalhost.com"

# Create namespace
kubectl create namespace vault-staging

# Create secret
kubectl create secret tls vault-staging-tls \
  --cert=tls.crt --key=tls.key -n vault-staging

# Clean up local files
rm tls.key tls.crt
```

### 2. Deploy HashiCorp Vault

Run the Vault setup script:

```bash
./scripts/setup_vault_staging.sh
```

The script performs the following:
- Creates `vault-staging` namespace
- Deploys Vault using official Helm chart with staging values
- Initializes Vault (3 key shares, threshold of 2)
- Unseals Vault
- Enables Transit secrets engine
- Creates JWT signing key: `wardseal-signing-key-staging` (RSA-2048 for RS256 JWTs)
- Configures AppRole authentication
- Saves credentials to `/tmp/vault-staging-keys.json` and `/tmp/vault-approle-staging.json`

**IMPORTANT**: 
- Save the Vault root token and unseal keys securely
- Delete the temporary files after saving credentials
- You'll need 2 of 3 unseal keys to unseal Vault after restarts

### 3. Deploy Wardseal Application

Run the deployment script:

```bash
./scripts/deploy_wardseal_staging.sh
```

The script performs the following:
- Creates `wardseal-staging` namespace
- Deploys PostgreSQL with persistent storage (10Gi)
- Waits for PostgreSQL to be ready
- Applies database migrations
- Creates Kubernetes secrets (database, service auth, Vault AppRole)
- Builds Helm chart dependencies
- Deploys wardseal services using Helm

#### Configuration Options

The script supports several environment variables:

```bash
# Use external PostgreSQL instead of deploying
DEPLOY_POSTGRES=no EXTERNAL_DB_HOST=postgres.example.com ./scripts/deploy_wardseal_staging.sh

# Use specific image tag
IMAGE_TAG=v1.0.0 ./scripts/deploy_wardseal_staging.sh

# Use different image registry
IMAGE_REGISTRY=myregistry.io/myorg ./scripts/deploy_wardseal_staging.sh

# Custom database password
DB_PASSWORD=secure-password ./scripts/deploy_wardseal_staging.sh

# Custom Vault address (for external Vault)
VAULT_ADDR=https://vault.example.com:8200 ./scripts/deploy_wardseal_staging.sh

# Custom Vault Transit path / key name (must match Vault setup)
VAULT_KEY_PATH=transit VAULT_KEY_NAME=wardseal-signing-key-staging ./scripts/deploy_wardseal_staging.sh
```

## Accessing Services

### Via Ingress (Production-like)

If ingress is configured in `values-staging.yaml`, services will be accessible at:
- Landing Site: https://staging.wardseal.com
- Console UI: https://manage-staging.wardseal.com
- Auth Service: https://auth-staging.wardseal.com
- API Service: https://api-staging.wardseal.com

Make sure DNS records point to your ingress controller's load balancer.

### Via Port Forwarding (Testing)

```bash
# Auth Service (port 8080)
kubectl port-forward -n wardseal-staging svc/wardseal-authsvc 8080:8080 &

# Directory Service (port 8081)
kubectl port-forward -n wardseal-staging svc/wardseal-dirsvc 8081:8081 &

# Governance Service (port 8082)
kubectl port-forward -n wardseal-staging svc/wardseal-govsvc 8082:8082 &

# Vault UI (port 8200)
kubectl port-forward -n vault-staging svc/vault 8200:8200 &
```

### Health Checks

```bash
curl http://localhost:8080/health  # Auth Service
curl http://localhost:8081/health  # Directory Service
curl http://localhost:8082/health  # Governance Service
```

## Verification

### Check Pod Status

```bash
# Vault
kubectl get pods -n vault-staging

# Wardseal
kubectl get pods -n wardseal-staging
```

All pods should show `READY 1/1` and `STATUS Running`.

### Check Vault Status

```bash
kubectl exec -n vault-staging vault-0 -- vault status
```

Should show:
- Initialized: `true`
- Sealed: `false`

### Check Logs

```bash
# Auth Service logs
kubectl logs -n wardseal-staging deployment/wardseal-authsvc -f

# Directory Service logs
kubectl logs -n wardseal-staging deployment/wardseal-dirsvc -f

# Governance Service logs
kubectl logs -n wardseal-staging deployment/wardseal-govsvc -f

# Vault logs
kubectl logs -n vault-staging vault-0 -f
```

Look for successful Vault authentication messages in auth service logs.

## Differences from Development

| Aspect | Development | Staging |
|--------|-------------|---------|
| Vault Initialization | 1 key share | 3 key shares (threshold: 2) |
| TLS | Disabled | Required |
| Storage | In-memory/small volumes | Persistent volumes (5-10Gi) |
| Database | Simple setup | Production-like configuration |
| Resource Limits | Minimal | Realistic staging limits |
| HA Mode | Disabled | Supported (1 replica to start) |
| Auto-seal | Not configured | Recommended for production |
| Monitoring | Basic | Should be configured |

## Troubleshooting

### Vault Pod Not Ready

**Problem**: Vault pod shows `0/1` ready

**Solution**: Vault needs to be unsealed after every restart

```bash
# Load unseal keys
UNSEAL_KEY_1=$(jq -r '.unseal_keys_b64[0]' /tmp/vault-staging-keys.json)
UNSEAL_KEY_2=$(jq -r '.unseal_keys_b64[1]' /tmp/vault-staging-keys.json)

# Unseal (need 2 keys)
kubectl exec -n vault-staging vault-0 -- vault operator unseal $UNSEAL_KEY_1
kubectl exec -n vault-staging vault-0 -- vault operator unseal $UNSEAL_KEY_2
```

### TLS Certificate Errors

**Problem**: Vault fails to start with TLS errors

**Solution**: Verify certificate secret exists and is valid

```bash
# Check certificate
kubectl get secret vault-staging-tls -n vault-staging -o yaml

# If using cert-manager, check certificate status
kubectl get certificate -n vault-staging
kubectl describe certificate vault-staging -n vault-staging
```

### Database Connection Errors

**Problem**: Services cannot connect to database

**Solution**: Check PostgreSQL status and credentials

```bash
kubectl get pods -n wardseal-staging | grep postgres
kubectl logs -n wardseal-staging deployment/postgres-staging

# Test connection
kubectl exec -n wardseal-staging deployment/postgres-staging -- \
  psql -U wardseal_staging -d identity_platform_staging -c "SELECT 1;"
```

### Vault Authentication Errors

**Problem**: Auth service cannot authenticate with Vault

**Solution**: Verify Vault AppRole secret exists and is correct

```bash
# Check secret
kubectl get secret wardseal-vault-kms-staging -n wardseal-staging -o yaml

# Recreate if needed
ROLE_ID=$(jq -r '.role_id' /tmp/vault-approle-staging.json)
SECRET_ID=$(jq -r '.secret_id' /tmp/vault-approle-staging.json)

kubectl delete secret wardseal-vault-kms-staging -n wardseal-staging
kubectl create secret generic wardseal-vault-kms-staging \
  -n wardseal-staging \
  --from-literal=VAULT_ADDR="http://vault.vault-staging.svc.cluster.local:8200" \
  --from-literal=VAULT_ROLE_ID="$ROLE_ID" \
  --from-literal=VAULT_SECRET_ID="$SECRET_ID" \
  --from-literal=VAULT_KEY_NAME="wardseal-signing-key-staging" \
  --from-literal=VAULT_KEY_PATH="transit"

# Restart auth service
kubectl rollout restart deployment/wardseal-authsvc -n wardseal-staging
```

### Required Vault + Key Configuration (Auth Service)

For staging, `authsvc` uses Vault Transit signing (`KMS_PROVIDER=vault`) and must receive these values via `wardseal-vault-kms-staging`:

- `VAULT_ADDR`
- `VAULT_ROLE_ID`
- `VAULT_SECRET_ID`
- `VAULT_KEY_NAME` (example: `wardseal-signing-key-staging`)
- `VAULT_KEY_PATH` (usually `transit`)

The Helm values also map AppRole credentials from this exact secret via `authsvc.vaultAppRole.existingSecret: wardseal-vault-kms-staging`, so using a different secret name requires updating values as well.

## Cleanup

To remove the staging deployment:

```bash
# Delete Wardseal
helm uninstall wardseal -n wardseal-staging
kubectl delete namespace wardseal-staging

# Delete Vault
helm uninstall vault -n vault-staging
kubectl delete namespace vault-staging

# Clean up temp files
rm -f /tmp/vault-staging-keys.json /tmp/vault-approle-staging.json
```

## Next Steps: ArgoCD Deployment

After manual setup and verification, you can migrate to GitOps with ArgoCD:

1. **Store secrets securely**: Use External Secrets Operator or Sealed Secrets
2. **Create ArgoCD Application**: Apply the application manifests from `deploy/argocd/`
3. **Configure automated sync**: Enable auto-sync for continuous deployment
4. **Set up monitoring**: Configure Prometheus and Grafana for staging

See the ArgoCD application manifests in:
- `deploy/argocd/application-staging.yaml`
- `deploy/argocd/external-secrets-staging.yaml`

## Security Best Practices

1. **Vault Keys**: Store unseal keys and root token in a secure vault (e.g., 1Password, AWS Secrets Manager)
2. **Auto-Unseal**: Consider configuring Vault auto-unseal for production-grade deployments
3. **Regular Backups**: Set up automated backups for both Vault and PostgreSQL
4. **Monitoring**: Configure alerts for pod failures, Vault seal status, and database issues
5. **Access Control**: Use RBAC to limit who can access staging resources
6. **Audit Logs**: Enable audit logging in Vault for security compliance
7. **Rotate Credentials**: Regularly rotate database passwords and AppRole secrets

## Support

For issues or questions:
- Check logs: `kubectl logs -n <namespace> <pod-name>`
- Review Vault documentation: https://developer.hashicorp.com/vault
- Review Kubernetes documentation: https://kubernetes.io/docs/
