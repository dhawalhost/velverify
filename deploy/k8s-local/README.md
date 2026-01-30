# Local Kubernetes Deployment Guide

This guide explains how to deploy wardseal with HashiCorp Vault integration on your local Kubernetes cluster for development.

## Prerequisites

- **Kubernetes Cluster**: Local cluster running (minikube, kind, Docker Desktop, etc.)
- **kubectl**: Configured to access your cluster
- **Helm 3**: Package manager for Kubernetes
- **jq**: JSON processor (for parsing Vault credentials)

### Verify Prerequisites

```bash
# Check Kubernetes cluster
kubectl cluster-info

# Check Helm
helm version

# Check jq
jq --version
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

## Quick Start

The easiest way to get started is to run the deployment scripts in order:

```bash
# 1. Deploy and configure Vault
./scripts/setup_vault_dev.sh

# 2. Deploy Wardseal application
./scripts/deploy_wardseal_dev.sh
```

That's it! The scripts will handle everything automatically.

## Step-by-Step Deployment

If you prefer to understand each step or need to troubleshoot, follow this detailed guide.

### 1. Deploy HashiCorp Vault

The Vault deployment script performs the following:
- Creates `vault-dev` namespace
- Deploys Vault using official Helm chart
- Initializes Vault (1 key share for dev)
- Unseals Vault
- Enables Transit secrets engine
- Creates JWT signing key
- Configures AppRole authentication
- Saves credentials to `/tmp/vault-dev-keys.json` and `/tmp/vault-approle-dev.json`

Run the script:

```bash
./scripts/setup_vault_dev.sh
```

**Important**: The script will output the Vault root token and unseal key. Save these securely!

#### Manual Vault Setup (Alternative)

If you need to set up Vault manually:

```bash
# Create namespace
kubectl create namespace vault-dev

# Add Helm repo
helm repo add hashicorp https://helm.releases.hashicorp.com
helm repo update

# Deploy Vault
helm install vault hashicorp/vault \
  --namespace vault-dev \
  --version 0.28.1 \
  --values deploy/vault/charts/vault/vault-values-development.yaml

# Initialize (after pod is running)
kubectl exec -n vault-dev vault-0 -- vault operator init \
  -key-shares=1 \
  -key-threshold=1 \
  -format=json > /tmp/vault-dev-keys.json

# Unseal
UNSEAL_KEY=$(jq -r '.unseal_keys_b64[0]' /tmp/vault-dev-keys.json)
kubectl exec -n vault-dev vault-0 -- vault operator unseal $UNSEAL_KEY

# Login and configure
ROOT_TOKEN=$(jq -r '.root_token' /tmp/vault-dev-keys.json)
kubectl exec -n vault-dev vault-0 -- vault login $ROOT_TOKEN

# Enable Transit
kubectl exec -n vault-dev vault-0 -- vault secrets enable transit
kubectl exec -n vault-dev vault-0 -- vault write -f transit/keys/jwt-signing type=ecdsa-p256

# Create policy and AppRole (see setup_vault_dev.sh for complete commands)
```

### 2. Deploy Wardseal Application

The Wardseal deployment script performs the following:
- Creates `wardseal-dev` namespace
- Deploys PostgreSQL with persistent storage
- Waits for PostgreSQL to be ready
- Applies database migrations
- Creates Kubernetes secrets (database, service auth, Vault AppRole)
- Builds Helm chart dependencies
- Deploys wardseal services using Helm

Run the script:

```bash
./scripts/deploy_wardseal_dev.sh
```

#### Manual Wardseal Deployment (Alternative)

If you prefer to deploy manually:

```bash
# Create namespace
kubectl create namespace wardseal-dev

# Deploy PostgreSQL
kubectl apply -f - <<EOF
# (See deploy_wardseal_dev.sh for complete PostgreSQL manifest)
EOF

# Apply migrations
for f in migrations/*.up.sql; do
  kubectl exec -n wardseal-dev deployment/postgres -- \
    psql -U wardseal -d identity_platform_dev -c "$(cat $f)"
done

# Create secrets
kubectl create secret generic wardseal-db-credentials-dev \
  -n wardseal-dev \
  --from-literal=username=wardseal \
  --from-literal=password=dev-password \
  --from-literal=host=postgres \
  --from-literal=port=5432 \
  --from-literal=database=identity_platform_dev

ROLE_ID=$(jq -r '.role_id' /tmp/vault-approle-dev.json)
SECRET_ID=$(jq -r '.secret_id' /tmp/vault-approle-dev.json)

kubectl create secret generic vault-approle \
  -n wardseal-dev \
  --from-literal=role-id="$ROLE_ID" \
  --from-literal=secret-id="$SECRET_ID"

# Deploy with Helm
cd deploy/charts/wardseal
helm dependency update
cd ../../..

helm install wardseal deploy/charts/wardseal \
  --namespace wardseal-dev \
  --values deploy/charts/wardseal/values.yaml \
  --values deploy/charts/wardseal/values-development.yaml \
  --set kms.provider=vault \
  --set kms.vaultAddr=http://vault.vault-dev.svc.cluster.local:8200 \
  --set authsvc.env.KMS_PROVIDER=vault \
  --set authsvc.env.VAULT_ADDR=http://vault.vault-dev.svc.cluster.local:8200 \
  --set authsvc.env.VAULT_TRANSIT_KEY=jwt-signing
```

## Accessing Services

### Port Forwarding

Forward ports to access services locally:

```bash
# Auth Service (port 8080)
kubectl port-forward -n wardseal-dev svc/wardseal-authsvc 8080:8080 &

# Directory Service (port 8081)
kubectl port-forward -n wardseal-dev svc/wardseal-dirsvc 8081:8081 &

# Governance Service (port 8082)
kubectl port-forward -n wardseal-dev svc/wardseal-govsvc 8082:8082 &

# Vault UI (port 8200)
kubectl port-forward -n vault-dev svc/vault 8200:8200 &
```

### Health Checks

Test that services are running:

```bash
curl http://localhost:8080/health  # Auth Service
curl http://localhost:8081/health  # Directory Service
curl http://localhost:8082/health  # Governance Service
```

### Vault UI

Access Vault UI at http://localhost:8200 using the root token from `/tmp/vault-dev-keys.json`.

## Verification

### Check Pod Status

```bash
# Vault
kubectl get pods -n vault-dev

# Wardseal
kubectl get pods -n wardseal-dev
```

All pods should show `READY 1/1` and `STATUS Running`.

### Check Vault Status

```bash
kubectl exec -n vault-dev vault-0 -- vault status
```

Should show:
- Initialized: `true`
- Sealed: `false`

### Check Logs

```bash
# Auth Service logs
kubectl logs -n wardseal-dev deployment/wardseal-authsvc -f

# Directory Service logs
kubectl logs -n wardseal-dev deployment/wardseal-dirsvc -f

# Governance Service logs
kubectl logs -n wardseal-dev deployment/wardseal-govsvc -f

# Vault logs
kubectl logs -n vault-dev vault-0 -f
```

Look for successful Vault authentication messages in auth service logs.

## Troubleshooting

### Vault Pod Not Ready

**Problem**: Vault pod shows `0/1` ready

**Solution**: Vault needs to be unsealed after every restart

```bash
UNSEAL_KEY=$(jq -r '.unseal_keys_b64[0]' /tmp/vault-dev-keys.json)
kubectl exec -n vault-dev vault-0 -- vault operator unseal $UNSEAL_KEY
```

### Database Connection Errors

**Problem**: Services cannot connect to database

**Solution**: Check PostgreSQL status and credentials

```bash
kubectl get pods -n wardseal-dev | grep postgres
kubectl logs -n wardseal-dev deployment/postgres

# Test connection
kubectl exec -n wardseal-dev deployment/postgres -- \
  psql -U wardseal -d identity_platform_dev -c "SELECT 1;"
```

### Vault Authentication Errors

**Problem**: Auth service cannot authenticate with Vault

**Solution**: Verify Vault AppRole secret exists and is correct

```bash
# Check secret
kubectl get secret vault-approle -n wardseal-dev -o yaml

# Recreate if needed
ROLE_ID=$(jq -r '.role_id' /tmp/vault-approle-dev.json)
SECRET_ID=$(jq -r '.secret_id' /tmp/vault-approle-dev.json)

kubectl delete secret vault-approle -n wardseal-dev
kubectl create secret generic vault-approle \
  -n wardseal-dev \
  --from-literal=role-id="$ROLE_ID" \
  --from-literal=secret-id="$SECRET_ID"

# Restart auth service
kubectl rollout restart deployment/wardseal-authsvc -n wardseal-dev
```

### Helm Dependency Errors

**Problem**: Helm install fails with dependency errors

**Solution**: Update Helm dependencies

```bash
cd deploy/charts/wardseal
helm dependency update
cd ../../..

# Try install again
```

### Image Pull Errors

**Problem**: Pods show `ImagePullBackOff` or `ErrImagePull`

**Cause**: Images don't exist in registry (development values use `ghcr.io/dhawalhost/`)

**Solution**: Either build and push images, or use local development:

```bash
# Option 1: Build and push images
make build-images
make push-images

# Option 2: Use local development with Docker Compose instead
docker-compose up -d
```

## Cleanup

To remove the deployment:

```bash
# Delete Wardseal
helm uninstall wardseal -n wardseal-dev
kubectl delete namespace wardseal-dev

# Delete Vault
helm uninstall vault -n vault-dev
kubectl delete namespace vault-dev

# Clean up temp files
rm -f /tmp/vault-dev-keys.json /tmp/vault-approle-dev.json
```

## Next Steps

After successful deployment:

1. **Create test users**: Insert test data into the database
2. **Test authentication**: Use the API to create sessions and generate JWTs
3. **Verify Vault integration**: Check that JWTs are signed using Vault Transit engine
4. **Explore Admin UI**: Deploy the admin UI for a graphical interface

## Additional Resources

- [Vault Deployment Guide](../docs/VAULT_DEPLOYMENT.md) - Comprehensive Vault setup
- [Vault Integration Guide](../docs/vault-integration.md) - Technical details on Vault integration
- [README.md](../README.md) - Main project documentation
- [QUICKSTART.md](../QUICKSTART.md) - Quick start guide for local development

## Support

For issues or questions:
- Check logs: `kubectl logs -n <namespace> <pod-name>`
- Review Vault documentation: https://developer.hashicorp.com/vault
- Review Kubernetes documentation: https://kubernetes.io/docs/
