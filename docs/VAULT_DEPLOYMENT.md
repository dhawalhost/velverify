# HashiCorp Vault Deployment Guide

This guide covers deploying HashiCorp Vault to Kubernetes using the official Helm chart, managed via ArgoCD, and integrating it with WardSeal for secrets management.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Deploying Vault via ArgoCD](#deploying-vault-via-argocd)
3. [Initializing and Unsealing Vault](#initializing-and-unsealing-vault)
4. [Configuring Vault for WardSeal](#configuring-vault-for-wardseal)
5. [Integrating WardSeal with Vault](#integrating-wardseal-with-vault)
6. [Backup and Disaster Recovery](#backup-and-disaster-recovery)
7. [Troubleshooting](#troubleshooting)

## Prerequisites

Before deploying Vault, ensure you have:

- **Kubernetes Cluster**: Running cluster with kubectl access
- **ArgoCD**: Installed and configured in the `argocd` namespace
- **Storage Provisioner**: Dynamic PV provisioning (for persistent storage)
- **Ingress Controller**: nginx-ingress or similar (for production)
- **Cert-Manager** (Production only): For TLS certificate management
- **kubectl**: Configured with appropriate permissions

### Verify Prerequisites

```bash
# Check ArgoCD is running
kubectl get pods -n argocd

# Check storage class
kubectl get storageclass

# Check ingress controller (production)
kubectl get pods -n ingress-nginx
```

## Deploying Vault via ArgoCD

### Development Environment

1. **Apply the Vault ArgoCD Application**:

   ```bash
   kubectl apply -f deploy/vault/argocd/vault-application-development.yaml
   ```

2. **Monitor the deployment**:

   ```bash
   # Watch ArgoCD sync status
   kubectl get application vault-development -n argocd -w

   # Watch Vault pods
   kubectl get pods -n vault-dev -w
   ```

3. **Verify deployment**:

   ```bash
   # Check application status
   argocd app get vault-development

   # Check pod status
   kubectl get pods -n vault-dev
   # Expected: vault-0 pod in Running state (but not ready)
   ```

### Production Environment

> [!IMPORTANT]
> Production deployment requires TLS certificates. Ensure cert-manager is configured with a ClusterIssuer before deploying.

1. **Create TLS certificate (if using cert-manager)**:

   ```bash
   # cert-manager will automatically create certificate from ingress annotation
   # Or create manually:
   cat <<EOF | kubectl apply -f -
   apiVersion: cert-manager.io/v1
   kind: Certificate
   metadata:
     name: vault-tls
     namespace: vault-production
   spec:
     secretName: vault-tls
     issuerRef:
       name: letsencrypt-prod
       kind: ClusterIssuer
     dnsNames:
       - vault.dhawalhost.com
   EOF
   ```

2. **Apply the Vault ArgoCD Application**:

   ```bash
   kubectl apply -f deploy/vault/argocd/vault-application-production.yaml
   ```

4. **Manually sync** (production uses manual sync):

   ```bash
   argocd app sync vault-production
   ```

5. **Monitor the deployment**:

   ```bash
   kubectl get pods -n vault-production -w
   # Expected: 3 vault pods (vault-0, vault-1, vault-2) in Running state
   ```

## Initializing and Unsealing Vault

After deployment, Vault needs to be initialized and unsealed. This is a **one-time operation** for initialization, but unsealing is required after every pod restart.

### Development Environment

1. **Port-forward to Vault** (if using ClusterIP service):

   ```bash
   kubectl port-forward -n vault-dev vault-0 8200:8200
   ```

2. **Set Vault environment variables**:

   ```bash
   export VAULT_ADDR='http://localhost:8200'
   export VAULT_SKIP_VERIFY=true  # Dev only, no TLS
   ```

3. **Initialize Vault**:

   ```bash
   vault operator init -key-shares=1 -key-threshold=1
   ```

   **IMPORTANT**: Save the output! You'll receive:
   - 1 unseal key
   - Initial root token

   Example output:
   ```
   Unseal Key 1: abcd1234efgh5678ijkl9012mnop3456qrst7890uvwx
   
   Initial Root Token: hvs.1234567890abcdefghijklmnopqrstuvwx
   ```

4. **Unseal Vault**:

   ```bash
   vault operator unseal
   # Enter the unseal key when prompted
   ```

5. **Verify Vault is ready**:

   ```bash
   vault status
   # Should show: Sealed: false, Initialized: true
   ```

6. **Login with root token**:

   ```bash
   vault login
   # Enter the root token when prompted
   ```

### Production Environment

Production uses 3 replicas for HA. Each pod must be initialized and unsealed.

1. **Initialize only the first pod** (vault-0):

   ```bash
   kubectl exec -n vault-production vault-0 -- vault operator init \
     -key-shares=5 \
     -key-threshold=3 \
     -format=json > vault-init-keys.json
   ```

   **CRITICAL**: Store `vault-init-keys.json` securely! This contains:
   - 5 unseal keys (need 3 to unseal)
   - Root token

   Recommended: Store in a secure vault/secrets manager, NOT in git!

2. **Unseal vault-0**:

   ```bash
   # Extract unseal keys from JSON
   UNSEAL_KEY_1=$(cat vault-init-keys.json | jq -r '.unseal_keys_b64[0]')
   UNSEAL_KEY_2=$(cat vault-init-keys.json | jq -r '.unseal_keys_b64[1]')
   UNSEAL_KEY_3=$(cat vault-init-keys.json | jq -r '.unseal_keys_b64[2]')

   # Unseal with 3 keys
   kubectl exec -n vault-production vault-0 -- vault operator unseal $UNSEAL_KEY_1
   kubectl exec -n vault-production vault-0 -- vault operator unseal $UNSEAL_KEY_2
   kubectl exec -n vault-production vault-0 -- vault operator unseal $UNSEAL_KEY_3
   ```

3. **Wait for other pods to join the Raft cluster**:

   ```bash
   # Check Raft cluster status
   kubectl exec -n vault-production vault-0 -- vault operator raft list-peers
   ```

4. **Unseal vault-1 and vault-2**:

   ```bash
   # Unseal vault-1
   kubectl exec -n vault-production vault-1 -- vault operator unseal $UNSEAL_KEY_1
   kubectl exec -n vault-production vault-1 -- vault operator unseal $UNSEAL_KEY_2
   kubectl exec -n vault-production vault-1 -- vault operator unseal $UNSEAL_KEY_3

   # Unseal vault-2
   kubectl exec -n vault-production vault-2 -- vault operator unseal $UNSEAL_KEY_1
   kubectl exec -n vault-production vault-2 -- vault operator unseal $UNSEAL_KEY_2
   kubectl exec -n vault-production vault-2 -- vault operator unseal $UNSEAL_KEY_3
   ```

5. **Verify all pods are unsealed and ready**:

   ```bash
   kubectl get pods -n vault-production
   # All pods should show READY 1/1

   # Check cluster status
   kubectl exec -n vault-production vault-0 -- vault status
   ```

## Configuring Vault for WardSeal

Once Vault is initialized and unsealed, configure it for WardSeal integration.

### 1. Enable Transit Secrets Engine

The Transit engine provides encryption-as-a-service for signing JWTs.

```bash
# Login to Vault
export VAULT_ADDR='http://localhost:8200'  # Development (via port-forward)
# Or for production: export VAULT_ADDR='https://vault.dhawalhost.com'
export VAULT_TOKEN='<root-token>'

# Enable transit secrets engine
vault secrets enable transit

# Create a signing key for JWT
vault write -f transit/keys/jwt-signing \
  type=ecdsa-p256 \
  exportable=false \
  allow_plaintext_backup=false

# Configure key usage
vault write transit/keys/jwt-signing/config \
  auto_rotate_period=2160h  # Rotate every 90 days
```

### 2. Create Vault Policy for WardSeal

Create a policy that allows WardSeal to sign JWTs:

```bash
vault policy write wardseal-auth - <<EOF
# Allow signing with the JWT key
path "transit/sign/jwt-signing" {
  capabilities = ["create", "update"]
}

# Allow verifying signatures
path "transit/verify/jwt-signing" {
  capabilities = ["create", "update"]
}

# Allow reading key metadata (for public key)
path "transit/keys/jwt-signing" {
  capabilities = ["read"]
}

# Optional: Allow reading key rotation info
path "transit/keys/jwt-signing/rotate" {
  capabilities = ["update"]
}
EOF
```

### 3. Create AppRole for WardSeal

AppRole provides secure authentication for WardSeal services:

```bash
# Enable AppRole auth method
vault auth enable approle

# Create AppRole for auth service
vault write auth/approle/role/wardseal-auth \
  token_policies="wardseal-auth" \
  token_ttl=1h \
  token_max_ttl=24h \
  bind_secret_id=true \
  secret_id_ttl=0 \
  secret_id_num_uses=0

# Get RoleID (store this in wardseal config)
vault read auth/approle/role/wardseal-auth/role-id

# Generate SecretID (store this as a Kubernetes secret)
vault write -f auth/approle/role/wardseal-auth/secret-id
```

### 4. Store Vault Credentials in Kubernetes

```bash
# Development
kubectl create secret generic vault-approle -n wardseal-dev \
  --from-literal=role-id='<role-id>' \
  --from-literal=secret-id='<secret-id>'

# Production
kubectl create secret generic vault-approle -n wardseal-production \
  --from-literal=role-id='<role-id>' \
  --from-literal=secret-id='<secret-id>'
```

## Integrating WardSeal with Vault

Update WardSeal Helm values to use Vault for JWT signing.

### Development Environment

Edit `deploy/charts/wardseal/values-development.yaml`:

> [!NOTE]
> Vault is now deployed in a separate directory (`deploy/vault/`) to keep infrastructure components separate from application deployments.

```yaml
# KMS Configuration - Use Vault
kms:
  provider: vault
  vaultAddr: http://vault.vault-dev.svc.cluster.local:8200
  vaultNamespace: ""  # Leave empty for OSS Vault
  approleRoleID: ""  # Will be populated from secret
  approleSecretID: ""  # Will be populated from secret
  transitMountPath: transit
  transitKeyName: jwt-signing

# Auth Service - Update environment
authsvc:
  env:
    KMS_PROVIDER: vault
    VAULT_ADDR: http://vault.vault-dev.svc.cluster.local:8200
    VAULT_TRANSIT_KEY: jwt-signing
  
  # Mount the vault-approle secret
  extraSecrets:
    - name: vault-approle
      mountPath: /vault/secrets
```

### Production Environment

Edit `deploy/charts/wardseal/values-production.yaml`:

```yaml
# KMS Configuration - Use Vault with TLS
kms:
  provider: vault
  vaultAddr: https://vault.vault-production.svc.cluster.local:8200
  vaultNamespace: ""
  vaultSkipVerify: false  # Enable TLS verification
  vaultCACert: /vault/tls/ca.crt
  transitMountPath: transit
  transitKeyName: jwt-signing

authsvc:
  env:
    KMS_PROVIDER: vault
    VAULT_ADDR: https://vault.vault-production.svc.cluster.local:8200
    VAULT_TRANSIT_KEY: jwt-signing
    VAULT_CACERT: /vault/tls/ca.crt
  
  extraSecrets:
    - name: vault-approle
      mountPath: /vault/secrets
  
  extraVolumes:
    - name: vault-tls
      secret:
        secretName: vault-tls  # CA cert for TLS verification
  
  extraVolumeMounts:
    - name: vault-tls
      mountPath: /vault/tls
      readOnly: true
```

### Redeploy WardSeal

```bash
# ArgoCD will automatically sync if automated sync is enabled
# Or manually sync:
argocd app sync wardseal-development
argocd app sync wardseal-production
```

## Backup and Disaster Recovery

### Automated Snapshots (Raft Storage)

For production, create a CronJob to take periodic Raft snapshots:

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: vault-snapshot
  namespace: vault-production
spec:
  schedule: "0 2 * * *"  # Daily at 2 AM
  jobTemplate:
    spec:
      template:
        spec:
          serviceAccountName: vault
          containers:
          - name: snapshot
            image: hashicorp/vault:1.15
            env:
            - name: VAULT_ADDR
              value: "https://vault.vault-production.svc.cluster.local:8200"
            - name: VAULT_TOKEN
              valueFrom:
                secretKeyRef:
                  name: vault-snapshot-token
                  key: token
            command:
            - /bin/sh
            - -c
            - |
              vault operator raft snapshot save /snapshots/vault-snapshot-$(date +%Y%m%d-%H%M%S).snap
              # Upload to S3/GCS (add aws-cli or gsutil)
              # aws s3 cp /snapshots/vault-snapshot-*.snap s3://vault-backups/
            volumeMounts:
            - name: snapshots
              mountPath: /snapshots
          volumes:
          - name: snapshots
            persistentVolumeClaim:
              claimName: vault-snapshots
          restartPolicy: OnFailure
```

### Manual Backup

```bash
# Take a snapshot
kubectl exec -n vault-production vault-0 -- vault operator raft snapshot save /tmp/snapshot.snap

# Copy snapshot locally
kubectl cp vault-production/vault-0:/tmp/snapshot.snap ./vault-snapshot-$(date +%Y%m%d).snap

# Store securely (S3, GCS, etc.)
```

### Disaster Recovery

To restore from a snapshot:

```bash
# Upload snapshot to pod
kubectl cp ./vault-snapshot.snap vault-production/vault-0:/tmp/snapshot.snap

# Restore snapshot
kubectl exec -n vault-production vault-0 -- vault operator raft snapshot restore /tmp/snapshot.snap

# Unseal all Vault pods
# (Use the original unseal keys)
```

## Troubleshooting

### Vault Pod Not Ready

**Symptom**: Pod is running but not ready (0/1)

**Cause**: Vault is sealed

**Solution**: Unseal Vault using the unseal keys

```bash
kubectl exec -n vault-dev vault-0 -- vault operator unseal
```

### Raft Cluster Not Forming

**Symptom**: vault-1 and vault-2 not joining cluster

**Cause**: vault-0 not initialized or unsealed

**Solution**: Initialize and unseal vault-0 first, then unseal other pods

### ArgoCD Sync Failing

**Symptom**: Application shows OutOfSync or sync errors

**Cause**: Missing prerequisites (namespace, TLS cert, etc.)

**Solution**: Check ArgoCD application events

```bash
kubectl describe application vault-development -n argocd
```

### WardSeal Cannot Connect to Vault

**Symptom**: Auth service logs show "connection refused" or "TLS verification failed"

**Causes & Solutions**:

1. **Network policy blocking**: Check network policies allow traffic from wardseal namespace to vault namespace

2. **Incorrect Vault address**: Verify `VAULT_ADDR` is correct in wardseal config

3. **TLS issues**: Ensure CA certificate is mounted and `VAULT_CACERT` is set correctly

4. **AppRole credentials invalid**: Regenerate AppRole SecretID and update Kubernetes secret

### Checking Vault Logs

```bash
# Development
kubectl logs -n vault-dev vault-0 -f

# Production
kubectl logs -n vault-production vault-0 -f
kubectl logs -n vault-production vault-1 -f
kubectl logs -n vault-production vault-2 -f
```

### Vault Status Check

```bash
# Port-forward to Vault
kubectl port-forward -n vault-production vault-0 8200:8200

# Check status
export VAULT_ADDR='https://localhost:8200'
export VAULT_SKIP_VERIFY=true  # Only if using self-signed cert
vault status

# Or access via ingress
export VAULT_ADDR='https://vault.dhawalhost.com'
vault status
```

## Additional Resources

- [Official Vault Documentation](https://developer.hashicorp.com/vault/docs)
- [Vault on Kubernetes](https://developer.hashicorp.com/vault/docs/platform/k8s)
- [Vault Helm Chart](https://github.com/hashicorp/vault-helm)
- [Transit Secrets Engine](https://developer.hashicorp.com/vault/docs/secrets/transit)
- [AppRole Auth Method](https://developer.hashicorp.com/vault/docs/auth/approle)
