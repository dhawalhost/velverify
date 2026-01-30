# HashiCorp Vault Integration

WardSeal supports external key management using HashiCorp Vault's Transit secrets engine. This provides:

- **Server-side signing**: Private keys never leave Vault
- **Key rotation**: Rotate keys without application restarts
- **Audit logging**: All cryptographic operations are logged
- **Centralized management**: Single source of truth for keys

---

## Quick Start

### 1. Start Vault (Development Mode)

```bash
docker run -d --name vault-dev \
  --cap-add=IPC_LOCK \
  -p 8200:8200 \
  -e VAULT_DEV_ROOT_TOKEN_ID=root \
  hashicorp/vault:latest

export VAULT_ADDR=http://localhost:8200
export VAULT_TOKEN=root
```

### 2. Enable Transit Engine

```bash
vault secrets enable transit
```

### 3. Create Signing Key

```bash
vault write -f transit/keys/wardseal-signing-key \
  type=rsa-2048 \
  exportable=false
```

### 4. Configure WardSeal

```bash
export KMS_PROVIDER=vault
export VAULT_ADDR=http://localhost:8200
export VAULT_TOKEN=root
export VAULT_KEY_NAME=wardseal-signing-key
```

### 5. Start Auth Service

```bash
go run cmd/authsvc/main.go
```

---

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `KMS_PROVIDER` | `local` | `local` for file-based, `vault` for Vault Transit |
| `VAULT_ADDR` | - | Vault server address (required for vault) |
| `VAULT_TOKEN` | - | Vault authentication token |
| `VAULT_KEY_NAME` | `wardseal-signing-key` | Transit key name |
| `VAULT_KEY_PATH` | `transit` | Transit engine mount path |
| `VAULT_NAMESPACE` | - | Vault namespace (Enterprise only) |         
| `VAULT_ROLE_ID` | - | AppRole role ID (alternative to token) |
| `VAULT_SECRET_ID` | - | AppRole secret ID |

### Local File-Based Keys (Default)

```bash
export KMS_PROVIDER=local
export JWT_PRIVATE_KEY_PATH=/path/to/private.pem
export JWT_PUBLIC_KEY_PATH=/path/to/public.pem
```

If no paths are provided, ephemeral keys are generated (development only).

---

## Production Setup

### 1. Vault Server Installation

Follow [HashiCorp's production deployment guide](https://developer.hashicorp.com/vault/tutorials/getting-started/getting-started-deploy).

### 2. Enable Transit Engine

```bash
vault secrets enable -path=transit transit
```

### 3. Create Key with Proper Settings

```bash
vault write transit/keys/wardseal-signing-key \
  type=rsa-2048 \
  exportable=false \
  allow_plaintext_backup=false \
  min_decryption_version=1 \
  min_encryption_version=0
```

### 4. Create Policy

```hcl
# wardseal-policy.hcl
path "transit/sign/wardseal-signing-key" {
  capabilities = ["update"]
}

path "transit/verify/wardseal-signing-key" {
  capabilities = ["update"]
}

path "transit/keys/wardseal-signing-key" {
  capabilities = ["read"]
}
```

Apply policy:

```bash
vault policy write wardseal wardseal-policy.hcl
```

### 5. AppRole Authentication (Recommended)

```bash
# Enable AppRole
vault auth enable approle

# Create role
vault write auth/approle/role/wardseal \
  token_policies="wardseal" \
  token_ttl=1h \
  token_max_ttl=4h \
  secret_id_ttl=24h

# Get role ID
vault read auth/approle/role/wardseal/role-id

# Generate secret ID
vault write -f auth/approle/role/wardseal/secret-id
```

Configure WardSeal:

```bash
export KMS_PROVIDER=vault
export VAULT_ADDR=https://vault.example.com:8200
export VAULT_ROLE_ID=<role-id>
export VAULT_SECRET_ID=<secret-id>
export VAULT_KEY_NAME=wardseal-signing-key
```

---

## Kubernetes Integration

### Using Vault Agent Injector

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: wardseal-authsvc
spec:
  template:
    metadata:
      annotations:
        vault.hashicorp.com/agent-inject: "true"
        vault.hashicorp.com/role: "wardseal"
        vault.hashicorp.com/agent-inject-secret-config: "secret/data/wardseal/config"
    spec:
      serviceAccountName: wardseal
      containers:
      - name: authsvc
        env:
        - name: KMS_PROVIDER
          value: vault
        - name: VAULT_ADDR
          value: http://vault:8200
```

### Using External Secrets Operator

```yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: wardseal-vault-auth
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: vault-backend
    kind: ClusterSecretStore
  target:
    name: wardseal-vault-auth
  data:
  - secretKey: VAULT_ROLE_ID
    remoteRef:
      key: secret/data/wardseal
      property: role_id
  - secretKey: VAULT_SECRET_ID
    remoteRef:
      key: secret/data/wardseal
      property: secret_id
```

---

## Key Rotation

### Rotate Key in Vault

```bash
vault write -f transit/keys/wardseal-signing-key/rotate
```

WardSeal automatically uses the latest key version for signing while still validating tokens signed with older versions.

### Force Application Restart

To immediately use the new key:

```bash
kubectl rollout restart deployment/wardseal-authsvc
```

---

## Troubleshooting

### Check Vault Connectivity

```bash
curl -H "X-Vault-Token: $VAULT_TOKEN" $VAULT_ADDR/v1/sys/health
```

### Check Key Exists

```bash
vault read transit/keys/wardseal-signing-key
```

### Test Signing Operation

```bash
echo -n "test" | base64 | vault write transit/sign/wardseal-signing-key \
  input=- \
  hash_algorithm=sha2-256
```

### Common Errors

| Error | Cause | Solution |
|-------|-------|----------|
| `permission denied` | Policy doesn't allow operation | Update Vault policy |
| `key not found` | Key doesn't exist | Create key with `vault write -f transit/keys/...` |
| `connection refused` | Wrong VAULT_ADDR | Verify Vault address and port |
| `token expired` | Token TTL exceeded | Renew token or use AppRole |

---

## Security Best Practices

1. **Never use root token in production** - Use AppRole or Kubernetes auth
2. **Enable audit logging** - `vault audit enable file file_path=/var/log/vault/audit.log`
3. **Use TLS** - Always use HTTPS for Vault connections
4. **Limit policy scope** - Only grant required permissions
5. **Rotate secrets regularly** - Use short-lived tokens and rotate secret IDs
6. **Monitor key usage** - Review audit logs for anomalies
