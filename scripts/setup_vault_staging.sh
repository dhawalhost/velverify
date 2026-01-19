#!/usr/bin/env bash
# Setup HashiCorp Vault for Wardseal Staging Environment
# This script deploys Vault to Kubernetes staging and configures it for wardseal
set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
NAMESPACE="vault-staging"
VAULT_RELEASE="vault"
VAULT_CHART_VERSION="0.28.1"
VAULT_VALUES_FILE="${VAULT_VALUES_FILE:-$(dirname "$0")/../../argocd-infra/vault/charts/vault/vault-values-staging.yaml}"
TLS_SECRET_NAME="vault-staging-tls"

# Function to print colored output
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    if ! command -v kubectl &> /dev/null; then
        log_error "kubectl not found. Please install kubectl."
        exit 1
    fi
    
    if ! command -v helm &> /dev/null; then
        log_error "helm not found. Please install Helm."
        exit 1
    fi
    
    if ! kubectl cluster-info &> /dev/null; then
        log_error "Cannot connect to Kubernetes cluster. Please ensure your cluster is running."
        exit 1
    fi
    
    if ! command -v jq &> /dev/null; then
        log_error "jq not found. Please install jq for JSON processing."
        exit 1
    fi
    
    if [ ! -f "$VAULT_VALUES_FILE" ]; then
        log_error "Vault values file not found at: $VAULT_VALUES_FILE"
        log_error "Please ensure the argocd-infra repository is cloned at the expected location."
        log_error "Or set VAULT_VALUES_FILE environment variable to the correct path."
        exit 1
    fi
    
    log_info "Prerequisites check passed ✓"
}

# Create namespace
create_namespace() {
    log_info "Creating namespace: $NAMESPACE"
    
    if kubectl get namespace "$NAMESPACE" &> /dev/null; then
        log_warn "Namespace $NAMESPACE already exists, skipping..."
    else
        kubectl create namespace "$NAMESPACE"
        log_info "Namespace $NAMESPACE created ✓"
    fi
}

# Check TLS certificate
check_tls_certificate() {
    log_info "Checking TLS certificate..."
    
    if kubectl get secret "$TLS_SECRET_NAME" -n "$NAMESPACE" &> /dev/null; then
        log_info "TLS certificate secret exists ✓"
    else
        log_warn "TLS certificate secret '$TLS_SECRET_NAME' not found in namespace '$NAMESPACE'"
        echo ""
        echo "=========================================="
        echo "TLS Certificate Required"
        echo "=========================================="
        echo ""
        echo "Vault in staging requires TLS. You have two options:"
        echo ""
        echo "Option 1: Use cert-manager (recommended)"
        echo "  Create a Certificate resource and let cert-manager manage it:"
        echo ""
        echo "  kubectl apply -f - <<EOF"
        echo "  apiVersion: cert-manager.io/v1"
        echo "  kind: Certificate"
        echo "  metadata:"
        echo "    name: vault-staging"
        echo "    namespace: $NAMESPACE"
        echo "  spec:"
        echo "    secretName: $TLS_SECRET_NAME"
        echo "    issuerRef:"
        echo "      name: letsencrypt-prod"
        echo "      kind: ClusterIssuer"
        echo "    dnsNames:"
        echo "      - vault-staging.dhawalhost.com"
        echo "  EOF"
        echo ""
        echo "Option 2: Create certificate manually"
        echo "  Generate a self-signed certificate for testing:"
        echo ""
        echo "  openssl req -x509 -nodes -days 365 -newkey rsa:2048 \\"
        echo "    -keyout tls.key -out tls.crt \\"
        echo "    -subj \"/CN=vault-staging.dhawalhost.com\""
        echo ""
        echo "  kubectl create secret tls $TLS_SECRET_NAME \\"
        echo "    --cert=tls.crt --key=tls.key -n $NAMESPACE"
        echo ""
        echo "=========================================="
        echo ""
        read -p "Do you want to continue without TLS certificate? (yes/no): " continue_without_tls
        if [[ "$continue_without_tls" != "yes" ]]; then
            log_error "Setup cancelled. Please create TLS certificate and try again."
            exit 1
        fi
        log_warn "Continuing without TLS certificate (Vault may not start properly)"
    fi
}

# Add HashiCorp Helm repository
add_helm_repo() {
    log_info "Adding HashiCorp Helm repository..."
    
    if helm repo list | grep -q "hashicorp"; then
        log_warn "HashiCorp repo already added, updating..."
        helm repo update hashicorp
    else
        helm repo add hashicorp https://helm.releases.hashicorp.com
        helm repo update
    fi
    
    log_info "Helm repository configured ✓"
}

# Deploy Vault
deploy_vault() {
    log_info "Deploying Vault to Kubernetes staging..."
    
    if helm status "$VAULT_RELEASE" -n "$NAMESPACE" &> /dev/null; then
        log_warn "Vault release already exists. Upgrading..."
        helm upgrade "$VAULT_RELEASE" hashicorp/vault \
            --namespace "$NAMESPACE" \
            --version "$VAULT_CHART_VERSION" \
            --values "$VAULT_VALUES_FILE" \
            --wait \
            --timeout 5m
    else
        helm install "$VAULT_RELEASE" hashicorp/vault \
            --namespace "$NAMESPACE" \
            --version "$VAULT_CHART_VERSION" \
            --values "$VAULT_VALUES_FILE" \
            --wait \
            --timeout 5m
    fi
    
    log_info "Vault deployed ✓"
}

# Wait for Vault pod to be running
wait_for_vault() {
    log_info "Waiting for Vault pod to be running..."
    
    kubectl wait --for=condition=Ready pod/vault-0 \
        -n "$NAMESPACE" \
        --timeout=300s || true
    
    # Vault pod will be running but not ready until unsealed
    sleep 5
    log_info "Vault pod is running ✓"
}

# Initialize Vault
initialize_vault() {
    log_info "Initializing Vault..."
    
    # Check if already initialized
    if kubectl exec -n "$NAMESPACE" vault-0 -- vault status 2>&1 | grep -q "Initialized.*true"; then
        log_warn "Vault is already initialized, skipping..."
        return 0
    fi
    
    # Initialize with 3 key shares for staging (more secure than dev's 1 share)
    INIT_OUTPUT=$(kubectl exec -n "$NAMESPACE" vault-0 -- vault operator init \
        -key-shares=3 \
        -key-threshold=2 \
        -format=json)
    
    # Save to temporary file
    VAULT_KEYS_FILE="/tmp/vault-staging-keys.json"
    echo "$INIT_OUTPUT" > "$VAULT_KEYS_FILE"
    chmod 600 "$VAULT_KEYS_FILE"
    
    log_info "Vault initialized ✓"
    log_warn "Vault keys saved to: $VAULT_KEYS_FILE"
    log_warn "IMPORTANT: Save these keys SECURELY and then DELETE this file!"
    
    # Export for use in this script
    export VAULT_UNSEAL_KEY_1=$(echo "$INIT_OUTPUT" | jq -r '.unseal_keys_b64[0]')
    export VAULT_UNSEAL_KEY_2=$(echo "$INIT_OUTPUT" | jq -r '.unseal_keys_b64[1]')
    export VAULT_ROOT_TOKEN=$(echo "$INIT_OUTPUT" | jq -r '.root_token')
    
    echo ""
    echo "=========================================="
    echo "Vault Root Token: $VAULT_ROOT_TOKEN"
    echo "Vault Unseal Keys (need 2 of 3):"
    echo "  Key 1: $VAULT_UNSEAL_KEY_1"
    echo "  Key 2: $VAULT_UNSEAL_KEY_2"
    echo "=========================================="
    echo ""
}

# Unseal Vault
unseal_vault() {
    log_info "Unsealing Vault..."
    
    # Check if already unsealed
    if kubectl exec -n "$NAMESPACE" vault-0 -- vault status 2>&1 | grep -q "Sealed.*false"; then
        log_warn "Vault is already unsealed, skipping..."
        return 0
    fi
    
    # Load keys if not in environment
    if [ -z "${VAULT_UNSEAL_KEY_1:-}" ]; then
        VAULT_KEYS_FILE="/tmp/vault-staging-keys.json"
        if [ -f "$VAULT_KEYS_FILE" ]; then
            export VAULT_UNSEAL_KEY_1=$(jq -r '.unseal_keys_b64[0]' "$VAULT_KEYS_FILE")
            export VAULT_UNSEAL_KEY_2=$(jq -r '.unseal_keys_b64[1]' "$VAULT_KEYS_FILE")
            export VAULT_ROOT_TOKEN=$(jq -r '.root_token' "$VAULT_KEYS_FILE")
        else
            log_error "Vault keys file not found and VAULT_UNSEAL_KEY_1 not set"
            log_error "Please set VAULT_UNSEAL_KEY_1 and VAULT_UNSEAL_KEY_2 environment variables"
            exit 1
        fi
    fi
    
    # Unseal with 2 keys (threshold is 2)
    kubectl exec -n "$NAMESPACE" vault-0 -- vault operator unseal "$VAULT_UNSEAL_KEY_1"
    kubectl exec -n "$NAMESPACE" vault-0 -- vault operator unseal "$VAULT_UNSEAL_KEY_2"
    
    log_info "Vault unsealed ✓"
}

# Configure Vault for Wardseal
configure_vault() {
    log_info "Configuring Vault for Wardseal staging..."
    
    # Load root token if not in environment
    if [ -z "${VAULT_ROOT_TOKEN:-}" ]; then
        VAULT_KEYS_FILE="/tmp/vault-staging-keys.json"
        if [ -f "$VAULT_KEYS_FILE" ]; then
            export VAULT_ROOT_TOKEN=$(jq -r '.root_token' "$VAULT_KEYS_FILE")
        else
            log_error "Vault keys file not found and VAULT_ROOT_TOKEN not set"
            log_error "Please set VAULT_ROOT_TOKEN environment variable"
            exit 1
        fi
    fi
    
    # Enable Transit secrets engine
    log_info "Enabling Transit secrets engine..."
    kubectl exec -n "$NAMESPACE" vault-0 -- vault login "$VAULT_ROOT_TOKEN" > /dev/null
    kubectl exec -n "$NAMESPACE" vault-0 -- vault secrets enable transit 2>/dev/null || log_warn "Transit already enabled"
    
    # Create JWT signing key (matching values-staging.yaml)
    log_info "Creating JWT signing key: wardseal-signing-key-staging..."
    kubectl exec -n "$NAMESPACE" vault-0 -- vault write -f transit/keys/wardseal-signing-key-staging \
        type=ecdsa-p256 \
        exportable=false \
        allow_plaintext_backup=false 2>/dev/null || log_warn "Key already exists"
    
    # Configure key rotation (90 days for staging)
    kubectl exec -n "$NAMESPACE" vault-0 -- vault write transit/keys/wardseal-signing-key-staging/config \
        auto_rotate_period=2160h
    
    # Create policy for wardseal
    log_info "Creating Vault policy for Wardseal staging..."
    kubectl exec -n "$NAMESPACE" vault-0 -- vault policy write wardseal-auth-staging - <<EOF
# Allow signing with the JWT key
path "transit/sign/wardseal-signing-key-staging" {
  capabilities = ["create", "update"]
}

# Allow verifying signatures
path "transit/verify/wardseal-signing-key-staging" {
  capabilities = ["create", "update"]
}

# Allow reading key metadata
path "transit/keys/wardseal-signing-key-staging" {
  capabilities = ["read"]
}
EOF
    
    # Enable AppRole auth
    log_info "Enabling AppRole authentication..."
    kubectl exec -n "$NAMESPACE" vault-0 -- vault auth enable approle 2>/dev/null || log_warn "AppRole already enabled"
    
    # Create AppRole
    log_info "Creating AppRole for Wardseal staging..."
    kubectl exec -n "$NAMESPACE" vault-0 -- vault write auth/approle/role/wardseal-auth-staging \
        token_policies="wardseal-auth-staging" \
        token_ttl=1h \
        token_max_ttl=24h \
        bind_secret_id=true \
        secret_id_ttl=0 \
        secret_id_num_uses=0
    
    # Get RoleID and SecretID
    log_info "Retrieving AppRole credentials..."
    ROLE_ID=$(kubectl exec -n "$NAMESPACE" vault-0 -- vault read -field=role_id auth/approle/role/wardseal-auth-staging/role-id)
    SECRET_ID=$(kubectl exec -n "$NAMESPACE" vault-0 -- vault write -field=secret_id -f auth/approle/role/wardseal-auth-staging/secret-id)
    
    # Save to file for wardseal deployment
    APPROLE_FILE="/tmp/vault-approle-staging.json"
    cat > "$APPROLE_FILE" <<EOF
{
  "role_id": "$ROLE_ID",
  "secret_id": "$SECRET_ID"
}
EOF
    chmod 600 "$APPROLE_FILE"
    
    log_info "AppRole credentials saved to: $APPROLE_FILE"
    
    echo ""
    echo "=========================================="
    echo "Vault AppRole Credentials:"
    echo "Role ID: $ROLE_ID"
    echo "Secret ID: $SECRET_ID"
    echo "=========================================="
    echo ""
}

# Verify Vault configuration
verify_vault() {
    log_info "Verifying Vault configuration..."
    
    # Check Vault status
    kubectl exec -n "$NAMESPACE" vault-0 -- vault status
    
    # List Transit keys
    log_info "Transit keys:"
    kubectl exec -n "$NAMESPACE" vault-0 -- vault list transit/keys
    
    log_info "Vault configuration verified ✓"
}

# Main execution
main() {
    log_info "Starting Vault setup for Wardseal staging environment..."
    echo ""
    
    check_prerequisites
    create_namespace
    check_tls_certificate
    add_helm_repo
    deploy_vault
    wait_for_vault
    initialize_vault
    unseal_vault
    configure_vault
    verify_vault
    
    echo ""
    log_info "=========================================="
    log_info "Vault setup completed successfully! ✓"
    log_info "=========================================="
    echo ""
    log_info "Next steps:"
    log_info "1. SECURELY save the Vault keys and tokens, then DELETE /tmp/vault-staging-keys.json"
    log_info "2. Run ./scripts/deploy_wardseal_staging.sh to deploy Wardseal"
    log_info "3. Consider setting up automated backups for Vault data"
    echo ""
    log_warn "SECURITY REMINDERS:"
    log_warn "- Vault keys are in /tmp/vault-staging-keys.json - SAVE AND DELETE!"
    log_warn "- AppRole credentials are in /tmp/vault-approle-staging.json"
    log_warn "- DO NOT commit these files to git!"
    log_warn "- Consider using auto-unseal for production-grade security"
    echo ""
}

# Run main function
main "$@"
