#!/bin/bash

###############################################################################
# Production Preflight Checklist Script
#
# This script validates production deployment prerequisites before applying
# Helm manifests. It checks DNS, TLS certificates, K8s secrets, Vault setup,
# and Helm values to catch configuration issues early.
#
# Usage: bash scripts/preflight_production.sh
#
# Exit codes:
#   0 = All checks passed
#   1 = One or more checks failed
###############################################################################

set -euo pipefail

# ANSI color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Counters
PASSED=0
FAILED=0
WARNINGS=0

# Helper functions
log_pass() {
  echo -e "${GREEN}✓${NC} $1"
  ((PASSED++))
}

log_fail() {
  echo -e "${RED}✗${NC} $1"
  ((FAILED++))
}

log_warn() {
  echo -e "${YELLOW}⚠${NC} $1"
  ((WARNINGS++))
}

log_info() {
  echo -e "${BLUE}ℹ${NC} $1"
}

section() {
  echo ""
  echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo -e "${BLUE}$1${NC}"
  echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

###############################################################################
# Configuration
###############################################################################

section "1. Configuration Validation"

# Get config from values-production.yaml
if [[ ! -f deploy/charts/wardseal/values-production.yaml ]]; then
  log_fail "values-production.yaml not found"
  exit 1
fi

# Extract key values from values-production.yaml using grep and awk
AUTH_SERVICE_URL=$(grep "AUTH_SERVICE_URL:" deploy/charts/wardseal/values-production.yaml | awk '{print $2}' | tr -d '"')
UI_URL=$(grep "UI_URL:" deploy/charts/wardseal/values-production.yaml | awk '{print $2}' | tr -d '"')
KMS_PROVIDER=$(grep "KMS_PROVIDER:" deploy/charts/wardseal/values-production.yaml | awk '{print $2}' | tr -d '"')

if [[ -z "$AUTH_SERVICE_URL" ]]; then
  log_fail "AUTH_SERVICE_URL not found in values-production.yaml"
else
  log_pass "AUTH_SERVICE_URL configured: $AUTH_SERVICE_URL"
fi

if [[ -z "$UI_URL" ]]; then
  log_fail "UI_URL not found in values-production.yaml"
else
  log_pass "UI_URL configured: $UI_URL"
fi

if [[ "$KMS_PROVIDER" != "vault" ]]; then
  log_fail "KMS_PROVIDER must be 'vault' for production (found: $KMS_PROVIDER)"
else
  log_pass "KMS_PROVIDER correctly set to 'vault'"
fi

# Check Vault AppRole secret reference
if grep -q 'existingSecret: wardseal-vault-kms-production' deploy/charts/wardseal/values-production.yaml; then
  log_pass "Vault AppRole secret correctly referenced: wardseal-vault-kms-production"
else
  log_fail "Vault AppRole secret not correctly set in values-production.yaml"
fi

###############################################################################
# Kubernetes Cluster Connectivity
###############################################################################

section "2. Kubernetes Cluster Connectivity"

if ! command -v kubectl &> /dev/null; then
  log_fail "kubectl not found in PATH"
  exit 1
fi

if ! kubectl cluster-info &> /dev/null; then
  log_fail "Cannot connect to Kubernetes cluster"
  exit 1
fi

KUBE_CONTEXT=$(kubectl config current-context)
log_pass "Connected to cluster: $KUBE_CONTEXT"

NAMESPACE="default"
if kubectl get namespace wardseal &> /dev/null; then
  NAMESPACE="wardseal"
  log_pass "Using namespace: wardseal"
else
  log_warn "Namespace 'wardseal' not found; defaulting to 'default'"
  log_info "Consider creating namespace: kubectl create namespace wardseal"
fi

###############################################################################
# Kubernetes Secrets
###############################################################################

section "3. Kubernetes Secrets"

check_secret() {
  local secret_name=$1
  local namespace=${2:-default}
  local required_keys=$3
  
  if kubectl get secret "$secret_name" -n "$namespace" &> /dev/null; then
    log_pass "Secret exists: $secret_name"
    
    # Check required keys
    IFS=',' read -ra KEYS <<< "$required_keys"
    for key in "${KEYS[@]}"; do
      key=$(echo "$key" | xargs) # trim whitespace
      if kubectl get secret "$secret_name" -n "$namespace" -o jsonpath="{.data.$key}" &> /dev/null; then
        local value=$(kubectl get secret "$secret_name" -n "$namespace" -o jsonpath="{.data.$key}" | base64 -d)
        if [[ -n "$value" ]]; then
          log_pass "  └─ Key '$key' present and not empty"
        else
          log_fail "  └─ Key '$key' is empty"
        fi
      else
        log_fail "  └─ Key '$key' missing from secret"
      fi
    done
  else
    log_fail "Secret not found: $secret_name"
  fi
}

log_info "Checking required secrets in namespace: $NAMESPACE"

# Database credentials
log_info "Checking database credentials secret..."
check_secret "wardseal-database" "$NAMESPACE" "DATABASE_URL,DB_USER,DB_PASSWORD"

# Service auth secret (for internal service-to-service auth)
log_info "Checking service auth secret..."
check_secret "wardseal-service-auth" "$NAMESPACE" "SERVICE_AUTH_SECRET,SERVICE_JWT_PUBLIC_KEY"

# Vault KMS secret (for JWT signing via Vault Transit)
log_info "Checking Vault KMS secret..."
check_secret "wardseal-vault-kms-production" "$NAMESPACE" "VAULT_ADDR,VAULT_ROLE_ID,VAULT_SECRET_ID,VAULT_KEY_PATH,VAULT_KEY_NAME"

# License secret (if applicable)
log_info "Checking license secret..."
if kubectl get secret "wardseal-license" -n "$NAMESPACE" &> /dev/null; then
  log_pass "License secret exists"
else
  log_warn "License secret not found (may be optional)"
fi

###############################################################################
# DNS Resolution
###############################################################################

section "4. DNS Resolution"

check_dns() {
  local domain=$1
  
  if [[ "$domain" == https://* ]]; then
    domain=${domain#https://}
  fi
  if [[ "$domain" == http://* ]]; then
    domain=${domain#http://}
  fi
  # Remove path if present
  domain=${domain%%/*}
  
  if dig +short "$domain" &> /dev/null; then
    local ip=$(dig +short "$domain" | head -1)
    log_pass "DNS resolves for $domain: $ip"
  else
    log_fail "DNS does not resolve for $domain"
  fi
}

if command -v dig &> /dev/null; then
  log_info "Checking DNS resolution..."
  check_dns "$AUTH_SERVICE_URL"
  check_dns "$UI_URL"
else
  log_warn "dig command not found; skipping DNS checks (install dnsutils/bind-tools)"
fi

###############################################################################
# TLS Certificate Check
###############################################################################

section "5. TLS Certificates"

check_cert() {
  local domain=$1
  
  if [[ "$domain" == https://* ]]; then
    domain=${domain#https://}
  fi
  domain=${domain%%/*}
  
  if command -v openssl &> /dev/null; then
    # Try to get certificate info
    if timeout 5 openssl s_client -connect "$domain:443" -servername "$domain" < /dev/null 2>/dev/null | openssl x509 -noout -subject &> /dev/null; then
      local expiry=$(timeout 5 openssl s_client -connect "$domain:443" -servername "$domain" < /dev/null 2>/dev/null | openssl x509 -noout -enddate | cut -d= -f2)
      log_pass "TLS certificate found for $domain: expires $expiry"
    else
      log_warn "Could not verify TLS certificate for $domain (may be self-signed or not yet issued)"
    fi
  else
    log_warn "openssl not found; skipping TLS verification"
  fi
}

log_info "Checking TLS certificates..."
check_cert "$AUTH_SERVICE_URL"
check_cert "$UI_URL"

###############################################################################
# Ingress Configuration
###############################################################################

section "6. Ingress Configuration"

log_info "Checking Ingress resources in namespace: $NAMESPACE"

if kubectl get ingress -n "$NAMESPACE" &> /dev/null; then
  ingress_count=$(kubectl get ingress -n "$NAMESPACE" --no-headers 2>/dev/null | wc -l)
  if [[ $ingress_count -gt 0 ]]; then
    log_pass "Found $ingress_count Ingress resource(s)"
    
    # Check for critical hosts
    if kubectl get ingress -n "$NAMESPACE" -o jsonpath='{.items[*].spec.rules[*].host}' | grep -q "$(echo "$AUTH_SERVICE_URL" | sed 's|https://||' | cut -d/ -f1)"; then
      log_pass "Ingress configured for AUTH_SERVICE_URL domain"
    else
      log_warn "AUTH_SERVICE_URL domain not found in Ingress rules"
    fi
    
    if kubectl get ingress -n "$NAMESPACE" -o jsonpath='{.items[*].spec.rules[*].host}' | grep -q "$(echo "$UI_URL" | sed 's|https://||' | cut -d/ -f1)"; then
      log_pass "Ingress configured for UI_URL domain"
    else
      log_warn "UI_URL domain not found in Ingress rules"
    fi
  else
    log_fail "No Ingress resources found in namespace"
  fi
else
  log_warn "Could not query Ingress resources (may not be available)"
fi

###############################################################################
# Cert-Manager
###############################################################################

section "7. Cert-Manager Configuration"

if kubectl get ns cert-manager &> /dev/null; then
  log_pass "cert-manager namespace exists"
  
  cert_count=$(kubectl get cert -A --no-headers 2>/dev/null | wc -l)
  if [[ $cert_count -gt 0 ]]; then
    log_pass "Found $cert_count Certificate resource(s)"
    
    # Check certificate status
    kubectl get cert -A -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.status.conditions[?(@.type=="Ready")].status}{"\n"}{end}' | while read -r cert_name cert_ready; do
      if [[ "$cert_ready" == "True" ]]; then
        log_pass "  └─ Certificate ready: $cert_name"
      else
        log_warn "  └─ Certificate not ready: $cert_name (status: $cert_ready)"
      fi
    done
  else
    log_warn "No Certificate resources found"
  fi
else
  log_warn "cert-manager namespace not found (TLS may be managed differently)"
fi

###############################################################################
# Vault Configuration
###############################################################################

section "8. Vault Configuration"

if [[ -n "${VAULT_ADDR:-}" ]]; then
  log_pass "VAULT_ADDR is set: $VAULT_ADDR"
  
  if command -v vault &> /dev/null; then
    if vault status &> /dev/null; then
      log_pass "Vault is accessible and unsealed"
      
      # Check Transit engine
      if vault list secret/transit/keys &> /dev/null 2>&1 || vault list transit/keys &> /dev/null 2>&1; then
        log_pass "Transit engine appears to be enabled"
        
        # Check for production signing key
        if vault read transit/keys/wardseal-signing-key-production &> /dev/null 2>&1; then
          log_pass "Product signing key exists: wardseal-signing-key-production"
          
          key_type=$(vault read -field=type transit/keys/wardseal-signing-key-production 2>/dev/null || echo "unknown")
          if [[ "$key_type" == "rsa-2048" ]]; then
            log_pass "  └─ Key type is RSA-2048 (correct for RS256)"
          else
            log_fail "  └─ Key type is $key_type (must be rsa-2048 for RS256)"
          fi
        else
          log_fail "Transit key not found: wardseal-signing-key-production"
        fi
      else
        log_warn "Transit engine status could not be verified"
      fi
    else
      log_fail "Cannot access Vault or Vault is sealed"
    fi
  else
    log_warn "vault CLI not found; skipping Vault checks"
  fi
else
  log_warn "VAULT_ADDR not set in environment; skipping Vault validation"
fi

###############################################################################
# Helm Chart Validation
###############################################################################

section "9. Helm Chart Validation"

if ! command -v helm &> /dev/null; then
  log_fail "helm not found in PATH"
  exit 1
fi

if [[ ! -d deploy/charts/wardseal ]]; then
  log_fail "Helm chart not found at deploy/charts/wardseal"
  exit 1
fi

log_pass "Helm chart located"

# Test Helm template rendering
log_info "Testing Helm template rendering..."
if helm template wardseal deploy/charts/wardseal \
  -f deploy/charts/wardseal/values-production.yaml \
  --namespace wardseal \
  &> /tmp/helm-render.log; then
  log_pass "Helm templates render successfully"
  
  # Check for required patterns in rendered output
  if grep -q "KMS_PROVIDER.*vault" /tmp/helm-render.log; then
    log_pass "  └─ KMS_PROVIDER=vault in rendered manifests"
  else
    log_fail "  └─ KMS_PROVIDER=vault NOT found in rendered manifests"
  fi
  
  if grep -q "wardseal-vault-kms-production" /tmp/helm-render.log; then
    log_pass "  └─ Vault secret reference found: wardseal-vault-kms-production"
  else
    log_fail "  └─ Vault secret reference NOT found in rendered manifests"
  fi
else
  log_fail "Helm template rendering failed"
  cat /tmp/helm-render.log
fi

###############################################################################
# PostgreSQL Database
###############################################################################

section "10. PostgreSQL Database"

log_info "Checking PostgreSQL connectivity..."

# Get database URL from secret
if kubectl get secret "wardseal-database" -n "$NAMESPACE" &> /dev/null; then
  db_url=$(kubectl get secret "wardseal-database" -n "$NAMESPACE" -o jsonpath="{.data.DATABASE_URL}" 2>/dev/null | base64 -d 2>/dev/null || echo "")
  
  if [[ -n "$db_url" ]]; then
    log_pass "Database URL found in secret"
    
    # Extract connection info (basic parsing of postgres://user:pass@host:port/db)
    if [[ "$db_url" == postgres* ]]; then
      log_pass "Database URL format appears valid"
      
      # Try to extract and test connection if psql is available
      if command -v psql &> /dev/null; then
        log_info "Attempting database connection test..."
        if timeout 5 psql "$db_url" -c "SELECT version();" &> /dev/null; then
          log_pass "Database connection successful"
        else
          log_warn "Database connection test failed (may be network issue)"
        fi
      else
        log_warn "psql not found; skipping connection test (install postgresql-client)"
      fi
    else
      log_fail "Database URL format not recognized (must be postgresql://...)"
    fi
  else
    log_fail "DATABASE_URL not found in secret"
  fi
else
  log_fail "Database secret not found"
fi

###############################################################################
# Summary Report
###############################################################################

section "Summary"

echo ""
echo -e "Checks Passed:  ${GREEN}$PASSED${NC}"
echo -e "Checks Failed:  ${RED}$FAILED${NC}"
echo -e "Warnings:       ${YELLOW}$WARNINGS${NC}"
echo ""

if [[ $FAILED -eq 0 ]]; then
  echo -e "${GREEN}✓ All critical checks passed!${NC}"
  if [[ $WARNINGS -gt 0 ]]; then
    echo -e "${YELLOW}Review $WARNINGS warning(s) above before deploying.${NC}"
  fi
  echo ""
  echo "Next steps:"
  echo "  1. Review all YELLOW warnings"
  echo "  2. Verify Vault Transit key rotation settings (recommended: 2160h / 90 days)"
  echo "  3. Ensure database backups are configured"
  echo "  4. Deploy with: helm install wardseal deploy/charts/wardseal -f deploy/charts/wardseal/values-production.yaml -n wardseal"
  echo ""
  exit 0
else
  echo -e "${RED}✗ Deployment blocked: $FAILED critical check(s) failed${NC}"
  echo ""
  echo "Fix the failures above before deploying."
  echo ""
  exit 1
fi
