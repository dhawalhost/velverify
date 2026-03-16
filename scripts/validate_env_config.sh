#!/usr/bin/env bash
set -euo pipefail

CHART_DIR="${CHART_DIR:-deploy/charts/wardseal}"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

pass() { echo "✔ $1"; }
fail() { echo "✖ $1"; exit 1; }

render() {
  local name="$1"
  shift
  helm template wardseal "$CHART_DIR" "$@" > "$TMP_DIR/$name.yaml"
}

check_contains() {
  local file="$1"
  local pattern="$2"
  local msg="$3"
  if grep -q "$pattern" "$file"; then
    pass "$msg"
  else
    fail "$msg"
  fi
}

check_not_contains() {
  local file="$1"
  local pattern="$2"
  local msg="$3"
  if grep -q "$pattern" "$file"; then
    fail "$msg"
  else
    pass "$msg"
  fi
}

echo "Rendering environment manifests..."
render local -f "$CHART_DIR/values.yaml" -f "$CHART_DIR/values-local.yaml"
render staging -f "$CHART_DIR/values.yaml" -f "$CHART_DIR/values-staging.yaml"
render staging-cm -f "$CHART_DIR/values.yaml" -f "$CHART_DIR/values-staging.yaml" -f "$CHART_DIR/values-staging-certmanager.yaml"
render prod -f "$CHART_DIR/values.yaml" -f "$CHART_DIR/values-production.yaml"
render prod-cm -f "$CHART_DIR/values.yaml" -f "$CHART_DIR/values-production.yaml" -f "$CHART_DIR/values-production-certmanager.yaml"

echo "Checking ingress class consistency..."
for file in "$TMP_DIR"/*.yaml; do
  check_contains "$file" 'ingressClassName: traefik' "$(basename "$file"): ingress class is traefik"
done

echo "Checking cert-manager split behavior..."
check_not_contains "$TMP_DIR/staging.yaml" 'cert-manager.io/cluster-issuer' "staging base has no cert-manager issuer"
check_contains "$TMP_DIR/staging-cm.yaml" 'cert-manager.io/cluster-issuer: letsencrypt-staging' "staging cert-manager overlay sets letsencrypt-staging"
check_not_contains "$TMP_DIR/prod.yaml" 'cert-manager.io/cluster-issuer' "production base has no cert-manager issuer"
check_contains "$TMP_DIR/prod-cm.yaml" 'cert-manager.io/cluster-issuer: letsencrypt-prod' "production cert-manager overlay sets letsencrypt-prod"

echo "Checking expected ingress hosts..."
check_contains "$TMP_DIR/local.yaml" 'host: "auth.wardseal.local"' "local auth host"
check_contains "$TMP_DIR/local.yaml" 'host: "api.wardseal.local"' "local api host"
check_contains "$TMP_DIR/local.yaml" 'host: "console.wardseal.local"' "local console host"
check_contains "$TMP_DIR/local.yaml" 'host: "wardseal.local"' "local landing host"
check_contains "$TMP_DIR/local.yaml" 'host: "help.wardseal.local"' "local help host"
check_contains "$TMP_DIR/staging.yaml" 'host: "auth-staging.wardseal.com"' "staging auth host"
check_contains "$TMP_DIR/staging.yaml" 'host: "api-staging.wardseal.com"' "staging api host"
check_contains "$TMP_DIR/staging.yaml" 'host: "console-staging.wardseal.com"' "staging console host"
check_contains "$TMP_DIR/staging.yaml" 'host: "staging.wardseal.com"' "staging landing host"
check_contains "$TMP_DIR/staging.yaml" 'host: "help-staging.wardseal.com"' "staging help host"
check_contains "$TMP_DIR/prod.yaml" 'host: "auth.wardseal.com"' "production auth host"
check_contains "$TMP_DIR/prod.yaml" 'host: "api.wardseal.com"' "production api host"
check_contains "$TMP_DIR/prod.yaml" 'host: "console.wardseal.com"' "production console host"
check_contains "$TMP_DIR/prod.yaml" 'host: "wardseal.com"' "production landing host"
check_contains "$TMP_DIR/prod.yaml" 'host: "help.wardseal.com"' "production help host"

echo "Checking critical URL/env configuration..."
check_contains "$TMP_DIR/local.yaml" 'value: "http://auth.wardseal.local"' "local AUTH_SERVICE_URL"
check_contains "$TMP_DIR/staging.yaml" 'value: "https://auth-staging.wardseal.com"' "staging AUTH_SERVICE_URL"
check_contains "$TMP_DIR/prod.yaml" 'value: "https://auth.wardseal.com"' "production AUTH_SERVICE_URL"
check_not_contains "$TMP_DIR/prod.yaml" 'admin.wardseal.com' "production admin host removed"
check_not_contains "$TMP_DIR/staging.yaml" 'admin-staging.wardseal.com' "staging admin host removed"

echo "Checking scaling/runtime env propagation..."
for file in "$TMP_DIR/local.yaml" "$TMP_DIR/staging.yaml" "$TMP_DIR/prod.yaml"; do
  check_contains "$file" 'name: "REDIS_ADDR"' "$(basename "$file"): REDIS_ADDR present"
  check_contains "$file" 'name: "RATE_LIMIT_KEY_PREFIX"' "$(basename "$file"): RATE_LIMIT_KEY_PREFIX present"
  check_contains "$file" 'name: "WEBAUTHN_SESSION_TTL_SECONDS"' "$(basename "$file"): WEBAUTHN_SESSION_TTL_SECONDS present"
done

echo "Checking landing deployment posture..."
check_contains "$TMP_DIR/local.yaml" 'name: wardseal-landingui' "local landing chart rendered"
check_contains "$TMP_DIR/staging.yaml" 'name: wardseal-landingui' "staging landing chart rendered"
check_contains "$TMP_DIR/prod.yaml" 'name: wardseal-landingui' "production landing chart rendered"

echo ""
echo "All environment consistency checks passed."
