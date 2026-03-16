#!/bin/bash
set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

NAMESPACE="${NAMESPACE:-wardseal}"
RELEASE_NAME="${RELEASE_NAME:-wardseal}"
CHART_PATH="${CHART_PATH:-deploy/charts/wardseal}"
BASE_VALUES="${BASE_VALUES:-deploy/charts/wardseal/values.yaml}"
ENV_VALUES="${ENV_VALUES:-deploy/charts/wardseal/values-staging.yaml}"
EXPECTED_INGRESS_CLASS="${EXPECTED_INGRESS_CLASS:-traefik}"
TRAEFIK_NAMESPACE="${TRAEFIK_NAMESPACE:-traefik}"
CERT_ISSUER="${CERT_ISSUER:-}"

FAILED=0
RENDER_SUCCEEDED=0

pass() {
  echo -e "${GREEN}✔${NC} $1"
}

warn() {
  echo -e "${YELLOW}⚠${NC} $1"
}

fail() {
  echo -e "${RED}✖${NC} $1"
  FAILED=1
}

section() {
  echo ""
  echo -e "${BLUE}== $1 ==${NC}"
}

require_cmd() {
  local cmd="$1"
  if command -v "$cmd" >/dev/null 2>&1; then
    pass "Command available: $cmd"
  else
    fail "Missing required command: $cmd"
  fi
}

section "Tooling"
require_cmd kubectl
require_cmd helm

if [[ "$FAILED" -ne 0 ]]; then
  echo -e "${RED}Preflight failed early due to missing tooling.${NC}"
  exit 1
fi

section "Cluster Connectivity"
if kubectl cluster-info >/dev/null 2>&1; then
  pass "kubectl can reach the cluster"
else
  fail "kubectl cannot reach a cluster/context"
fi

section "Traefik Ingress Controller"
if kubectl get ingressclass "$EXPECTED_INGRESS_CLASS" >/dev/null 2>&1; then
  pass "IngressClass exists: $EXPECTED_INGRESS_CLASS"
else
  fail "IngressClass not found: $EXPECTED_INGRESS_CLASS"
fi

if ! kubectl get namespace "$TRAEFIK_NAMESPACE" >/dev/null 2>&1; then
  DETECTED_TRAEFIK_NAMESPACE=$(kubectl get ingressclass "$EXPECTED_INGRESS_CLASS" -o jsonpath='{.metadata.annotations.meta\.helm\.sh/release-namespace}' 2>/dev/null || true)
  if [[ -n "$DETECTED_TRAEFIK_NAMESPACE" ]] && kubectl get namespace "$DETECTED_TRAEFIK_NAMESPACE" >/dev/null 2>&1; then
    warn "Traefik namespace '$TRAEFIK_NAMESPACE' not found; auto-detected '$DETECTED_TRAEFIK_NAMESPACE' from IngressClass metadata"
    TRAEFIK_NAMESPACE="$DETECTED_TRAEFIK_NAMESPACE"
  else
    fail "Traefik namespace not found: $TRAEFIK_NAMESPACE"
  fi
fi

if kubectl get namespace "$TRAEFIK_NAMESPACE" >/dev/null 2>&1; then
  pass "Traefik namespace exists: $TRAEFIK_NAMESPACE"
fi

if kubectl get pods -n "$TRAEFIK_NAMESPACE" >/dev/null 2>&1; then
  READY_COUNT=$(kubectl get pods -n "$TRAEFIK_NAMESPACE" --no-headers 2>/dev/null | awk '$2 ~ /^[1-9][0-9]*\/[1-9][0-9]*$/ && $3=="Running" {count++} END {print count+0}')
  if [[ "$READY_COUNT" -gt 0 ]]; then
    pass "Traefik has running pods in namespace $TRAEFIK_NAMESPACE"
  else
    warn "No clearly ready Traefik pods detected in $TRAEFIK_NAMESPACE"
  fi
else
  fail "Unable to list pods in namespace: $TRAEFIK_NAMESPACE"
fi

section "Cert Manager Issuer"
if [[ -z "$CERT_ISSUER" ]]; then
  warn "CERT_ISSUER not set; skipping ClusterIssuer validation"
elif kubectl get clusterissuer "$CERT_ISSUER" >/dev/null 2>&1; then
  pass "ClusterIssuer found: $CERT_ISSUER"
else
  warn "ClusterIssuer not found: $CERT_ISSUER (continue only if you use another issuer)"
fi

section "Helm Values & Template Rendering"
rm -f /tmp/wardseal-traefik-rendered.yaml /tmp/wardseal-traefik-rendered.err

if [[ -f "$BASE_VALUES" ]]; then
  pass "Base values file found: $BASE_VALUES"
else
  fail "Base values file missing: $BASE_VALUES"
fi

if [[ -f "$ENV_VALUES" ]]; then
  pass "Environment values file found: $ENV_VALUES"
else
  fail "Environment values file missing: $ENV_VALUES"
fi

if helm dependency build "$CHART_PATH" >/tmp/wardseal-traefik-deps.out 2>/tmp/wardseal-traefik-deps.err; then
  pass "Helm chart dependencies are available"
else
  fail "Helm dependency build failed (see /tmp/wardseal-traefik-deps.err)"
fi

if helm template "$RELEASE_NAME" "$CHART_PATH" -n "$NAMESPACE" -f "$BASE_VALUES" -f "$ENV_VALUES" >/tmp/wardseal-traefik-rendered.yaml 2>/tmp/wardseal-traefik-rendered.err; then
  pass "Helm template render succeeded"
  RENDER_SUCCEEDED=1
else
  fail "Helm template render failed (see /tmp/wardseal-traefik-rendered.err)"
fi

if [[ "$RENDER_SUCCEEDED" -eq 1 && -f /tmp/wardseal-traefik-rendered.yaml ]]; then
  if grep -q "ingressClassName: $EXPECTED_INGRESS_CLASS" /tmp/wardseal-traefik-rendered.yaml; then
    pass "Rendered manifests contain ingressClassName: $EXPECTED_INGRESS_CLASS"
  else
    fail "Rendered manifests do not contain ingressClassName: $EXPECTED_INGRESS_CLASS"
  fi
fi

section "Route Coverage Sanity"
if [[ "$RENDER_SUCCEEDED" -eq 1 && -f /tmp/wardseal-traefik-rendered.yaml ]]; then
  for path in "/api/v1/users" "/api/v1/groups" "/api/v1/oauth" "/api/v1/governance"; do
    if grep -q "path: $path" /tmp/wardseal-traefik-rendered.yaml; then
      pass "Rendered ingress path present: $path"
    else
      fail "Rendered ingress path missing: $path"
    fi
  done
else
  warn "Skipping route coverage checks because render did not succeed"
fi

echo ""
if [[ "$FAILED" -eq 0 ]]; then
  echo -e "${GREEN}Traefik preflight passed. Safe to run Helm deploy.${NC}"
  exit 0
fi

echo -e "${RED}Traefik preflight failed. Resolve issues before deployment.${NC}"
exit 1
