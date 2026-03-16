#!/usr/bin/env bash
# setup_k8s_local.sh — Compatibility wrapper for local k8s setup
#
# Canonical script: scripts/deploy_local_k8s.sh
# This wrapper keeps older docs/commands working.
set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
pass()    { echo -e "${GREEN}✔${NC} $1"; }
warn()    { echo -e "${YELLOW}⚠${NC} $1"; }
section() { echo -e "\n${BLUE}══ $1 ══${NC}"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$REPO_ROOT"

section "Local Kubernetes Setup"
pass "Using Rancher Desktop workflow via scripts/deploy_local_k8s.sh"

for cmd in kubectl helm docker; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Missing required command: $cmd"
    exit 1
  fi
done

CURRENT_CTX="$(kubectl config current-context 2>/dev/null || true)"
if [[ "$CURRENT_CTX" != "rancher-desktop" ]]; then
  warn "Current context is '$CURRENT_CTX' (expected 'rancher-desktop')."
  warn "The deploy script will attempt to switch context automatically."
fi

if docker compose ps --services --filter status=running 2>/dev/null | grep -q '^traefik$'; then
  warn "Docker Compose traefik is currently running and may conflict with local k8s ingress on port 80."
  warn "Consider: docker compose stop traefik"
fi

ARGS=()
if [[ "${1:-}" == "--sync-charts-only" ]]; then
  ARGS+=("--sync-charts-only")
fi

if [[ -z "${DEPLOY_LANDING:-}" ]]; then
  export DEPLOY_LANDING=true
  pass "DEPLOY_LANDING not set; defaulting to true"
fi

bash scripts/deploy_local_k8s.sh "${ARGS[@]}"
