#!/usr/bin/env bash
# =============================================================================
# deploy_local_k8s.sh — Full local Kubernetes deployment for Rancher Desktop
# =============================================================================
# Prerequisites:
#   - Rancher Desktop running with containerd or dockerd runtime
#   - kubectl context set to rancher-desktop
#   - Helm 3
#   - dev keys generated: make generate-keys  (or run scripts/generate-dev-keys.sh)
# =============================================================================
set -euo pipefail

# ── Colors ─────────────────────────────────────────────────────────────────
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; BLUE='\033[0;34m'; NC='\033[0m'
pass()    { echo -e "${GREEN}✔${NC} $1"; }
warn()    { echo -e "${YELLOW}⚠${NC} $1"; }
fail()    { echo -e "${RED}✖${NC} $1"; exit 1; }
section() { echo -e "\n${BLUE}══ $1 ══${NC}"; }

# ── Config ──────────────────────────────────────────────────────────────────
NAMESPACE="${NAMESPACE:-wardseal-local}"
RELEASE="${RELEASE:-wardseal}"
CHART_DIR="deploy/charts/wardseal"
K8S_LOCAL_DIR="deploy/k8s-local"
DEV_KEYS_DIR="deploy/dev-keys"
MIGRATIONS_DIR="migrations"
SYNC_ONLY=false
DEPLOY_LANDING="${DEPLOY_LANDING:-true}"

SKIP_BUILD=false
SKIP_INFRA=false
SKIP_SYNC=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --sync-charts-only)
      SYNC_ONLY=true
      shift
      ;;
    --with-landing)
      DEPLOY_LANDING=true
      shift
      ;;
    --without-landing)
      DEPLOY_LANDING=false
      shift
      ;;
    --skip-build)
      SKIP_BUILD=true
      shift
      ;;
    --skip-infra)
      SKIP_INFRA=true
      shift
      ;;
    --skip-sync)
      SKIP_SYNC=true
      shift
      ;;
    *)
      fail "Unknown argument: $1\n  Supported: --sync-charts-only, --with-landing, --without-landing, --skip-build, --skip-infra, --skip-sync"
      ;;
  esac
done

LOCAL_HOSTS=("wardseal.local" "auth.wardseal.local" "api.wardseal.local" "manage.wardseal.local")

DB_USER="${DB_USER:-user}"
DB_PASS="${DB_PASS:-password}"

IMAGE_TAG="local"
SERVICES=("authsvc" "dirsvc" "govsvc" "policysvc" "provsvc")
POSTGRES_IMAGE="${POSTGRES_IMAGE:-postgres:15-alpine}"
REDIS_IMAGE="${REDIS_IMAGE:-redis:7-alpine}"

# ── Detect Rancher Desktop runtime ──────────────────────────────────────────
# Returns "docker-cri" if k3s uses cri-dockerd (Docker images visible directly),
# "nerdctl" if k3s uses native containerd (images must be imported to k8s.io).
detect_runtime() {
  if ! command -v docker >/dev/null 2>&1 && ! command -v nerdctl >/dev/null 2>&1; then
    fail "Neither nerdctl nor docker found. Is Rancher Desktop installed?"
  fi

  # Detect Rancher Desktop dockerd mode:
  # When docker info reports lima-rancher-desktop, k3s uses cri-dockerd and
  # docker images are shared with k3s without any import step needed.
  if command -v docker >/dev/null 2>&1; then
    local docker_name
    docker_name=$(docker info --format '{{.Name}}' 2>/dev/null || echo "")
    if [[ "$docker_name" == *"lima-rancher-desktop"* ]]; then
      echo "docker-cri"
      return
    fi
  fi

  # Fallback: if nerdctl is present assume native containerd (needs k8s.io import)
  if command -v nerdctl >/dev/null 2>&1; then
    echo "nerdctl"
  else
    echo "docker"
  fi
}

# Load an image into the k8s.io containerd namespace (native containerd mode)
load_image_containerd() {
  local image="$1"
  local tar_file="/tmp/${image//\//-}.tar"
  echo "  → Saving $image to tar..."
  docker save "$image:$IMAGE_TAG" -o "$tar_file"
  echo "  → Loading into k8s.io containerd namespace..."
  nerdctl -n k8s.io load -i "$tar_file"
  rm -f "$tar_file"
}

load_tagged_image_containerd() {
  local image_ref="$1"
  local image_sanitized="${image_ref//\//-}"
  local image_sanitized="${image_sanitized//:/-}"
  local tar_file="/tmp/${image_sanitized}.tar"
  echo "  → Saving $image_ref to tar..."
  docker save "$image_ref" -o "$tar_file"
  echo "  → Loading $image_ref into k8s.io containerd namespace..."
  nerdctl -n k8s.io load -i "$tar_file"
  rm -f "$tar_file"
}

pull_image_with_retry() {
  local image_ref="$1"
  local attempts=3
  local sleep_seconds=3

  for attempt in $(seq 1 $attempts); do
    if docker pull "$image_ref"; then
      pass "Pulled $image_ref"
      return 0
    fi
    if [[ "$attempt" -lt "$attempts" ]]; then
      warn "Failed to pull $image_ref (attempt $attempt/$attempts). Retrying in ${sleep_seconds}s..."
      sleep "$sleep_seconds"
    fi
  done

  fail "Could not pull $image_ref after $attempts attempts"
}

# ── Step 0: Verify we're in repo root ────────────────────────────────────────
section "Pre-flight"
[[ -f "go.mod" ]] || fail "Run this script from the repository root (wardseal/)"
pass "Working directory is repo root"

if [[ "$SYNC_ONLY" == "true" ]]; then
  section "Helm Chart Sync Only"
  bash scripts/sync_helm_charts.sh "$CHART_DIR" || fail "Helm chart sync failed"
  pass "Helm charts synced"
  exit 0
fi

# ── Step 1: Check tools ───────────────────────────────────────────────────────
section "Tool Check"
for cmd in kubectl helm; do
  command -v "$cmd" >/dev/null 2>&1 && pass "$cmd available" || fail "$cmd not found"
done
RUNTIME=$(detect_runtime)
case "$RUNTIME" in
  docker-cri) pass "Container runtime: Docker + cri-dockerd (images shared with k3s)" ;;
  nerdctl)    pass "Container runtime: containerd via nerdctl (images will be imported)" ;;
  docker)     pass "Container runtime: docker" ;;
esac

# ── Step 2: Check kubectl context ─────────────────────────────────────────────
section "Kubernetes Context"
CURRENT_CTX=$(kubectl config current-context 2>/dev/null || echo "none")
echo "  Current context: $CURRENT_CTX"

if [[ "$CURRENT_CTX" != "rancher-desktop" ]]; then
  warn "Context is not 'rancher-desktop'. Attempting to switch..."
  if kubectl config use-context rancher-desktop >/dev/null 2>&1; then
    pass "Switched to rancher-desktop context"
  else
    warn "Could not switch; continuing with context: $CURRENT_CTX"
    warn "If pods fail to start, run: kubectl config use-context rancher-desktop"
  fi
else
  pass "Using rancher-desktop context"
fi

kubectl cluster-info >/dev/null 2>&1 && pass "Cluster is reachable" || fail "Cluster unreachable"

if docker compose ps --services --filter status=running 2>/dev/null | grep -q '^traefik$'; then
  warn "Docker Compose traefik is running; it may conflict with local k8s ingress on port 80"
  warn "Consider: docker compose stop traefik"
fi

# ── Step 3: Build Docker images ───────────────────────────────────────────────
section "Building Docker Images"
if [[ "$SKIP_BUILD" == "true" ]]; then
  warn "--skip-build set: skipping image builds (using existing local images)"
else
for svc in "${SERVICES[@]}"; do
  if [[ ! -f "cmd/$svc/Dockerfile" ]]; then
    warn "Dockerfile not found for $svc — skipping"
    continue
  fi
  echo "  Building wardseal-$svc:$IMAGE_TAG ..."
  # Always build with docker (Rancher Desktop bridges docker -> containerd)
  # --load is required on Rancher Desktop to push the image through BuildKit
  # into the local dockerd (which cri-dockerd bridges to k3s)
  docker build --load -t "wardseal-$svc:$IMAGE_TAG" -f "cmd/$svc/Dockerfile" . \
    || fail "Failed to build $svc"
  pass "Built wardseal-$svc:$IMAGE_TAG"
done

# Build Admin UI (different context: web/admin, bake VITE_ URLs via --build-arg)
if [[ -d "web/admin" ]]; then
  echo "  Building wardseal-adminui:$IMAGE_TAG ..."
  docker build --load \
    --build-arg VITE_AUTHSVC_URL="http://auth.wardseal.local" \
    --build-arg VITE_DIRSVC_URL="http://api.wardseal.local" \
    --build-arg VITE_GOVSVC_URL="http://api.wardseal.local" \
    --build-arg VITE_APP_MODE="saas" \
    -t "wardseal-adminui:$IMAGE_TAG" \
    -f "web/admin/Dockerfile" \
    "web/admin" \
    || fail "Failed to build adminui"
  pass "Built wardseal-adminui:$IMAGE_TAG"
fi

# Build Landing Site (React + Vite SPA served by NGINX)
# Only built when DEPLOY_LANDING=true. The landing site is WardSeal's own
# marketing page and is NOT part of the core platform shipped to enterprise
# customers. Set DEPLOY_LANDING=true only when simulating the SaaS stack locally.
if [[ "$DEPLOY_LANDING" == "true" && -d "web/landing" ]]; then
  echo "  Building wardseal-landingui:$IMAGE_TAG ..."
  docker build --load \
    --build-arg VITE_ENVIRONMENT="local" \
    --build-arg VITE_SITE_BASE_URL="http://wardseal.local" \
    --build-arg VITE_CONSOLE_BASE_URL="http://manage.wardseal.local" \
    --build-arg VITE_SUPPORT_EMAIL="support@wardseal.com" \
    -t "wardseal-landingui:$IMAGE_TAG" \
    -f "web/landing/Dockerfile" \
    "web/landing" \
    || fail "Failed to build landingui"
  pass "Built wardseal-landingui:$IMAGE_TAG"
else
  [[ -d "web/landing" ]] && warn "Skipping landingui build (set DEPLOY_LANDING=true to include)"
fi

# wardseal-docs is handled in its own repo now
if [[ ! -d "../wardseal-docs" ]]; then
  warn "wardseal-docs directory not found at ../wardseal-docs — skipping"
fi

fi # end --skip-build

# If using native containerd (not cri-dockerd), import images into k8s.io namespace
if [[ "$SKIP_BUILD" == "true" ]]; then
  pass "--skip-build: skipping containerd import"
elif [[ "$RUNTIME" == "nerdctl" ]]; then
  section "Importing Images into k3s containerd"
  for svc in "${SERVICES[@]}"; do
    [[ -f "cmd/$svc/Dockerfile" ]] || continue
    load_image_containerd "wardseal-$svc"
    pass "Imported wardseal-$svc:$IMAGE_TAG into k8s.io"
  done
  if [[ -d "web/admin" ]]; then
    load_image_containerd "wardseal-adminui"
    pass "Imported wardseal-adminui:$IMAGE_TAG into k8s.io"
  fi
  if [[ "$DEPLOY_LANDING" == "true" && -d "web/landing" ]]; then
    load_image_containerd "wardseal-landingui"
    pass "Imported wardseal-landingui:$IMAGE_TAG into k8s.io"
  fi
else
  pass "Using cri-dockerd / docker runtime — images are available to k3s directly"
fi

# ── Step 4: Generate dev keys if missing ─────────────────────────────────────
section "JWT Keys"
if [[ ! -f "$DEV_KEYS_DIR/private_key.pem" || ! -f "$DEV_KEYS_DIR/public_key.pem" ]]; then
  warn "Dev keys not found. Generating..."
  ./scripts/generate-dev-keys.sh
fi
pass "Dev keys present at $DEV_KEYS_DIR/"

# ── Step 5: Create namespace ──────────────────────────────────────────────────
section "Namespace"
kubectl get namespace "$NAMESPACE" >/dev/null 2>&1 \
  && pass "Namespace $NAMESPACE already exists" \
  || { kubectl create namespace "$NAMESPACE"; pass "Created namespace $NAMESPACE"; }

# ── Step 6: Create Secrets ────────────────────────────────────────────────────
section "Secrets"

# DB credentials secret — includes host, port, username, password, database
# so each sub-chart can reference them via secretKeyRef
if kubectl get secret wardseal-db-credentials -n "$NAMESPACE" >/dev/null 2>&1; then
  pass "Secret wardseal-db-credentials already exists"
else
  kubectl create secret generic wardseal-db-credentials \
    -n "$NAMESPACE" \
    --from-literal=host="postgres.${NAMESPACE}.svc.cluster.local" \
    --from-literal=port="5432" \
    --from-literal=username="$DB_USER" \
    --from-literal=password="$DB_PASS" \
    --from-literal=database="identity_platform"
  pass "Created wardseal-db-credentials secret"
fi

# JWT keys secret
if kubectl get secret wardseal-jwt-keys -n "$NAMESPACE" >/dev/null 2>&1; then
  pass "Secret wardseal-jwt-keys already exists"
else
  kubectl create secret generic wardseal-jwt-keys \
    -n "$NAMESPACE" \
    --from-file=private_key.pem="$DEV_KEYS_DIR/private_key.pem" \
    --from-file=public_key.pem="$DEV_KEYS_DIR/public_key.pem"
  pass "Created wardseal-jwt-keys secret"
fi

# ── Step 7: Deploy Infra (Postgres + Redis) ───────────────────────────────────
section "Infra: Postgres + Redis"

if [[ "$SKIP_INFRA" == "true" ]]; then
  warn "--skip-infra: assuming Postgres and Redis are already running"
else

# Only pull if the image isn't already in the local Docker store
if ! docker image inspect "$POSTGRES_IMAGE" >/dev/null 2>&1; then
  pull_image_with_retry "$POSTGRES_IMAGE"
else
  pass "$POSTGRES_IMAGE already present locally"
fi
if ! docker image inspect "$REDIS_IMAGE" >/dev/null 2>&1; then
  pull_image_with_retry "$REDIS_IMAGE"
else
  pass "$REDIS_IMAGE already present locally"
fi

if [[ "$RUNTIME" == "nerdctl" ]]; then
  echo "  Importing infra images into k8s.io namespace..."
  load_tagged_image_containerd "$POSTGRES_IMAGE"
  pass "Imported $POSTGRES_IMAGE into k8s.io"
  load_tagged_image_containerd "$REDIS_IMAGE"
  pass "Imported $REDIS_IMAGE into k8s.io"
fi

kubectl apply -f "$K8S_LOCAL_DIR/postgres.yaml"
pass "Applied postgres manifest"

kubectl apply -f "$K8S_LOCAL_DIR/redis.yaml"
pass "Applied redis manifest"

echo "  Waiting for Postgres to be ready (up to 180s)..."
kubectl rollout status deployment/postgres -n "$NAMESPACE" --timeout=180s \
  && pass "Postgres ready" || {
    warn "Postgres did not become ready in time. Recent events:"
    kubectl describe deployment postgres -n "$NAMESPACE" | sed -n '/Events:/,$p' || true
    kubectl get pods -n "$NAMESPACE" -l app=postgres -o wide || true
    fail "Postgres not ready after 180s"
  }

echo "  Waiting for Redis to be ready (up to 60s)..."
kubectl rollout status deployment/redis -n "$NAMESPACE" --timeout=60s \
  && pass "Redis ready" || fail "Redis not ready after 60s"

fi # end --skip-infra

# ── Step 8: Run Migrations ────────────────────────────────────────────────────
section "Database Migrations"

# Create a ConfigMap from migration files so the Job can run them
echo "  Creating migrations ConfigMap from $MIGRATIONS_DIR/..."
kubectl create configmap wardseal-migrations-cm \
  -n "$NAMESPACE" \
  --from-file="$MIGRATIONS_DIR/" \
  --dry-run=client -o yaml | kubectl apply -f -
pass "Migrations ConfigMap applied ($(ls "$MIGRATIONS_DIR"/*.up.sql | wc -l | tr -d ' ') up files)"

# Delete any previous migration job to allow re-run
kubectl delete job wardseal-migrate -n "$NAMESPACE" --ignore-not-found >/dev/null 2>&1

kubectl apply -f "$K8S_LOCAL_DIR/migrate-job.yaml"
pass "Migration Job submitted"

echo "  Waiting for migrations to complete (up to 120s)..."
kubectl wait --for=condition=complete job/wardseal-migrate \
  -n "$NAMESPACE" --timeout=120s \
  && pass "Migrations completed successfully" \
  || {
    warn "Migration job did not complete in time. Checking logs..."
    kubectl logs -n "$NAMESPACE" -l app=wardseal-migrate --tail=40 || true
    fail "Migrations failed — fix errors before proceeding"
  }

# ── Step 9: Helm deploy ────────────────────────────────────────────────────────
section "Helm Deploy"

if [[ "$SKIP_SYNC" == "true" ]]; then
  warn "--skip-sync: skipping Helm chart packaging (using existing Chart.lock)"
else
  bash scripts/sync_helm_charts.sh "$CHART_DIR" || fail "Helm chart sync failed"
  pass "Helm chart dependencies and packages synced"
fi

helm upgrade --install "$RELEASE" "$CHART_DIR" \
  -n "$NAMESPACE" \
  -f "$CHART_DIR/values.yaml" \
  -f "$CHART_DIR/values-local.yaml" \
  --wait --timeout 3m

pass "Helm release '$RELEASE' deployed to namespace '$NAMESPACE'"

# ── Step 10: /etc/hosts entries ───────────────────────────────────────────────
section "/etc/hosts"

# k3s exposes via NodePort or Traefik on localhost:80 on Rancher Desktop
# Use word-boundary grep so e.g. "wardseal.local" doesn't match inside "help.wardseal.local"
for host in "${LOCAL_HOSTS[@]}"; do
  if grep -qE "(^|[[:space:]])${host}([[:space:]]|$)" /etc/hosts 2>/dev/null; then
    pass "/etc/hosts already has $host"
  else
    echo "  Adding $host → 127.0.0.1 (requires sudo)"
    echo "127.0.0.1  $host" | sudo tee -a /etc/hosts >/dev/null
    pass "Added $host to /etc/hosts"
  fi
done


# ── Step 11: Status summary ───────────────────────────────────────────────────
section "Deployment Status"
kubectl get pods -n "$NAMESPACE" -o wide
echo ""
echo -e "${GREEN}══ Local deployment complete! ══${NC}"
echo ""
echo "  Landing Site   : http://wardseal.local"
echo "  Auth Service   : http://auth.wardseal.local"
echo "  API Service    : http://api.wardseal.local"
echo "  Console UI     : http://manage.wardseal.local"
echo "  OpenID Config  : http://auth.wardseal.local/t/admin-system/.well-known/openid-configuration"
echo ""
echo "  View logs      : kubectl logs -n $NAMESPACE -l app=wardseal-authsvc -f"
echo "  Helm status    : helm status $RELEASE -n $NAMESPACE"
echo "  Teardown       : ./scripts/destroy_local_k8s.sh"
