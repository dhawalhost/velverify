#!/usr/bin/env bash
# destroy_local_k8s.sh — Tear down the local Wardseal k8s deployment
set -euo pipefail

NAMESPACE="${NAMESPACE:-wardseal-local}"
RELEASE="${RELEASE:-wardseal}"
REMOVE_HOSTS=false
if [[ "${1:-}" == "--remove-hosts" ]]; then
	REMOVE_HOSTS=true
fi

LOCAL_HOSTS=(
	"wardseal.local"
	"auth.wardseal.local"
	"api.wardseal.local"
	"manage.wardseal.local"
)

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
section() { echo -e "\n${BLUE}══ $1 ══${NC}"; }
pass()    { echo -e "${GREEN}✔${NC} $1"; }
warn()    { echo -e "${YELLOW}⚠${NC} $1"; }

for cmd in kubectl helm; do
	command -v "$cmd" >/dev/null 2>&1 || { echo "Missing required command: $cmd"; exit 1; }
done

if ! kubectl cluster-info >/dev/null 2>&1; then
	warn "Kubernetes cluster is not reachable. Attempting best-effort local cleanup only."
fi

section "DANGER ZONE"
warn "This will DELETE the entire $NAMESPACE namespace, including all PERSISTENT DATA (Postgres passwords, users, etc.)."
read -p "Are you sure you want to proceed? (y/N) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Aborting teardown."
    exit 1
fi

section "Removing Helm Release"
helm uninstall "$RELEASE" -n "$NAMESPACE" --ignore-not-found 2>/dev/null && pass "Helm release removed" || warn "Helm release not found"

section "Removing Infra"
kubectl delete -f deploy/k8s-local/migrate-job.yaml -n "$NAMESPACE" --ignore-not-found 2>/dev/null || true
kubectl delete -f deploy/k8s-local/redis.yaml -n "$NAMESPACE" --ignore-not-found 2>/dev/null || true
kubectl delete -f deploy/k8s-local/postgres.yaml -n "$NAMESPACE" --ignore-not-found 2>/dev/null || true
kubectl delete configmap wardseal-migrations-cm -n "$NAMESPACE" --ignore-not-found 2>/dev/null || true
pass "Infra resources removed"

section "Removing Secrets"
kubectl delete secret wardseal-db-credentials wardseal-jwt-keys -n "$NAMESPACE" --ignore-not-found 2>/dev/null || true
pass "Secrets removed"

section "Removing Namespace"
kubectl delete namespace "$NAMESPACE" --ignore-not-found
pass "Namespace $NAMESPACE deleted (PVC data also removed)"

if [[ "$REMOVE_HOSTS" == "true" ]]; then
	section "Removing /etc/hosts entries"
	for host in "${LOCAL_HOSTS[@]}"; do
		if grep -q "$host" /etc/hosts 2>/dev/null; then
			sudo sed -i '' "/[[:space:]]$host$/d" /etc/hosts
			pass "Removed $host from /etc/hosts"
		else
			pass "$host not present in /etc/hosts"
		fi
	done
else
	section "Optional /etc/hosts cleanup"
	echo "  Re-run with --remove-hosts to remove local Wardseal host entries."
fi

echo -e "\n${GREEN}✔ Teardown complete.${NC}"
echo "  Namespace: $NAMESPACE"
echo "  Release:   $RELEASE"
