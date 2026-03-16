#!/usr/bin/env bash
set -euo pipefail

# Syncs local umbrella chart dependencies and packaged sub-charts.
# Usage:
#   bash scripts/sync_helm_charts.sh [chart_dir]
# Example:
#   bash scripts/sync_helm_charts.sh deploy/charts/wardseal

CHART_DIR="${1:-deploy/charts/wardseal}"
CHART_FILE="$CHART_DIR/Chart.yaml"
CHARTS_DIR="$CHART_DIR/charts"

if [[ ! -f "$CHART_FILE" ]]; then
  echo "[sync-helm] Chart.yaml not found at: $CHART_FILE" >&2
  exit 1
fi

if ! command -v helm >/dev/null 2>&1; then
  echo "[sync-helm] helm is required" >&2
  exit 1
fi

mkdir -p "$CHARTS_DIR"

echo "[sync-helm] chart: $CHART_DIR"

# Extract local file dependencies from umbrella Chart.yaml
# Example repository entry: repository: "file://../authsvc"
local_deps=()
while IFS= read -r dep; do
  [[ -n "$dep" ]] && local_deps+=("$dep")
done < <(
  grep -E 'repository:\s*"?file://\.\./[^" ]+"?' "$CHART_FILE" \
    | sed -E 's/.*file:\/\/\.\.\/([^" ]+).*/\1/'
)

if [[ ${#local_deps[@]} -eq 0 ]]; then
  echo "[sync-helm] no local file dependencies found in $CHART_FILE"
else
  echo "[sync-helm] local deps: ${local_deps[*]}"
fi

# Clean old packaged charts to avoid stale tarballs
rm -f "$CHARTS_DIR"/*.tgz

# Package local dependency charts
for dep in "${local_deps[@]}"; do
  dep_dir="$(dirname "$CHART_DIR")/$dep"
  if [[ ! -d "$dep_dir" ]]; then
    echo "[sync-helm] missing dependency chart directory: $dep_dir" >&2
    exit 1
  fi

  echo "[sync-helm] packaging $dep"
  helm package "$dep_dir" -d "$CHARTS_DIR" >/dev/null

done

# Refresh lock file and dependency metadata
# `helm dependency update` updates Chart.lock when dependencies changed.
echo "[sync-helm] updating dependencies and Chart.lock"
helm dependency update "$CHART_DIR" >/dev/null

# Build once more to verify lock/deps consistency.
echo "[sync-helm] verifying dependency build"
helm dependency build "$CHART_DIR" >/dev/null

echo "[sync-helm] done"
