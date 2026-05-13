#!/usr/bin/env bash
# run_benchmarks.sh
# 
# This script automates the process of running baseline (1 replica) vs scaled (N replicas)
# benchmarks using k6 against the WardSeal platform deployed in Kubernetes.
#
# Prerequisite: A local or remote Kubernetes cluster with WardSeal deployed, and k6 installed.

set -e

# Configuration
K6_SCRIPT="tests/load/k6/comprehensive_auth_flow.js"
SERVICES=("authsvc" "dirsvc" "govsvc")
NAMESPACE="default" # Update if WardSeal is deployed in a different namespace
VUS=50              # Number of virtual users
DURATION="1m"       # Duration of the load test
SCALED_REPLICAS=3   # Number of replicas for the scaled test

echo "=================================================="
echo " Starting WardSeal Benchmarks"
echo "=================================================="

# Function to scale services and wait for them to be ready
scale_services() {
  local replicas=$1
  echo "Scaling services to $replicas replica(s)..."
  
  for svc in "${SERVICES[@]}"; do
    kubectl scale deployment "$svc" --replicas="$replicas" -n "$NAMESPACE"
  done

  echo "Waiting for pods to be ready..."
  for svc in "${SERVICES[@]}"; do
    kubectl rollout status deployment "$svc" -n "$NAMESPACE"
  done
  
  echo "Services scaled successfully."
}

# 1. Run Baseline (Single Replica)
echo ""
echo "--- Phase 1: Baseline Test (1 Replica) ---"
scale_services 1

echo "Warming up..."
sleep 10

echo "Running k6 baseline benchmark..."
k6 run --vus "$VUS" --duration "$DURATION" --out json=baseline_results.json "$K6_SCRIPT"

# 2. Run Scaled (N Replicas)
echo ""
echo "--- Phase 2: Scaled Test ($SCALED_REPLICAS Replicas) ---"
scale_services "$SCALED_REPLICAS"

echo "Warming up..."
sleep 10

echo "Running k6 scaled benchmark..."
k6 run --vus "$VUS" --duration "$DURATION" --out json=scaled_results.json "$K6_SCRIPT"

echo ""
echo "=================================================="
echo " Benchmarks Complete!"
echo " Results saved to:"
echo " - baseline_results.json"
echo " - scaled_results.json"
echo "=================================================="
