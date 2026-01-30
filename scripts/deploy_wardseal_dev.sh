#!/usr/bin/env bash
# Deploy Wardseal Identity Platform to Local Kubernetes
# This script deploys PostgreSQL and Wardseal services with Vault integration
set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
NAMESPACE="wardseal-dev"
DB_NAME="identity_platform_dev"
DB_USER="wardseal"
DB_PASSWORD="dev-password"
POSTGRES_RELEASE="postgres"
WARDSEAL_RELEASE="wardseal"
VAULT_NAMESPACE="vault-dev"

# Paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CHARTS_DIR="$PROJECT_ROOT/deploy/charts"
MIGRATIONS_DIR="$PROJECT_ROOT/migrations"
SECRETS_FILE="$PROJECT_ROOT/deploy/argocd/secrets-development.yaml"
APPROLE_FILE="/tmp/vault-approle-dev.json"

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
        log_error "Cannot connect to Kubernetes cluster."
        exit 1
    fi
    
    # Check if Vault is running
    if ! kubectl get namespace "$VAULT_NAMESPACE" &> /dev/null; then
        log_error "Vault namespace not found. Please run setup_vault_dev.sh first."
        exit 1
    fi
    
    if ! kubectl get pod vault-0 -n "$VAULT_NAMESPACE" &> /dev/null; then
        log_error "Vault pod not found. Please run setup_vault_dev.sh first."
        exit 1
    fi
    
    # Check AppRole credentials
    if [ ! -f "$APPROLE_FILE" ]; then
        log_error "Vault AppRole credentials not found at $APPROLE_FILE"
        log_error "Please run setup_vault_dev.sh first or set the credentials manually."
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

# Deploy PostgreSQL
deploy_postgres() {
    log_info "Deploying PostgreSQL..."
    
    # Check if already deployed
    if kubectl get deployment postgres -n "$NAMESPACE" &> /dev/null; then
        log_warn "PostgreSQL already deployed, skipping..."
        return 0
    fi
    
    # Create PostgreSQL deployment
    kubectl apply -n "$NAMESPACE" -f - <<EOF
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: postgres-pvc
  namespace: $NAMESPACE
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 5Gi
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: postgres
  namespace: $NAMESPACE
spec:
  replicas: 1
  selector:
    matchLabels:
      app: postgres
  template:
    metadata:
      labels:
        app: postgres
    spec:
      containers:
      - name: postgres
        image: postgres:14-alpine
        ports:
        - containerPort: 5432
        env:
        - name: POSTGRES_DB
          value: "$DB_NAME"
        - name: POSTGRES_USER
          value: "$DB_USER"
        - name: POSTGRES_PASSWORD
          value: "$DB_PASSWORD"
        volumeMounts:
        - name: postgres-storage
          mountPath: /var/lib/postgresql/data
        livenessProbe:
          exec:
            command:
            - pg_isready
            - -U
            - "$DB_USER"
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          exec:
            command:
            - pg_isready
            - -U
            - "$DB_USER"
          initialDelaySeconds: 5
          periodSeconds: 5
      volumes:
      - name: postgres-storage
        persistentVolumeClaim:
          claimName: postgres-pvc
---
apiVersion: v1
kind: Service
metadata:
  name: postgres
  namespace: $NAMESPACE
spec:
  selector:
    app: postgres
  ports:
  - port: 5432
    targetPort: 5432
  type: ClusterIP
EOF
    
    log_info "PostgreSQL deployment created ✓"
}

# Wait for PostgreSQL to be ready
wait_for_postgres() {
    log_info "Waiting for PostgreSQL to be ready..."
    
    kubectl wait --for=condition=Available deployment/postgres \
        -n "$NAMESPACE" \
        --timeout=300s
    
    # Additional wait for database to be fully ready
    sleep 10
    
    log_info "PostgreSQL is ready ✓"
}

# Apply database migrations
apply_migrations() {
    log_info "Applying database migrations..."
    
    # Get list of migration files
    MIGRATION_FILES=$(find "$MIGRATIONS_DIR" -name "*.up.sql" | sort)
    
    if [ -z "$MIGRATION_FILES" ]; then
        log_warn "No migration files found in $MIGRATIONS_DIR"
        return 0
    fi
    
    # Create a job to run migrations
    for migration_file in $MIGRATION_FILES; do
        log_info "Applying migration: $(basename "$migration_file")"
        
        # Read migration file content
        MIGRATION_SQL=$(cat "$migration_file")
        
        # Execute migration via kubectl exec
        kubectl exec -n "$NAMESPACE" deployment/postgres -- \
            psql -U "$DB_USER" -d "$DB_NAME" -c "$MIGRATION_SQL" || true
    done
    
    log_info "Database migrations applied ✓"
}

# Create Kubernetes secrets
create_secrets() {
    log_info "Creating Kubernetes secrets..."
    
    # Create database credentials secret
    kubectl create secret generic wardseal-db-credentials-dev \
        -n "$NAMESPACE" \
        --from-literal=username="$DB_USER" \
        --from-literal=password="$DB_PASSWORD" \
        --from-literal=host="postgres" \
        --from-literal=port="5432" \
        --from-literal=database="$DB_NAME" \
        --dry-run=client -o yaml | kubectl apply -f -
    
    log_info "Database credentials secret created ✓"
    
    # Create service auth secret
    kubectl create secret generic wardseal-service-auth-dev \
        -n "$NAMESPACE" \
        --from-literal=token="dev-internal-token" \
        --from-literal=header="X-Service-Auth" \
        --dry-run=client -o yaml | kubectl apply -f -
    
    log_info "Service auth secret created ✓"
    
    # Create Vault AppRole secret
    if [ -f "$APPROLE_FILE" ]; then
        ROLE_ID=$(jq -r '.role_id' "$APPROLE_FILE")
        SECRET_ID=$(jq -r '.secret_id' "$APPROLE_FILE")
        
        kubectl create secret generic vault-approle \
            -n "$NAMESPACE" \
            --from-literal=role-id="$ROLE_ID" \
            --from-literal=secret-id="$SECRET_ID" \
            --dry-run=client -o yaml | kubectl apply -f -
        
        log_info "Vault AppRole secret created ✓"
    else
        log_warn "Vault AppRole file not found, skipping..."
    fi
}

# Build Helm chart dependencies
build_helm_dependencies() {
    log_info "Building Helm chart dependencies..."
    
    cd "$CHARTS_DIR/wardseal"
    helm dependency update
    cd "$PROJECT_ROOT"
    
    log_info "Helm dependencies updated ✓"
}

# Deploy Wardseal application
deploy_wardseal() {
    log_info "Deploying Wardseal application..."
    
    # Install or upgrade Wardseal
    if helm status "$WARDSEAL_RELEASE" -n "$NAMESPACE" &> /dev/null; then
        log_warn "Wardseal release already exists. Upgrading..."
        helm upgrade "$WARDSEAL_RELEASE" "$CHARTS_DIR/wardseal" \
            --namespace "$NAMESPACE" \
            --values "$CHARTS_DIR/wardseal/values.yaml" \
            --values "$CHARTS_DIR/wardseal/values-development.yaml" \
            --set kms.provider=vault \
            --set kms.vaultAddr=http://vault.vault-dev.svc.cluster.local:8200 \
            --set authsvc.env.KMS_PROVIDER=vault \
            --set authsvc.env.VAULT_ADDR=http://vault.vault-dev.svc.cluster.local:8200 \
            --set authsvc.env.VAULT_TRANSIT_KEY=jwt-signing \
            --wait \
            --timeout 5m
    else
        helm install "$WARDSEAL_RELEASE" "$CHARTS_DIR/wardseal" \
            --namespace "$NAMESPACE" \
            --values "$CHARTS_DIR/wardseal/values.yaml" \
            --values "$CHARTS_DIR/wardseal/values-development.yaml" \
            --set kms.provider=vault \
            --set kms.vaultAddr=http://vault.vault-dev.svc.cluster.local:8200 \
            --set authsvc.env.KMS_PROVIDER=vault \
            --set authsvc.env.VAULT_ADDR=http://vault.vault-dev.svc.cluster.local:8200 \
            --set authsvc.env.VAULT_TRANSIT_KEY=jwt-signing \
            --wait \
            --timeout 5m
    fi
    
    log_info "Wardseal deployed ✓"
}

# Verify deployment
verify_deployment() {
    log_info "Verifying deployment..."
    
    # Check pods
    kubectl get pods -n "$NAMESPACE"
    
    # Wait for all pods to be ready
    log_info "Waiting for all pods to be ready..."
    kubectl wait --for=condition=Ready pods --all -n "$NAMESPACE" --timeout=300s || true
    
    log_info "Deployment verification complete ✓"
}

# Print access instructions
print_access_info() {
    echo ""
    log_info "=========================================="
    log_info "Wardseal Deployment Complete! ✓"
    log_info "=========================================="
    echo ""
    log_info "To access the services, use port-forward:"
    echo ""
    echo "  # Auth Service"
    echo "  kubectl port-forward -n $NAMESPACE svc/wardseal-authsvc 8080:8080"
    echo ""
    echo "  # Directory Service"
    echo "  kubectl port-forward -n $NAMESPACE svc/wardseal-dirsvc 8081:8081"
    echo ""
    echo "  # Governance Service"
    echo "  kubectl port-forward -n $NAMESPACE svc/wardseal-govsvc 8082:8082"
    echo ""
    log_info "Health check endpoints:"
    echo "  curl http://localhost:8080/health"
    echo "  curl http://localhost:8081/health"
    echo "  curl http://localhost:8082/health"
    echo ""
    log_info "View logs:"
    echo "  kubectl logs -n $NAMESPACE deployment/wardseal-authsvc -f"
    echo "  kubectl logs -n $NAMESPACE deployment/wardseal-dirsvc -f"
    echo "  kubectl logs -n $NAMESPACE deployment/wardseal-govsvc -f"
    echo ""
}

# Main execution
main() {
    log_info "Starting Wardseal deployment to local Kubernetes..."
    echo ""
    
    check_prerequisites
    create_namespace
    deploy_postgres
    wait_for_postgres
    apply_migrations
    create_secrets
    build_helm_dependencies
    deploy_wardseal
    verify_deployment
    print_access_info
}

# Run main function
main "$@"
