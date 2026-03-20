#!/usr/bin/env bash
# Deploy Wardseal Identity Platform to Kubernetes Staging
# This script deploys PostgreSQL (optional) and Wardseal services with Vault integration
set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
NAMESPACE="wardseal-staging"
DB_NAME="identity_platform_staging"
DB_USER="wardseal_staging"
DB_PASSWORD="${DB_PASSWORD:-staging-password-change-me}"
POSTGRES_RELEASE="postgres"
WARDSEAL_RELEASE="wardseal"
VAULT_NAMESPACE="vault-staging"
VAULT_ADDR="${VAULT_ADDR:-http://vault.vault-staging.svc.cluster.local:8200}"
VAULT_KEY_PATH="${VAULT_KEY_PATH:-transit}"
VAULT_KEY_NAME="${VAULT_KEY_NAME:-wardseal-signing-key-staging}"
VAULT_ROLE_ID="${VAULT_ROLE_ID:-}"
VAULT_SECRET_ID="${VAULT_SECRET_ID:-}"
DEFAULT_EXTERNAL_VAULT="no"
if [[ "$VAULT_ADDR" != *"vault.vault-staging.svc.cluster.local"* ]]; then
    DEFAULT_EXTERNAL_VAULT="yes"
fi
USE_EXTERNAL_VAULT="${USE_EXTERNAL_VAULT:-$DEFAULT_EXTERNAL_VAULT}"
DEPLOY_POSTGRES="${DEPLOY_POSTGRES:-yes}"  # Set to 'no' to skip PostgreSQL deployment
EXTERNAL_DB_HOST="${EXTERNAL_DB_HOST:-}"    # Set if using external PostgreSQL

# Paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CHARTS_DIR="$PROJECT_ROOT/deploy/charts"
MIGRATIONS_DIR="$PROJECT_ROOT/migrations"
APPROLE_FILE="/tmp/vault-approle-staging.json"

# Image configuration
IMAGE_TAG="${IMAGE_TAG:-latest}"
IMAGE_REGISTRY="${IMAGE_REGISTRY:-ghcr.io/dhawalhost}"

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
    
    if ! command -v jq &> /dev/null; then
        log_error "jq not found. Please install jq."
        exit 1
    fi
    
    if [ "$USE_EXTERNAL_VAULT" != "yes" ]; then
        # Check if in-cluster Vault is running
        if ! kubectl get namespace "$VAULT_NAMESPACE" &> /dev/null; then
            log_error "Vault namespace not found. Please run setup_vault_staging.sh first."
            exit 1
        fi

        if ! kubectl get pod vault-0 -n "$VAULT_NAMESPACE" &> /dev/null; then
            log_error "Vault pod not found. Please run setup_vault_staging.sh first."
            exit 1
        fi
    else
        log_info "Using external/shared Vault at $VAULT_ADDR"
    fi

    # Check AppRole credentials (environment variables or file)
    if [ -n "$VAULT_ROLE_ID" ] && [ -n "$VAULT_SECRET_ID" ]; then
        log_info "Using Vault AppRole credentials from environment variables"
    elif [ ! -f "$APPROLE_FILE" ]; then
        log_error "Vault AppRole credentials not found"
        log_error "Provide VAULT_ROLE_ID and VAULT_SECRET_ID, or create $APPROLE_FILE"
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
    if [ "$DEPLOY_POSTGRES" != "yes" ]; then
        log_info "Skipping PostgreSQL deployment (DEPLOY_POSTGRES=$DEPLOY_POSTGRES)"
        return 0
    fi
    
    log_info "Deploying PostgreSQL..."
    
    # Check if already deployed
    if kubectl get deployment postgres-staging -n "$NAMESPACE" &> /dev/null; then
        log_warn "PostgreSQL already deployed, skipping..."
        return 0
    fi
    
    # Create PostgreSQL deployment with larger storage for staging
    kubectl apply -n "$NAMESPACE" -f - <<EOF
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: postgres-staging-pvc
  namespace: $NAMESPACE
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 10Gi
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: postgres-staging
  namespace: $NAMESPACE
  labels:
    app: postgres
    environment: staging
spec:
  replicas: 1
  selector:
    matchLabels:
      app: postgres
      environment: staging
  template:
    metadata:
      labels:
        app: postgres
        environment: staging
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
        resources:
          requests:
            memory: 256Mi
            cpu: 100m
          limits:
            memory: 512Mi
            cpu: 500m
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
          claimName: postgres-staging-pvc
---
apiVersion: v1
kind: Service
metadata:
  name: postgres-staging
  namespace: $NAMESPACE
  labels:
    app: postgres
    environment: staging
spec:
  selector:
    app: postgres
    environment: staging
  ports:
  - port: 5432
    targetPort: 5432
  type: ClusterIP
EOF
    
    log_info "PostgreSQL deployment created ✓"
}

# Wait for PostgreSQL to be ready
wait_for_postgres() {
    if [ "$DEPLOY_POSTGRES" != "yes" ]; then
        log_info "Skipping PostgreSQL wait (external database)"
        return 0
    fi
    
    log_info "Waiting for PostgreSQL to be ready..."
    
    kubectl wait --for=condition=Available deployment/postgres-staging \
        -n "$NAMESPACE" \
        --timeout=300s
    
    # Additional wait for database to be fully ready
    sleep 10
    
    log_info "PostgreSQL is ready ✓"
}

# Apply database migrations
apply_migrations() {
    log_info "Applying database migrations..."
    
    # Determine database host
    if [ "$DEPLOY_POSTGRES" = "yes" ]; then
        DB_POD="deployment/postgres-staging"
    elif [ -n "$EXTERNAL_DB_HOST" ]; then
        log_warn "Skipping migrations - external database requires manual migration"
        log_warn "Please run migrations manually against: $EXTERNAL_DB_HOST"
        return 0
    else
        log_error "Cannot apply migrations - no database available"
        return 1
    fi
    
    # Get list of migration files
    MIGRATION_FILES=$(find "$MIGRATIONS_DIR" -name "*.up.sql" | sort)
    
    if [ -z "$MIGRATION_FILES" ]; then
        log_warn "No migration files found in $MIGRATIONS_DIR"
        return 0
    fi
    
    # Apply migrations
    for migration_file in $MIGRATION_FILES; do
        log_info "Applying migration: $(basename "$migration_file")"
        
        # Read migration file content
        MIGRATION_SQL=$(cat "$migration_file")
        
        # Execute migration via kubectl exec
        kubectl exec -n "$NAMESPACE" "$DB_POD" -- \
            psql -U "$DB_USER" -d "$DB_NAME" -c "$MIGRATION_SQL" || true
    done
    
    log_info "Database migrations applied ✓"
}

# Create Kubernetes secrets
create_secrets() {
    log_info "Creating Kubernetes secrets..."
    
    # Determine database host
    if [ "$DEPLOY_POSTGRES" = "yes" ]; then
        DB_HOST="postgres-staging"
    elif [ -n "$EXTERNAL_DB_HOST" ]; then
        DB_HOST="$EXTERNAL_DB_HOST"
    else
        log_error "No database host specified"
        exit 1
    fi
    
    # Create database credentials secret
    kubectl create secret generic wardseal-db-credentials-staging \
        -n "$NAMESPACE" \
        --from-literal=username="$DB_USER" \
        --from-literal=password="$DB_PASSWORD" \
        --from-literal=host="$DB_HOST" \
        --from-literal=port="5432" \
        --from-literal=database="$DB_NAME" \
        --dry-run=client -o yaml | kubectl apply -f -
    
    log_info "Database credentials secret created ✓"
    
    # Generate service auth token
    SERVICE_AUTH_TOKEN="${SERVICE_AUTH_TOKEN:-$(openssl rand -hex 32)}"
    
    # Create service auth secret
    kubectl create secret generic wardseal-service-auth-staging \
        -n "$NAMESPACE" \
        --from-literal=token="$SERVICE_AUTH_TOKEN" \
        --from-literal=header="X-Service-Auth" \
        --dry-run=client -o yaml | kubectl apply -f -
    
    log_info "Service auth secret created ✓"
    
    # Create Vault KMS secret
    ROLE_ID="$VAULT_ROLE_ID"
    SECRET_ID="$VAULT_SECRET_ID"
    if [ -z "$ROLE_ID" ] || [ -z "$SECRET_ID" ]; then
        ROLE_ID=$(jq -r '.role_id' "$APPROLE_FILE")
        SECRET_ID=$(jq -r '.secret_id' "$APPROLE_FILE")
    fi

    if [ -z "$ROLE_ID" ] || [ -z "$SECRET_ID" ] || [ "$ROLE_ID" = "null" ] || [ "$SECRET_ID" = "null" ]; then
        log_error "Vault AppRole credentials are empty. Cannot create wardseal-vault-kms-staging secret."
        exit 1
    fi

    kubectl create secret generic wardseal-vault-kms-staging \
        -n "$NAMESPACE" \
        --from-literal=VAULT_ADDR="$VAULT_ADDR" \
        --from-literal=VAULT_ROLE_ID="$ROLE_ID" \
        --from-literal=VAULT_SECRET_ID="$SECRET_ID" \
        --from-literal=VAULT_KEY_NAME="$VAULT_KEY_NAME" \
        --from-literal=VAULT_KEY_PATH="$VAULT_KEY_PATH" \
        --dry-run=client -o yaml | kubectl apply -f -

    log_info "Vault KMS secret created ✓"
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
    log_info "Deploying Wardseal application to staging..."
    
    # Install or upgrade Wardseal
    if helm status "$WARDSEAL_RELEASE" -n "$NAMESPACE" &> /dev/null; then
        log_warn "Wardseal release already exists. Upgrading..."
        helm upgrade "$WARDSEAL_RELEASE" "$CHARTS_DIR/wardseal" \
            --namespace "$NAMESPACE" \
            --values "$CHARTS_DIR/wardseal/values.yaml" \
            --values "$CHARTS_DIR/wardseal/values-staging.yaml" \
            --set global.imageRegistry="$IMAGE_REGISTRY" \
            --set authsvc.image.tag="$IMAGE_TAG" \
            --set dirsvc.image.tag="$IMAGE_TAG" \
            --set govsvc.image.tag="$IMAGE_TAG" \
            --set policysvc.image.tag="$IMAGE_TAG" \
            --set provsvc.image.tag="$IMAGE_TAG" \
            --set adminui.image.tag="$IMAGE_TAG" \
            --set landingui.image.tag="$IMAGE_TAG" \
            --wait \
            --timeout 5m
    else
        helm install "$WARDSEAL_RELEASE" "$CHARTS_DIR/wardseal" \
            --namespace "$NAMESPACE" \
            --values "$CHARTS_DIR/wardseal/values.yaml" \
            --values "$CHARTS_DIR/wardseal/values-staging.yaml" \
            --set global.imageRegistry="$IMAGE_REGISTRY" \
            --set authsvc.image.tag="$IMAGE_TAG" \
            --set dirsvc.image.tag="$IMAGE_TAG" \
            --set govsvc.image.tag="$IMAGE_TAG" \
            --set policysvc.image.tag="$IMAGE_TAG" \
            --set provsvc.image.tag="$IMAGE_TAG" \
            --set adminui.image.tag="$IMAGE_TAG" \
            --set landingui.image.tag="$IMAGE_TAG" \
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
    
    # Check services
    log_info "Services:"
    kubectl get svc -n "$NAMESPACE"
    
    log_info "Deployment verification complete ✓"
}

# Print access instructions
print_access_info() {
    echo ""
    log_info "=========================================="
    log_info "Wardseal Staging Deployment Complete! ✓"
    log_info "=========================================="
    echo ""
    log_info "Deployed configuration:"
    echo "  - Namespace: $NAMESPACE"
    echo "  - Image tag: $IMAGE_TAG"
    echo "  - Vault address: $VAULT_ADDR"
    echo "  - Database: $DB_NAME"
    echo ""
    
    if kubectl get ingress -n "$NAMESPACE" &> /dev/null; then
        log_info "Access via Ingress:"
        kubectl get ingress -n "$NAMESPACE"
        echo ""
    fi
    
    log_info "To access services locally via port-forward:"
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
    log_info "Next steps:"
    log_info "1. Configure DNS records for ingress hostnames (if using ingress)"
    log_info "2. Set up monitoring and alerting"
    log_info "3. Configure automated backups for database and Vault"
    log_info "4. Deploy via ArgoCD for GitOps management"
    echo ""
}

# Main execution
main() {
    log_info "Starting Wardseal deployment to Kubernetes staging..."
    echo ""
    
    # Display configuration
    echo "Configuration:"
    echo "  - Deploy PostgreSQL: $DEPLOY_POSTGRES"
    echo "  - External DB Host: ${EXTERNAL_DB_HOST:-N/A}"
    echo "  - Use External Vault: $USE_EXTERNAL_VAULT"
    echo "  - Vault Address: $VAULT_ADDR"
    echo "  - Image Tag: $IMAGE_TAG"
    echo "  - Image Registry: $IMAGE_REGISTRY"
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
