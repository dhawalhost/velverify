#!/bin/bash
set -e

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

CLUSTER_NAME="wardseal-local"
NAMESPACE="wardseal-dev"
REGISTRY_PREFIX="ghcr.io/dhawalhost"
SERVICES="authsvc dirsvc govsvc policysvc provsvc"

echo -e "${GREEN}Starting Local Development Setup (Kubernetes/Kind)...${NC}"
echo -e "${BLUE}Note: This setup does NOT use Vault. Auth service uses local ephemeral keys.${NC}"

# Check requirements
if ! command -v kind &> /dev/null; then
    echo "Error: kind is not installed."
    echo "Install it: brew install kind"
    exit 1
fi

if ! command -v kubectl &> /dev/null; then
    echo "Error: kubectl is not installed."
    exit 1
fi

if ! command -v helm &> /dev/null; then
    echo "Error: helm is not installed."
    exit 1
fi

# Create Cluster if not exists
if ! kind get clusters | grep -q "^$CLUSTER_NAME$"; then
    echo -e "${BLUE}Creating Kind cluster '$CLUSTER_NAME'...${NC}"
    kind create cluster --name $CLUSTER_NAME
else
    echo -e "${BLUE}Cluster '$CLUSTER_NAME' already exists.${NC}"
fi

# Ensure kubectl context is set
kubectl cluster-info --context kind-$CLUSTER_NAME

# Build Images
echo -e "${GREEN}Building Docker Images...${NC}"
make build-images

# Load Images into Kind
echo -e "${GREEN}Loading Images into Kind...${NC}"
for svc in $SERVICES; do
    echo "Loading $svc..."
    kind load docker-image $REGISTRY_PREFIX/$svc:latest --name $CLUSTER_NAME || echo "Image $svc not found, skipping"
done
# Admin UI image
echo "Loading admin-ui..."
kind load docker-image $REGISTRY_PREFIX/admin-ui:latest --name $CLUSTER_NAME || echo "admin-ui not found"

# Create namespace
echo -e "${GREEN}Creating namespace...${NC}"
kubectl create namespace $NAMESPACE --dry-run=client -o yaml | kubectl apply -f -

# Deploy PostgreSQL inline
echo -e "${GREEN}Deploying PostgreSQL...${NC}"
kubectl apply -n $NAMESPACE -f - <<EOF
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: postgres-pvc
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 1Gi
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: postgres
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
          value: "identity_platform"
        - name: POSTGRES_USER
          value: "user"
        - name: POSTGRES_PASSWORD
          value: "password"
        volumeMounts:
        - name: postgres-storage
          mountPath: /var/lib/postgresql/data
      volumes:
      - name: postgres-storage
        persistentVolumeClaim:
          claimName: postgres-pvc
---
apiVersion: v1
kind: Service
metadata:
  name: postgres
spec:
  selector:
    app: postgres
  ports:
  - port: 5432
    targetPort: 5432
EOF

echo "Waiting for PostgreSQL to be ready..."
kubectl wait --for=condition=Available deployment/postgres -n $NAMESPACE --timeout=120s

# Deploy WardSeal using Helm (without Vault)
echo -e "${GREEN}Deploying WardSeal (No Vault)...${NC}"
cd deploy/charts/wardseal
helm dependency update
cd ../../..

helm upgrade --install wardseal deploy/charts/wardseal \
  --namespace $NAMESPACE \
  --values deploy/charts/wardseal/values.yaml \
  --values deploy/charts/wardseal/values-development.yaml \
  --set kms.provider=local \
  --set authsvc.env.KMS_PROVIDER=local \
  --wait \
  --timeout 10m

echo -e "${GREEN}Setup Complete!${NC}"
echo "================================================"
echo "Use 'kubectl get pods -n $NAMESPACE' to check status."
echo ""
echo "Port forward examples:"
echo "  kubectl port-forward -n $NAMESPACE svc/wardseal-authsvc 8080:8080"
echo "  kubectl port-forward -n $NAMESPACE svc/wardseal-dirsvc 8081:8081"
echo "================================================"
