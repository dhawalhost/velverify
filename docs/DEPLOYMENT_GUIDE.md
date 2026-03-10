# WardSeal Deployment Guide

Complete step-by-step guide for deploying WardSeal Identity Platform.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Quick Start (Local Development)](#quick-start-local-development)
3. [Docker Compose Deployment](#docker-compose-deployment)
4. [Kubernetes Deployment](#kubernetes-deployment)
5. [ArgoCD GitOps Deployment](#argocd-gitops-deployment)
6. [Production Checklist](#production-checklist)
7. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### Software Requirements

| Component | Version | Purpose |
|-----------|---------|---------|
| Go | 1.21+ | Building services |
| Node.js | 18+ | Building admin UI |
| Docker | 24+ | Container runtime |
| kubectl | 1.28+ | Kubernetes CLI |
| Helm | 3.12+ | Kubernetes package manager |
| PostgreSQL | 14+ | Database |

### Infrastructure Requirements

| Environment | Resources |
|-------------|-----------|
| Development | 4 CPU, 8GB RAM |
| Staging | 8 CPU, 16GB RAM |
| Production | 16+ CPU, 32GB+ RAM, HA setup |

---

## Quick Start (Local Development)

### Step 1: Clone Repository

```bash
git clone https://github.com/dhawalhost/wardseal.git
cd wardseal
```

### Step 2: Start Database

```bash
docker run -d --name wardseal-postgres \
  -e POSTGRES_USER=user \
  -e POSTGRES_PASSWORD=password \
  -e POSTGRES_DB=identity_platform \
  -p 5432:5432 \
  postgres:14-alpine
```

### Step 3: Run Migrations

```bash
export DB_HOST=localhost
export DB_USER=user
export DB_PASSWORD=password
go run cmd/migrate_patch/main.go
```

### Step 4: Start Services

```bash
# Terminal 1 - Directory Service
go run cmd/dirsvc/main.go

# Terminal 2 - Auth Service
go run cmd/authsvc/main.go

# Terminal 3 - Governance Service
go run cmd/govsvc/main.go
```

### Step 5: Start Admin UI

```bash
cd web/admin
npm install
npm run dev
```

Access the platform:
- **Admin UI**: http://localhost:5173
- **Auth Service**: http://localhost:8080
- **Directory Service**: http://localhost:8081
- **Governance Service**: http://localhost:8082

---

## Docker Compose Deployment

### Step 1: Build and Start All Services

```bash
# Build and start all services
docker compose up -d --build

# View logs
docker compose logs -f
```

### Step 2: Verify Services

```bash
# Check service health
docker compose ps

# Test auth service
curl http://localhost:8080/health

# Test governance service
curl http://localhost:8082/health
```

### Step 3: Access Services

| Service | URL |
|---------|-----|
| Admin UI | http://localhost:5173 |
| Auth API | http://localhost:8080 |
| Directory API | http://localhost:8081 |
| Governance API | http://localhost:8082 |
| Metrics | http://localhost:8080/metrics |

### Step 4: Stop Services

```bash
docker compose down

# To remove volumes (database data)
docker compose down -v
```

---

## Kubernetes Deployment

### Step 1: Prepare Cluster

```bash
# Create namespace
kubectl create namespace wardseal

# Verify access
kubectl get nodes
```

### Step 2: Generate Secrets

```bash
# Run the secrets setup script
chmod +x scripts/setup-secrets.sh
./scripts/setup-secrets.sh -n wardseal -e staging
```

This creates:
- `wardseal-db-credentials-staging` - Database credentials
- `wardseal-service-auth-staging` - Service-to-service auth
- `wardseal-jwt-keys-staging` - JWT signing keys
- `wardseal-webhook-secret-staging` - Webhook secrets

### Step 3: Install with Helm

```bash
# Add Helm dependencies
cd deploy/charts/wardseal
helm dependency update

# Install for staging
helm install wardseal . \
  --namespace wardseal \
  --values values.yaml \
  --values values-staging.yaml

# Install for production
helm install wardseal . \
  --namespace wardseal-prod \
  --values values.yaml \
  --values values-production.yaml
```

### Step 4: Verify Deployment

```bash
# Check pods
kubectl get pods -n wardseal

# Check services
kubectl get svc -n wardseal

# Check ingress
kubectl get ingress -n wardseal

# View logs
kubectl logs -f deployment/wardseal-authsvc -n wardseal
```

### Step 5: Configure DNS

Point your domains to the Ingress controller:
- `auth.wardseal.com` → Auth Service
- `api.wardseal.com` → API Services

### Step 6: Upgrade or Rollback

```bash
# Upgrade with new values
helm upgrade wardseal . \
  --namespace wardseal \
  --values values.yaml \
  --values values-staging.yaml

# Rollback to previous version
helm rollback wardseal 1 -n wardseal
```

---

## ArgoCD GitOps Deployment

### Step 1: Install ArgoCD (if not installed)

```bash
kubectl create namespace argocd
kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml

# Wait for ArgoCD to be ready
kubectl wait --for=condition=Ready pods --all -n argocd --timeout=300s

# Get initial admin password
kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" | base64 -d
```

### Step 2: Access ArgoCD UI

```bash
# Port forward
kubectl port-forward svc/argocd-server -n argocd 8443:443

# Open https://localhost:8443
# Login with admin / <password from step 1>
```

### Step 3: Create Secrets (Manual Step)

Before deploying, create the required secrets:

```bash
./scripts/setup-secrets.sh -n wardseal -e staging
```

### Step 4: Apply ArgoCD Application

```bash
# For staging
kubectl apply -f deploy/argocd/application.yaml

# For production - edit application.yaml first
# Change values-staging.yaml to values-production.yaml
kubectl apply -f deploy/argocd/application.yaml
```

### Step 5: Verify in ArgoCD

1. Open ArgoCD UI
2. Find the `wardseal` application
3. Click "Sync" if not auto-syncing
4. Verify all resources are healthy (green)

### Step 6: GitOps Workflow

After initial setup, deploy by pushing to git:

```bash
# Make changes to values files or charts
git add deploy/charts/
git commit -m "chore: update wardseal deployment"
git push origin main

# ArgoCD will automatically detect and sync changes
```

---

## Production Checklist

### Security

- [ ] **TLS Certificates**: Configure cert-manager or upload certs
- [ ] **Secrets Management**: Use external secrets operator or vault
- [ ] **Network Policies**: Restrict pod-to-pod communication
- [ ] **RBAC**: Configure Kubernetes RBAC for operators
- [ ] **Pod Security**: Enable PodSecurityPolicies/Standards

### Database

- [ ] **Use managed PostgreSQL**: AWS RDS, GCP Cloud SQL, etc.
- [ ] **Enable SSL**: Set `DB_SSLMODE=require`
- [ ] **Configure backups**: Daily automated backups
- [ ] **Connection pooling**: Use PgBouncer for high traffic

### High Availability

- [ ] **Multiple replicas**: Set `replicaCount: 3+`
- [ ] **Pod anti-affinity**: Distribute across nodes
- [ ] **Autoscaling**: Enable HPA for all services
- [ ] **Multi-zone deployment**: Spread across availability zones

### Monitoring

- [ ] **Prometheus**: Scrape `/metrics` endpoints
- [ ] **Grafana dashboards**: Import WardSeal dashboards
- [ ] **Alerting**: Configure alerts for error rates
- [ ] **Logging**: Ship logs to Elasticsearch/Loki

### Configuration

```yaml
# values-production.yaml minimum settings
global:
  imageRegistry: ghcr.io/dhawalhost

authsvc:
  replicaCount: 3
  autoscaling:
    enabled: true
    minReplicas: 3
    maxReplicas: 10

dirsvc:
  replicaCount: 3
  autoscaling:
    enabled: true

govsvc:
  replicaCount: 3
  autoscaling:
    enabled: true

database:
  sslMode: require
  host: your-rds-endpoint.amazonaws.com

ingress:
  enabled: true
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
  tls:
    - secretName: wardseal-tls
      hosts:
        - auth.wardseal.com
        - api.wardseal.com
```

---

## Troubleshooting

### Common Issues

#### Pods not starting

```bash
# Check pod events
kubectl describe pod <pod-name> -n wardseal

# Check logs
kubectl logs <pod-name> -n wardseal --previous
```

#### Database connection failures

```bash
# Verify secret
kubectl get secret wardseal-db-credentials-staging -n wardseal -o yaml

# Test connectivity from pod
kubectl exec -it <pod-name> -n wardseal -- nc -zv postgres 5432
```

#### Ingress not working

```bash
# Check ingress controller
kubectl get pods -n ingress-nginx

# Check ingress resource
kubectl describe ingress wardseal -n wardseal

# Check TLS certificate
kubectl get certificate -n wardseal
```

#### ArgoCD sync failures

```bash
# Check application status
argocd app get wardseal

# Force sync
argocd app sync wardseal --force

# Check diff
argocd app diff wardseal
```

### Useful Commands

```bash
# Restart all pods
kubectl rollout restart deployment -n wardseal

# Scale up/down
kubectl scale deployment wardseal-authsvc --replicas=5 -n wardseal

# Port forward for debugging
kubectl port-forward svc/wardseal-authsvc 8080:8080 -n wardseal

# Get all resources
kubectl get all -n wardseal

# Delete and reinstall
helm uninstall wardseal -n wardseal
helm install wardseal deploy/charts/wardseal -n wardseal
```

### Health Check Endpoints

| Service | Endpoint | Expected |
|---------|----------|----------|
| authsvc | `/health` | 200 OK |
| dirsvc | `/health` | 200 OK |
| govsvc | `/health` | 200 OK |
| Metrics | `/metrics` | Prometheus format |

---

## Support

- **Documentation**: [docs/README.md](README.md)
- **Issues**: https://github.com/dhawalhost/wardseal/issues
- **Security**: security@wardseal.com
