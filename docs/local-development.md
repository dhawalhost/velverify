# Local Development Guide

WardSeal supports two primary ways to run the full stack locally: **Docker Compose** (recommended for speed) and **Kubernetes/Kind** (recommended for verification).

> [!NOTE]
> **No Vault Required**: Local development uses ephemeral local signing keys. This simplifies setup. Vault is only used in staging/production.

## Option 1: Docker Compose (Fastest)

This method runs all services, the database, and the Admin UI in Docker containers.

### Prerequisites
*   Docker & Docker Compose

### Start
```bash
./scripts/setup_docker_dev.sh
```

This will:
1.  Start Postgres and Redis.
2.  Run database migrations.
3.  Build and start all microservices sequentially.
4.  Start the Admin UI.

Access `http://localhost:5173` for the Admin Console.

### Stop
```bash
docker compose down
```

## Option 2: Local Kubernetes (Kind)

This method deploys the stack to a local Kubernetes cluster using Helm.

### Prerequisites
*   Docker
*   Kind (`brew install kind`)
*   Kubectl (`brew install kubectl`)
*   Helm (`brew install helm`)

### Start
```bash
./scripts/setup_k8s_local.sh
```

### Access
Port-forward to access services:
```bash
kubectl port-forward -n wardseal-dev svc/wardseal-authsvc 8080:8080
```
