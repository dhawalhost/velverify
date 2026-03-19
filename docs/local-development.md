# Local Development Guide

WardSeal supports two primary ways to run the full stack locally: **Docker Compose** (recommended for speed) and **Kubernetes/Kind** (recommended for verification).

> [!NOTE]
> **No Vault Required**: Local development uses ephemeral local signing keys. This simplifies setup. Vault is only used in staging/production.

## Option 1: Docker Compose (Fastest)

This method runs all services, the database, the public landing/help site, and the Admin Console in Docker containers behind local host-based routing.

### Kubernetes prerequisites

* Docker & Docker Compose

### Kubernetes start

```bash
./scripts/setup_docker_dev.sh
```

This will:

1. Start Postgres and Redis.
2. Run database migrations.
3. Build and start all microservices sequentially.
4. Start Traefik, the landing site, and the Admin Console.

Add this line to `/etc/hosts`:

```text
127.0.0.1 wardseal.local help.wardseal.local manage.wardseal.local auth.wardseal.local api.wardseal.local
```

Then access:

* Admin Console: <http://manage.wardseal.local>
* Landing Site: <http://wardseal.local>
* Help Portal: <http://help.wardseal.local>

> [!IMPORTANT]
> `UI_URL` must point to the Admin Console origin (for example `http://manage.wardseal.local`), not the auth API host. Auth flows use this value for redirects to `/login` and password setup links.

### Stop

```bash
docker compose down
```

## Option 2: Local Kubernetes (Kind)

This method deploys the stack to a local Kubernetes cluster using Helm.

### Prerequisites

* Docker
* Kind (`brew install kind`)
* Kubectl (`brew install kubectl`)
* Helm (`brew install helm`)

### Start

```bash
./scripts/setup_k8s_local.sh
```

### Access

Port-forward to access services:

```bash
kubectl port-forward -n wardseal-dev svc/wardseal-authsvc 8080:8080
```
