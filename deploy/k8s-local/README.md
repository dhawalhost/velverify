# Local Kubernetes Deployment — Rancher Desktop

Deploy the full Wardseal stack locally on Rancher Desktop to test Helm charts, ingress routing, and service-to-service communication before pushing to staging or production.

> **Why local k8s instead of `docker-compose`?**
> `docker-compose` is great for fast iteration on individual services. Local k8s gives you a production-faithful environment: real Helm chart, real Traefik ingress, Secrets, init containers, and migration Jobs — so you catch deployment anomalies before they hit staging.

## Prerequisites

| Tool | Install | Notes |
|------|---------|-------|
| [Rancher Desktop](https://rancherdesktop.io) | Download | Enable Kubernetes; use `containerd` or `dockerd` runtime |
| `kubectl` | ships with Rancher Desktop | |
| `helm` | `brew install helm` | v3+ |
| `docker` | ships with Rancher Desktop | needed for image builds |

```bash
# Verify
kubectl version --short
helm version --short
kubectl config current-context   # should print: rancher-desktop
```

## Quickstart

```bash
# From repo root — does everything end-to-end
./scripts/deploy_local_k8s.sh
```

## What the Script Does

1. **Build images** — builds `wardseal-authsvc:local`, `wardseal-dirsvc:local`, `wardseal-govsvc:local` from local source
2. **Import images** — if containerd runtime, loads them into the `k8s.io` namespace so k3s can pull with `pullPolicy: Never`
3. **Create namespace** — `wardseal-local`
4. **Create Secrets** — `wardseal-db-credentials` and `wardseal-jwt-keys` (from `deploy/dev-keys/`)
5. **Deploy Postgres + Redis** — in-cluster single-replica via `k8s-local/postgres.yaml` and `k8s-local/redis.yaml`
6. **Run Migrations** — mounts `migrations/*.up.sql` as a ConfigMap, then a `Job` applies them in order
7. **Helm deploy** — `helm upgrade --install` using `values.yaml` + `values-local.yaml`
8. **`/etc/hosts`** — adds `auth.wardseal.local` and `api.wardseal.local → 127.0.0.1` (one-time sudo prompt)

## Files

```
deploy/
  charts/wardseal/
    values-local.yaml               # Local overrides (HTTP, Never pull, single replicas)
  k8s-local/
    postgres.yaml                   # Postgres Deployment + Service + PVC
    redis.yaml                      # Redis Deployment + Service
    migrate-job.yaml                # Migration batch Job
    README.md                       # This file
scripts/
  deploy_local_k8s.sh               # Full deploy automation
  destroy_local_k8s.sh              # Teardown
```

## Environment Variables (deploy_local_k8s.sh)

| Variable | Default | Description |
|----------|---------|-------------|
| `NAMESPACE` | `wardseal-local` | k8s namespace |
| `RELEASE` | `wardseal` | Helm release name |
| `DB_USER` | `user` | Postgres username |
| `DB_PASS` | `password` | Postgres password |

```bash
# Example with custom credentials
DB_USER=admin DB_PASS=secret ./scripts/deploy_local_k8s.sh
```

## Accessing Services After Deploy

| Endpoint | URL |
|----------|-----|
| Auth Service | http://auth.wardseal.local |
| OpenID Configuration | http://auth.wardseal.local/t/admin-system/.well-known/openid-configuration |
| Directory API | http://api.wardseal.local/api/v1/users |
| Governance API | http://api.wardseal.local/api/v1/governance |

> Traefik in k3s/Rancher Desktop listens on port 80 (HTTP). `values-local.yaml` uses the `web` entrypoint — no TLS setup needed locally.

## Useful Commands

```bash
