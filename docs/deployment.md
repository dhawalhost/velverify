# Deployment Guide

Deploy WardSeal to production environments.

## Prerequisites

- PostgreSQL 14+
- Go 1.21+ (for building)
- Docker (optional, for containerized deployment)
- TLS certificates

---

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ENVIRONMENT` | ✓ | development | Set to `production` |
| `DB_HOST` | ✓ | localhost | PostgreSQL host |
| `DB_PORT` | | 5432 | PostgreSQL port |
| `DB_USER` | ✓ | user | Database user |
| `DB_PASSWORD` | ✓ | | Database password |
| `DB_NAME` | ✓ | identity_platform | Database name |
| `JWT_PRIVATE_KEY_PATH` | ✓ | | Path to RSA private key |
| `JWT_PUBLIC_KEY_PATH` | ✓ | | Path to RSA public key |
| `CORS_ALLOWED_ORIGINS` | | * | Comma-separated origins |

---

## Build

### Build Binaries

```bash
# Build all services
go build -o bin/authsvc ./cmd/authsvc
go build -o bin/dirsvc ./cmd/dirsvc
go build -o bin/govsvc ./cmd/govsvc

# Build frontend
cd web/admin && npm install && npm run build
```

### Build Docker Images

```dockerfile
# Dockerfile.authsvc
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY . .
RUN go build -o authsvc ./cmd/authsvc

FROM alpine:3.18
COPY --from=builder /app/authsvc /usr/local/bin/
EXPOSE 8080
CMD ["authsvc"]
```

```bash
docker build -f Dockerfile.authsvc -t wardseal/authsvc:latest .
```

---

## Database Setup

### 1. Create Database

```sql
CREATE DATABASE identity_platform;
CREATE USER wardseal WITH PASSWORD 'secure_password';
GRANT ALL PRIVILEGES ON DATABASE identity_platform TO wardseal;
```

### 2. Run Migrations

```bash
export DB_HOST=your-db-host
export DB_PASSWORD=secure_password
go run cmd/migrate_patch/main.go
```

---

## Generate Keys

### RSA Keys for JWT

```bash
# Generate private key
openssl genrsa -out private.pem 2048

# Extract public key
openssl rsa -in private.pem -pubout -out public.pem
```

Set paths in environment:
```bash
export JWT_PRIVATE_KEY_PATH=/etc/wardseal/private.pem
export JWT_PUBLIC_KEY_PATH=/etc/wardseal/public.pem
```

---

## Nginx Configuration

```nginx
upstream authsvc {
    server 127.0.0.1:8080;
}

upstream dirsvc {
    server 127.0.0.1:8081;
}

upstream govsvc {
    server 127.0.0.1:8082;
}

server {
    listen 443 ssl http2;
    server_name auth.wardseal.com;
    
    ssl_certificate /etc/ssl/cert.pem;
    ssl_certificate_key /etc/ssl/key.pem;
    
    # Auth endpoints
    location / {
        proxy_pass http://authsvc;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
    
    # SCIM endpoints
    location /scim {
        proxy_pass http://dirsvc;
    }
    
    # Governance endpoints  
    location /api/v1/organizations {
        proxy_pass http://govsvc;
    }
    
    location /api/v1/roles {
        proxy_pass http://govsvc;
    }
    
    location /api/v1/audit-logs {
        proxy_pass http://govsvc;
    }
}
```

---

## Systemd Services

```ini
# /etc/systemd/system/wardseal-auth.service
[Unit]
Description=WardSeal Auth Service
After=network.target postgresql.service

[Service]
Type=simple
User=wardseal
Environment=ENVIRONMENT=production
Environment=DB_HOST=localhost
EnvironmentFile=/etc/wardseal/env
ExecStart=/usr/local/bin/authsvc
Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable wardseal-auth
sudo systemctl start wardseal-auth
```

---

## Docker Compose (Production)

```yaml
version: '3.8'

services:
  postgres:
    image: postgres:14
    environment:
      POSTGRES_USER: wardseal
      POSTGRES_PASSWORD: ${DB_PASSWORD}
      POSTGRES_DB: identity_platform
    volumes:
      - pg_data:/var/lib/postgresql/data
    restart: always

  authsvc:
    image: wardseal/authsvc:latest
    environment:
      - ENVIRONMENT=production
      - DB_HOST=postgres
      - DB_PASSWORD=${DB_PASSWORD}
    depends_on:
      - postgres
    restart: always

  dirsvc:
    image: wardseal/dirsvc:latest
    environment:
      - ENVIRONMENT=production
      - DB_HOST=postgres
    depends_on:
      - postgres
    restart: always

  govsvc:
    image: wardseal/govsvc:latest
    environment:
      - ENVIRONMENT=production
      - DB_HOST=postgres
    depends_on:
      - postgres
    restart: always

  nginx:
    image: nginx:alpine
    ports:
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./certs:/etc/ssl
    depends_on:
      - authsvc
      - dirsvc
      - govsvc
    restart: always

volumes:
  pg_data:
```

---

## Health Checks

Each service exposes `/metrics` for Prometheus:

```bash
curl http://localhost:8080/metrics
```

---

## Traefik Preflight Check

Run this before first Helm deployment to verify cluster connectivity, Traefik ingress class, cert issuer, and rendered ingress paths:

```bash
NAMESPACE=wardseal \
RELEASE_NAME=wardseal \
ENV_VALUES=deploy/charts/wardseal/values-staging.yaml \
./scripts/preflight_traefik.sh
```

Optionally include `CERT_ISSUER=<your-clusterissuer-name>` if cert-manager is installed and you want issuer validation.

For cert-manager-enabled staging:

```bash
NAMESPACE=wardseal \
RELEASE_NAME=wardseal \
ENV_VALUES=deploy/charts/wardseal/values-staging.yaml \
CERT_ISSUER=letsencrypt-staging \
./scripts/preflight_traefik.sh
```

Helm values split for TLS mode:

- Without cert-manager: use `values-staging.yaml` (staging) or `values-production.yaml` (production)
- With cert-manager: add `values-staging-certmanager.yaml` (staging) or `values-production-certmanager.yaml` (production)

---

## Distributed Rate-Limit Tuning Runbook

The platform uses Redis-backed distributed rate limiting with endpoint-aware buckets (`login`, `token`, `setup`, `webhook`) and a strict degraded fallback when Redis is unavailable.

### 1) Set baseline profile (production)

```bash
export RATE_LIMIT_USE_TENANT=true
export RATE_LIMIT_KEY_PREFIX=wardseal:ratelimit
export RATE_LIMIT_LOGIN_REQUESTS=60
export RATE_LIMIT_TOKEN_REQUESTS=240
export RATE_LIMIT_SETUP_REQUESTS=30
export RATE_LIMIT_WEBHOOK_REQUESTS=600
export RATE_LIMIT_DEFAULT_REQUESTS=1200
export RATE_LIMIT_DEGRADED_REQUESTS=30
```

### 1.1) Copy-paste profiles by environment

Use these blocks as starting points and adjust after load/abuse testing.

#### Development (high throughput, low friction)

```bash
export REDIS_ADDR=localhost:6379
export REDIS_DB=0
export WEBAUTHN_SESSION_TTL_SECONDS=600

export RATE_LIMIT_USE_TENANT=true
export RATE_LIMIT_KEY_PREFIX=wardseal:ratelimit:dev
export RATE_LIMIT_DEFAULT_REQUESTS=2400
export RATE_LIMIT_DEFAULT_WINDOW_SECONDS=60
export RATE_LIMIT_LOGIN_REQUESTS=120
export RATE_LIMIT_LOGIN_WINDOW_SECONDS=60
export RATE_LIMIT_TOKEN_REQUESTS=600
export RATE_LIMIT_TOKEN_WINDOW_SECONDS=60
export RATE_LIMIT_SETUP_REQUESTS=60
export RATE_LIMIT_SETUP_WINDOW_SECONDS=60
export RATE_LIMIT_WEBHOOK_REQUESTS=1200
export RATE_LIMIT_WEBHOOK_WINDOW_SECONDS=60
export RATE_LIMIT_DEGRADED_REQUESTS=60
export RATE_LIMIT_DEGRADED_WINDOW_SECONDS=60
```

#### Staging (pre-prod safety checks)

```bash
export REDIS_ADDR=redis.staging.svc.cluster.local:6379
export REDIS_DB=0
export WEBAUTHN_SESSION_TTL_SECONDS=600

export RATE_LIMIT_USE_TENANT=true
export RATE_LIMIT_KEY_PREFIX=wardseal:ratelimit:staging
export RATE_LIMIT_DEFAULT_REQUESTS=1600
export RATE_LIMIT_DEFAULT_WINDOW_SECONDS=60
export RATE_LIMIT_LOGIN_REQUESTS=80
export RATE_LIMIT_LOGIN_WINDOW_SECONDS=60
export RATE_LIMIT_TOKEN_REQUESTS=360
export RATE_LIMIT_TOKEN_WINDOW_SECONDS=60
export RATE_LIMIT_SETUP_REQUESTS=45
export RATE_LIMIT_SETUP_WINDOW_SECONDS=60
export RATE_LIMIT_WEBHOOK_REQUESTS=800
export RATE_LIMIT_WEBHOOK_WINDOW_SECONDS=60
export RATE_LIMIT_DEGRADED_REQUESTS=40
export RATE_LIMIT_DEGRADED_WINDOW_SECONDS=60
```

#### Production (conservative initial rollout)

```bash
export REDIS_ADDR=redis.prod.svc.cluster.local:6379
export REDIS_DB=0
export WEBAUTHN_SESSION_TTL_SECONDS=600

export RATE_LIMIT_USE_TENANT=true
export RATE_LIMIT_KEY_PREFIX=wardseal:ratelimit:prod
export RATE_LIMIT_DEFAULT_REQUESTS=1200
export RATE_LIMIT_DEFAULT_WINDOW_SECONDS=60
export RATE_LIMIT_LOGIN_REQUESTS=60
export RATE_LIMIT_LOGIN_WINDOW_SECONDS=60
export RATE_LIMIT_TOKEN_REQUESTS=240
export RATE_LIMIT_TOKEN_WINDOW_SECONDS=60
export RATE_LIMIT_SETUP_REQUESTS=30
export RATE_LIMIT_SETUP_WINDOW_SECONDS=60
export RATE_LIMIT_WEBHOOK_REQUESTS=600
export RATE_LIMIT_WEBHOOK_WINDOW_SECONDS=60
export RATE_LIMIT_DEGRADED_REQUESTS=30
export RATE_LIMIT_DEGRADED_WINDOW_SECONDS=60
```

### 1.2) Helm values override examples (Kubernetes)

Use environment-specific values files (for example `values-staging.yaml` and `values-production.yaml`) with the same profile values.

```yaml
# values-staging.yaml (example)
authsvc:
  env:
    REDIS_ADDR: redis.staging.svc.cluster.local:6379
    REDIS_DB: "0"
    WEBAUTHN_SESSION_TTL_SECONDS: "600"
    RATE_LIMIT_USE_TENANT: "true"
    RATE_LIMIT_KEY_PREFIX: wardseal:ratelimit:staging
    RATE_LIMIT_DEFAULT_REQUESTS: "1600"
    RATE_LIMIT_DEFAULT_WINDOW_SECONDS: "60"
    RATE_LIMIT_LOGIN_REQUESTS: "80"
    RATE_LIMIT_LOGIN_WINDOW_SECONDS: "60"
    RATE_LIMIT_TOKEN_REQUESTS: "360"
    RATE_LIMIT_TOKEN_WINDOW_SECONDS: "60"
    RATE_LIMIT_SETUP_REQUESTS: "45"
    RATE_LIMIT_SETUP_WINDOW_SECONDS: "60"
    RATE_LIMIT_WEBHOOK_REQUESTS: "800"
    RATE_LIMIT_WEBHOOK_WINDOW_SECONDS: "60"
    RATE_LIMIT_DEGRADED_REQUESTS: "40"
    RATE_LIMIT_DEGRADED_WINDOW_SECONDS: "60"

dirsvc:
  env:
    REDIS_ADDR: redis.staging.svc.cluster.local:6379
    REDIS_DB: "0"
    RATE_LIMIT_USE_TENANT: "true"
    RATE_LIMIT_KEY_PREFIX: wardseal:ratelimit:staging
    RATE_LIMIT_DEFAULT_REQUESTS: "1600"
    RATE_LIMIT_DEFAULT_WINDOW_SECONDS: "60"
    RATE_LIMIT_LOGIN_REQUESTS: "80"
    RATE_LIMIT_LOGIN_WINDOW_SECONDS: "60"
    RATE_LIMIT_TOKEN_REQUESTS: "360"
    RATE_LIMIT_TOKEN_WINDOW_SECONDS: "60"
    RATE_LIMIT_SETUP_REQUESTS: "45"
    RATE_LIMIT_SETUP_WINDOW_SECONDS: "60"
    RATE_LIMIT_WEBHOOK_REQUESTS: "800"
    RATE_LIMIT_WEBHOOK_WINDOW_SECONDS: "60"
    RATE_LIMIT_DEGRADED_REQUESTS: "40"
    RATE_LIMIT_DEGRADED_WINDOW_SECONDS: "60"

govsvc:
  env:
    REDIS_ADDR: redis.staging.svc.cluster.local:6379
    REDIS_DB: "0"
    RATE_LIMIT_USE_TENANT: "true"
    RATE_LIMIT_KEY_PREFIX: wardseal:ratelimit:staging
    RATE_LIMIT_DEFAULT_REQUESTS: "1600"
    RATE_LIMIT_DEFAULT_WINDOW_SECONDS: "60"
    RATE_LIMIT_LOGIN_REQUESTS: "80"
    RATE_LIMIT_LOGIN_WINDOW_SECONDS: "60"
    RATE_LIMIT_TOKEN_REQUESTS: "360"
    RATE_LIMIT_TOKEN_WINDOW_SECONDS: "60"
    RATE_LIMIT_SETUP_REQUESTS: "45"
    RATE_LIMIT_SETUP_WINDOW_SECONDS: "60"
    RATE_LIMIT_WEBHOOK_REQUESTS: "800"
    RATE_LIMIT_WEBHOOK_WINDOW_SECONDS: "60"
    RATE_LIMIT_DEGRADED_REQUESTS: "40"
    RATE_LIMIT_DEGRADED_WINDOW_SECONDS: "60"
```

Install/upgrade with your override file:

```bash
helm upgrade --install wardseal ./deploy/charts/wardseal \
  --namespace wardseal \
  --values deploy/charts/wardseal/values.yaml \
  --values deploy/charts/wardseal/values-staging.yaml
```

### 2) Canary rollout process

1. Roll out to one service/pod set first.
2. Observe `429` rate, latency, and auth failure rates for at least 30-60 minutes.
3. Increase budgets in small increments (10-20%) if legitimate traffic is impacted.
4. Keep degraded profile strict so Redis outages fail closed rather than fail open.

### 3) Operational guardrails

- Keep key prefixes service-scoped (example: `wardseal:ratelimit:authsvc`).
- Keep tenant-aware mode enabled for multi-tenant fairness.
- Adjust webhook limits separately from login/token limits.
- Validate changes during peak windows before promoting to all clusters.

### 4) Quick diagnosis checklist

- Sudden `429` spikes on `/login` with normal Redis health: increase `RATE_LIMIT_LOGIN_REQUESTS` gradually.
- `429` spikes across all endpoints with Redis errors: service is in degraded mode; restore Redis first.
- One tenant impacted disproportionately: review tenant traffic and consider tenant-specific policy overlay.

---

## Backup Strategy

### Database Backup

```bash
pg_dump -h localhost -U wardseal identity_platform > backup.sql
```

### Scheduled Backups (cron)

```bash
0 2 * * * pg_dump -h localhost -U wardseal identity_platform | gzip > /backups/wardseal_$(date +\%Y\%m\%d).sql.gz
```
