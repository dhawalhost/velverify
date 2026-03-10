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

## Backup Strategy

### Database Backup

```bash
pg_dump -h localhost -U wardseal identity_platform > backup.sql
```

### Scheduled Backups (cron)

```bash
0 2 * * * pg_dump -h localhost -U wardseal identity_platform | gzip > /backups/wardseal_$(date +\%Y\%m\%d).sql.gz
```
