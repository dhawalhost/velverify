# Quick Start Guide

This guide walks you through setting up the Identity & Governance Platform from scratch, including all prerequisites, database migrations, and service startup steps.

## Prerequisites

Before you begin, ensure you have the following installed:

- **Docker & Docker Compose** (v2.0+): For running Postgres, Redis, and containerized services
- **Go** (1.25+): For building and running services locally
- **Node.js** (20+) & npm: For the Admin UI
- **PostgreSQL client tools** (optional): For manual database inspection (`psql`)

## Fresh Setup: Docker Compose (Recommended)

This is the fastest way to get the entire stack running locally.

### 1. Clone the repository

```bash
git clone https://github.com/dhawalhost/velverify.git
cd velverify
```

### 2. Start the infrastructure services

Start Postgres and Redis first to ensure they're healthy before dependent services boot:

```bash
docker compose up -d postgres redis
```

Wait ~10 seconds for Postgres to initialize, then verify health:

```bash
docker compose ps postgres
```

You should see `healthy` in the STATUS column.

### 3. Apply database migrations

The services expect the database schema to exist. Apply all migrations manually using the following script:

```bash
for f in migrations/*.up.sql; do
  echo "Applying $f"
  cat "$f" | docker exec -i identity_platform_postgres psql -U user -d identity_platform
done
```

**What these migrations do:**

- **000001**: Creates initial `accounts` and `identity_providers` tables
- **000002**: Adds `identity_groups`, `group_memberships`, and password hash support
- **000003**: Enforces tenant isolation with `tenant_id` columns and indexes
- **000004**: Creates `oauth_clients` table for governance OAuth client management

You should see output like:

```text
Applying migrations/000001_create_initial_tables.up.sql
CREATE TABLE
CREATE TABLE
...
Applying migrations/000004_create_oauth_clients.up.sql
CREATE TABLE
...
```


### 4. Start the services

Now bring up the authentication, directory, and governance services:

```bash
docker compose up -d authsvc dirsvc govsvc
```

Verify all services are running:

```bash
docker compose ps
```

### 5. Start the Admin UI (optional)

If you want to use the web-based admin interface:

```bash
docker compose up -d adminui
```

The Admin UI will be available at <http://localhost:5173> (proxied to `govsvc` at port 8082).

### 6. Verify the setup

Test the governance service health endpoint:

```bash
curl http://localhost:8082/health
```

Expected response:

```json
{"healthy":true}
```

Test listing OAuth clients (should return empty initially):

```bash
curl -H "X-Tenant-ID: 11111111-1111-1111-1111-111111111111" \
  http://localhost:8082/api/v1/oauth/clients
```

Expected response:

```json
{"clients":[]}
```


### 7. Create your first OAuth client

Using the Admin CLI:

```bash
go run ./cmd/admincli create \
  -tenant 11111111-1111-1111-1111-111111111111 \
  -client-id my-app \
  -name "My Application" \
  -type public \
  -redirects http://localhost:3000/callback \
  -scopes openid,profile,email
```

Or via curl:

```bash
curl -X POST http://localhost:8082/api/v1/oauth/clients \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: 11111111-1111-1111-1111-111111111111" \
  -d '{
    "client_id": "my-app",
    "name": "My Application",
    "client_type": "public",
    "redirect_uris": ["http://localhost:3000/callback"],
    "allowed_scopes": ["openid", "profile", "email"]
  }'
```

### 8. View logs

To troubleshoot or monitor services:

```bash
# All services
docker compose logs -f

# Specific service
docker compose logs -f govsvc
```

### 9. Stop the stack

When you're done:

```bash
docker compose down
```

To remove volumes (including database data):

```bash
docker compose down -v
```

---

## Alternative: Running Services Locally (Development)

For active development, you may prefer running Go services directly on your host.

### 1. Start infrastructure

```bash
docker compose up -d postgres redis
```

### 2. Apply migrations

```bash
for f in migrations/*.up.sql; do
  cat "$f" | docker exec -i identity_platform_postgres psql -U user -d identity_platform
done
```

### 3. Install Go dependencies

```bash
go mod download
```

### 4. Run the governance service

```bash
cd /path/to/velverify
go run ./cmd/govsvc
```

The service will start on port 8082 and connect to Postgres at `localhost:5432`.

### 5. Run the Admin UI in dev mode

In a separate terminal:

```bash
cd web/admin
npm install
npm run dev
```

The UI will start at <http://localhost:5173> with hot-reload enabled.

### 6. Run other services as needed

```bash
# Directory service (port 8081)
go run ./cmd/dirsvc

# Auth service (port 8080)
go run ./cmd/authsvc

# Policy service (port 8083)
go run ./cmd/policysvc

# Provisioning service (port 8084)
go run ./cmd/provsvc
```

---

## Database Migration Details

All migrations live in the `migrations/` folder and follow the naming convention:

```text
{version}_{description}.{up|down}.sql
```


### Manual Migration Management

If you need more control over migrations, you can apply them individually:

```bash
# Apply a specific migration
cat migrations/000004_create_oauth_clients.up.sql | \
  docker exec -i identity_platform_postgres psql -U user -d identity_platform

# Rollback a migration
cat migrations/000004_create_oauth_clients.down.sql | \
  docker exec -i identity_platform_postgres psql -U user -d identity_platform
```

### Using a Migration Tool (Optional)

For production environments, consider using [golang-migrate](https://github.com/golang-migrate/migrate):

```bash
# Install golang-migrate
brew install golang-migrate  # macOS
# or download from https://github.com/golang-migrate/migrate/releases

# Apply all migrations
migrate -path ./migrations \
  -database "postgres://user:password@localhost:5432/identity_platform?sslmode=disable" up

# Rollback last migration
migrate -path ./migrations \
  -database "postgres://user:password@localhost:5432/identity_platform?sslmode=disable" down 1
```

### Verifying Schema

Connect to the database and inspect tables:

```bash
docker exec -it identity_platform_postgres psql -U user -d identity_platform
```

Inside psql:

```sql
-- List all tables
\dt

-- Describe oauth_clients table
\d oauth_clients

-- Check for tenant isolation
SELECT column_name, data_type 
FROM information_schema.columns 
WHERE table_name = 'oauth_clients' AND column_name = 'tenant_id';
```

---

## Environment Variables

### Governance Service (`govsvc`)

| Variable | Default | Description |
|----------|---------|-------------|
| `DB_HOST` | `localhost` | PostgreSQL host |
| `DB_PORT` | `5432` | PostgreSQL port |
| `DB_USER` | `user` | Database username |
| `DB_PASSWORD` | `password` | Database password |
| `DB_NAME` | `identity_platform` | Database name |
| `DB_SSLMODE` | `disable` | SSL mode for Postgres connection |
| `CORS_ALLOWED_ORIGINS` | `http://localhost:5173,http://127.0.0.1:5173` | Comma-separated list of allowed origins |

### Admin UI Build (`adminui`)

| Variable | Default | Description |
|----------|---------|-------------|
| `VITE_GOVSVC_URL` | `http://localhost:8082` | Governance API base URL (build-time) |

Override in `docker-compose.yml`:

```yaml
adminui:
  build:
    args:
      VITE_GOVSVC_URL: http://your-custom-host:8082
```

---

## Tenant Setup

The platform is multi-tenant and requires a valid UUID for the `X-Tenant-ID` header. The sample tenant UUID used throughout this guide is:

```text
11111111-1111-1111-1111-111111111111
```


### Creating Additional Tenants

Tenants are managed via the Directory Service APIs (future work). For now, you can seed tenants directly in the database:

```bash
docker exec -i identity_platform_postgres psql -U user -d identity_platform <<EOF
-- Insert a new tenant (accounts table serves as tenant registry for now)
INSERT INTO accounts (id, tenant_id, email, created_at, updated_at)
VALUES (
  gen_random_uuid(),
  '22222222-2222-2222-2222-222222222222',
  'admin@tenant2.example.com',
  NOW(),
  NOW()
);
EOF
```

Then use `22222222-2222-2222-2222-222222222222` as your `X-Tenant-ID` header value.

---

## Troubleshooting

### Issue: "relation 'oauth_clients' does not exist"

**Cause:** Migrations haven't been applied.

**Solution:** Run the migration script from step 3 above.

### Issue: Port 5432 already allocated

**Cause:** Another Postgres instance is running on your host.

**Solution:**

- Stop the conflicting instance: `brew services stop postgresql` (macOS)
- Or change the port mapping in `docker-compose.yml`:

  ```yaml
  postgres:
    ports:
      - "5433:5432"  # Use host port 5433
  ```


### Issue: CORS errors in the browser

**Cause:** The Admin UI origin isn't in the `CORS_ALLOWED_ORIGINS` list.

**Solution:** Update `docker-compose.yml` and rebuild:

```yaml
govsvc:
  environment:
    - CORS_ALLOWED_ORIGINS=http://localhost:5173,http://localhost:3000
```

```bash
docker compose build govsvc
docker compose up -d govsvc
```

### Issue: CLI returns "invalid input syntax for type uuid"

**Cause:** Tenant ID is not a valid UUID.

**Solution:** Use a properly formatted UUID:

```bash
go run ./cmd/admincli list -tenant 11111111-1111-1111-1111-111111111111
```

### Issue: Cannot connect to database from local services

**Cause:** Environment variables may be misconfigured.

**Solution:** Export the variables before running:

```bash
export DB_HOST=localhost
export DB_USER=user
export DB_PASSWORD=password
export DB_NAME=identity_platform
export DB_SSLMODE=disable

go run ./cmd/govsvc
```

---

## Next Steps

Once your environment is running:

1. **Explore the APIs**: See `README.md` for detailed API documentation
2. **Read the spec**: Review `identity-platform-spec.md` for architecture and design decisions
3. **Check the roadmap**: See `ROADMAP.md` for planned features
4. **Run tests**: Execute `go test ./...` to verify the codebase
5. **Build custom integrations**: Use the OpenAPI spec in `api/openapi.yaml` to generate client SDKs

---

## Production Deployment

For production deployments:

1. **Use Kubernetes with Helm charts** (see `deploy/charts/`)
2. **Enable TLS/SSL** for all database connections
3. **Use a secrets manager** (Vault, AWS Secrets Manager) instead of environment variables
4. **Apply migrations via CI/CD** with a migration tool like `golang-migrate`
5. **Configure proper CORS origins** matching your production domains
6. **Set up monitoring** using Prometheus and Grafana (see `pkg/observability/`)
7. **Review security hardening** recommendations in the roadmap (Phase 4)

For Helm deployment examples, see the "Kubernetes deployment" section in `README.md`.

---

## Support

For issues, questions, or contributions:

- GitHub Issues: [https://github.com/dhawalhost/velverify/issues](https://github.com/dhawalhost/velverify/issues)
- Documentation: See `README.md`, `identity-platform-spec.md`, and `ROADMAP.md`
