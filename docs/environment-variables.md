# Environment Variables Configuration

This document describes all environment variables required for the Identity Platform services and CI/CD pipeline.

## CircleCI Contexts

### `ghcr` Context (GitHub Container Registry)
Create in CircleCI → Organization Settings → Contexts

| Variable | Required | Description |
| :--- | :---: | :--- |
| `GHCR_USERNAME` | ✅ | GitHub username |
| `GHCR_TOKEN` | ✅ | GitHub Personal Access Token with `write:packages` scope |
| `GHCR_OWNER` | ✅ | GitHub org/username for image prefix (e.g., `dhawalhost`) |

---

## Integration Test Environment Variables

These are automatically set by CircleCI for the `integration-test` job, but listed here for local testing:

| Variable | Default | Description |
| :--- | :--- | :--- |
| `TEST_DB_HOST` | `localhost` | PostgreSQL host for integration tests |
| `TEST_DB_PORT` | `5432` | PostgreSQL port |
| `TEST_DB_USER` | `user` | Test database username |
| `TEST_DB_PASSWORD` | `password` | Test database password |
| `TEST_DB_NAME` | `identity_platform_test` | Test database name |

### Running Integration Tests Locally

```bash
# Start PostgreSQL (using docker-compose)
docker-compose up -d postgres

# Create test database
psql -h localhost -U user -d postgres -c "CREATE DATABASE identity_platform_test;"

# Run migrations on test database
./scripts/migrate/migrate -path migrations \
  -database "postgres://user:password@localhost:5432/identity_platform_test?sslmode=disable" up

# Run integration tests
TEST_DB_HOST=localhost \
TEST_DB_USER=user \
TEST_DB_PASSWORD=password \
TEST_DB_NAME=identity_platform_test \
go test -v -tags=integration ./tests/integration/...
```

## Service Environment Variables

### Database Configuration (All Services)

| Variable | Required | Default | Description |
| :--- | :---: | :--- | :--- |
| `DB_HOST` | ❌ | `localhost` | PostgreSQL host |
| `DB_PORT` | ❌ | `5432` | PostgreSQL port |
| `DB_USER` | ❌ | `user` | Database username |
| `DB_PASSWORD` | ❌ | `password` | Database password |
| `DB_NAME` | ❌ | `identity_platform` | Database name |
| `DB_SSLMODE` | ❌ | `disable` | SSL mode: `disable`, `require`, `verify-full` |

---

### Auth Service (`authsvc`)

| Variable | Required | Default | Description |
| :--- | :---: | :--- | :--- |
| `AUTH_SERVICE_URL` | ❌ | `http://localhost:8080` | Base URL for auth service |
| `UI_URL` | ❌ | `http://manage.wardseal.local` | Admin UI origin used for login/password redirects |
| `DIRECTORY_SERVICE_URL` | ❌ | `http://dirsvc:8081` | URL of directory service |
| `SERVICE_AUTH_TOKEN` | ⚠️ | - | Token for service-to-service auth |
| `SERVICE_AUTH_HEADER` | ❌ | `X-Service-Auth` | Header name for service auth |
| `KMS_PROVIDER` | ❌ | `local` | Key provider: `local` or `vault` |
| `JWT_PRIVATE_KEY_PATH` | ⚠️ | - | Required in local mode; filesystem path to private key |
| `JWT_PUBLIC_KEY_PATH` | ⚠️ | - | Required in local mode; filesystem path to public key |
| `VAULT_ADDR` | ⚠️ | - | Required with `KMS_PROVIDER=vault` |
| `VAULT_TOKEN` | ⚠️ | - | Vault auth token (optional if using AppRole) |
| `VAULT_ROLE_ID` | ⚠️ | - | Vault AppRole role ID (optional if using token) |
| `VAULT_SECRET_ID` | ⚠️ | - | Vault AppRole secret ID (optional if using token) |
| `VAULT_KEY_NAME` | ❌ | `wardseal-signing-key` | Vault Transit key name used for JWT signing |
| `VAULT_KEY_PATH` | ❌ | `transit` | Vault Transit mount path |
| `VAULT_NAMESPACE` | ❌ | - | Vault Enterprise namespace (if used) |
| `LOG_LEVEL` | ❌ | `info` | Logging level: `debug`, `info`, `warn`, `error` |

#### Key Management Mode Matrix

| Environment | KMS Mode | Required Key Vars |
| :--- | :--- | :--- |
| Local | `KMS_PROVIDER=local` | `JWT_PRIVATE_KEY_PATH`, `JWT_PUBLIC_KEY_PATH` |
| Staging | `KMS_PROVIDER=vault` | `VAULT_ADDR` + (`VAULT_TOKEN` **or** `VAULT_ROLE_ID`+`VAULT_SECRET_ID`) + `VAULT_KEY_NAME` (+ optional `VAULT_KEY_PATH`) |
| Production | `KMS_PROVIDER=vault` | Same as staging |

> Runtime policy enforcement now validates this contract. Staging/production reject non-vault KMS; local rejects missing JWT key paths.

#### Redis-backed session and distributed rate-limit settings

| Variable | Required | Default | Description |
| :--- | :---: | :--- | :--- |
| `REDIS_ADDR` | ⚠️ | - | Redis host:port. Required in production for WebAuthn transient session storage. |
| `REDIS_PASSWORD` | ❌ | - | Redis password (if enabled). |
| `REDIS_DB` | ❌ | `0` | Redis DB index. |
| `WEBAUTHN_SESSION_TTL_SECONDS` | ❌ | `600` | TTL for transient WebAuthn sessions. |
| `RATE_LIMIT_USE_TENANT` | ❌ | `true` | When `true`, limiter buckets include tenant scope. |
| `RATE_LIMIT_KEY_PREFIX` | ❌ | `authsvc:ratelimit` | Base Redis key prefix for limiter counters. |
| `RATE_LIMIT_DEFAULT_REQUESTS` | ❌ | `1200` | Default request budget per window. |
| `RATE_LIMIT_DEFAULT_WINDOW_SECONDS` | ❌ | `60` | Default limiter window in seconds. |
| `RATE_LIMIT_LOGIN_REQUESTS` | ❌ | `60` | Login endpoint budget per window. |
| `RATE_LIMIT_LOGIN_WINDOW_SECONDS` | ❌ | `60` | Login limiter window in seconds. |
| `RATE_LIMIT_TOKEN_REQUESTS` | ❌ | `240` | Token endpoint budget per window. |
| `RATE_LIMIT_TOKEN_WINDOW_SECONDS` | ❌ | `60` | Token limiter window in seconds. |
| `RATE_LIMIT_SETUP_REQUESTS` | ❌ | `30` | Setup endpoint budget per window. |
| `RATE_LIMIT_SETUP_WINDOW_SECONDS` | ❌ | `60` | Setup limiter window in seconds. |
| `RATE_LIMIT_WEBHOOK_REQUESTS` | ❌ | `600` | Webhook endpoint budget per window. |
| `RATE_LIMIT_WEBHOOK_WINDOW_SECONDS` | ❌ | `60` | Webhook limiter window in seconds. |
| `RATE_LIMIT_DEGRADED_REQUESTS` | ❌ | `30` | Strict fallback budget when Redis is unavailable. |
| `RATE_LIMIT_DEGRADED_WINDOW_SECONDS` | ❌ | `60` | Fallback limiter window in seconds. |

#### Recommended starting profiles

| Environment | Login | Token | Setup | Webhook | Default | Degraded |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| Development | 120/min | 600/min | 60/min | 1200/min | 2400/min | 60/min |
| Staging | 80/min | 360/min | 45/min | 800/min | 1600/min | 40/min |
| Production (initial) | 60/min | 240/min | 30/min | 600/min | 1200/min | 30/min |

> Tune these per tenant size and observed traffic patterns. Start conservative on auth-critical endpoints (`/login`, `/oauth2/token`) and increase only after load and abuse testing.

#### Enterprise License (Optional)
| Variable | Required | Default | Description |
| :--- | :---: | :--- | :--- |
| `REQUIRE_LICENSE` | ❌ | `false` | Set to `true` to enable license check |
| `LICENSE_KEY` | ⚠️ | - | Enterprise license key (required if REQUIRE_LICENSE=true) |
| `LICENSE_PUBLIC_KEY_PATH` | ❌ | `/etc/wardseal/license_public.pem` | Path to license public key |

---

### Directory Service (`dirsvc`)

| Variable | Required | Default | Description |
| :--- | :---: | :--- | :--- |
| `SERVICE_AUTH_TOKEN` | ⚠️ | `dev-internal-token` | Token for service-to-service auth |
| `SERVICE_AUTH_HEADER` | ❌ | - | Custom header name for service auth |

---

### Governance Service (`govsvc`)

| Variable | Required | Default | Description |
| :--- | :---: | :--- | :--- |
| `DIRECTORY_SERVICE_URL` | ❌ | `http://dirsvc:8081` | URL of directory service |
| `WEBHOOK_SECRET` | ⚠️ | - | Secret for signing webhooks |
| **`WARDSEAL_MASTER_KEY`** | ✅ | - | **CRITICAL**. A 32-byte hex string used for field-level encryption (Connectors, Slack). |
| `KMS_PROVIDER` | ❌ | `local` | Encryption provider: `local` (AES) or `vault` (Transit). |
| `REDIS_ADDR` | ✅ | `localhost:6379` | Required for async discovery jobs and ChatOps state. |
| `REDIS_PASSWORD` | ❌ | - | Optional Redis auth. |
| `REDIS_DB` | ❌ | `0` | Redis database index. |
| `VAULT_ADDR` | ⚠️ | - | Required if `KMS_PROVIDER=vault`. |
| `VAULT_TOKEN` | ⚠️ | - | Vault auth token. |
| `VAULT_KEY_NAME` | ❌ | `wardseal-master` | Transit engine key name. |

---

### Observability (All Services)

| Variable | Required | Default | Description |
| :--- | :---: | :--- | :--- |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | ❌ | - | OpenTelemetry collector endpoint |
| `OTEL_SERVICE_NAME` | ❌ | - | Service name for tracing |

---

## Production Recommendations

> [!CAUTION]
> Never use default values in production!

1. **Use environment-appropriate key management:**
   - Local: `WARDSEAL_MASTER_KEY` must be a cryptographically strong 32-byte hex string.
   - Staging/Production: Vault Transit (`KMS_PROVIDER=vault`) is highly recommended for multi-tenant isolation.

2. **Generate strong secrets:**
   ```bash
   # Generate a 32-byte Master Key
   openssl rand -hex 32
   ```

3. **Infrastructure Isolation:**
   - Ensure `Redis` is configured with TLS in production if accessed over network.
   - Use `DB_SSLMODE=verify-full` for all PostgreSQL connections.
