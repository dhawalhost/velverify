# Identity & Governance Platform

This repository contains the source code for the Identity & Governance Platform, a multi-tenant, enterprise-grade identity solution.

## Project Structure

The project is organized as a monorepo containing multiple microservices. This structure is designed to promote code sharing, maintainability, and independent service deployment.

-   **/api**: Contains OpenAPI specifications for all public-facing APIs.
-   **/cmd**: Houses the main application entry points. Each subdirectory corresponds to a specific service (e.g., `authsvc`, `dirsvc`).
-   **/configs**: Stores configuration files for different environments (e.g., `development.yaml`, `production.yaml`).
-   **/deploy**: Contains deployment configurations, such as Kubernetes manifests and Helm charts.
-   **/docs**: Includes project documentation, architecture diagrams, and design documents.
-   **/internal**: Contains the core business logic for each service. This code is not intended to be imported by other applications.
    -   **/internal/auth**: Business logic for the Authentication Service.
    -   **/internal/directory**: Business logic for the Directory Service.
    -   **/internal/governance**: Business logic for the Governance Service.
    -   **/internal/policy**: Business logic for the Policy Service.
    -   **/internal/provisioning**: Business logic for the Provisioning Service.
-   **/pkg**: Provides shared libraries and utilities that can be used across multiple services.
    -   **/pkg/config**: Configuration loading and management.
    -   **/pkg/database**: Database connections and abstractions.
    -   **/pkg/errors**: Standardized error handling.
    -   **/pkg/logger**: Structured logging setup.
    -   **/pkg/middleware**: Shared HTTP/gRPC middleware.
    -   **/pkg/observability**: Metrics, tracing, and health checks.
    -   **/pkg/transport**: Shared transport utilities (e.g., HTTP/gRPC helpers).
-   **/scripts**: Includes helper scripts for development, building, and testing.
-   **/test**: Contains end-to-end and integration tests.

## Getting Started

... (To be added)

## Multi-tenant requests

All Directory and Auth service APIs expect the caller to include an `X-Tenant-ID` header. The tenant middleware validates the
presence of this header and will reject the request with `400 Bad Request` when it is missing. If you are testing locally,
remember to add the header, for example:

```bash
curl -H "X-Tenant-ID: demo-tenant" ...
```

### Internal credential verification

To keep password hashes inside the Directory service while still allowing the Auth service to authenticate users, there is an
internal-only endpoint exposed by `dirsvc`:

- `POST /internal/credentials/verify` — Accepts `{ "email": "user@example.com", "password": "…" }`, enforces the tenant
    header, and returns the user profile when the credentials are valid. Invalid credentials respond with `401`.

Only other platform services should call this endpoint. It is not intended for direct use by external clients or the Admin UI, and it
is now protected by a shared service-to-service authentication token.

#### Service-to-service authentication

- Set `SERVICE_AUTH_TOKEN` in both `authsvc` and `dirsvc` deployments. The same value must be configured on each service for the
    shared secret handshake. A fallback value of `dev-internal-token` is used only for local development.
- Optionally, `SERVICE_AUTH_HEADER` customizes the header name (defaults to `X-Service-Token`).
- All calls to `/internal/*` routes on `dirsvc` must include the header/value pair; requests without it receive `401` before any
    business logic runs.

### Database tenant isolation

Migrations up to `000003_enforce_tenant_isolation` ensure every account and membership row carries a `tenant_id`, and logins are
unique per tenant. Apply the latest SQL migrations before running the services to guarantee strict data isolation.

### Authorization Code + PKCE (preview)

The auth service now supports the OAuth 2.0 Authorization Code flow with PKCE:

- `/oauth2/authorize` expects `response_type=code`, `code_challenge`, and `code_challenge_method=S256`.
- `/oauth2/token` accepts `grant_type=authorization_code`, the original `code`, and a matching `code_verifier`.
- Authorization codes are short-lived (5 minutes) and scoped per tenant/client/redirect URI. Redeeming a code twice or using a
    mismatched verifier returns `invalid_grant`.
- OAuth clients now live in Postgres (`oauth_clients` table, see migration `000004`). Each row is scoped to a tenant via
        `tenant_id`, includes a stable `client_id`, `client_type` (`public` or `confidential`), and stores redirect URIs and allowed
        scopes as arrays. Run the latest migrations before starting `authsvc` so the table exists.
- `authsvc` reads clients via the new repository—configure `DB_HOST`, `DB_USER`, `DB_PASSWORD`, `DB_NAME`, and `DB_SSLMODE` if
    the defaults (`localhost`, `user`, `password`, `identity_platform`, `disable`) don’t match your environment.
- You can seed clients manually if needed, for example:

```sql
INSERT INTO oauth_clients (tenant_id, client_id, client_type, name, redirect_uris, allowed_scopes)
VALUES (
    '11111111-1111-1111-1111-111111111111',
    'demo-client',
    'public',
    'Demo SPA',
    ARRAY['http://localhost:3000/callback'],
    ARRAY['openid','profile','email']
);
```

This lays the groundwork for full OIDC compliance once client registration and user sessions are wired up.

### Governance OAuth client administration

The Governance service exposes tenant-scoped CRUD APIs for managing OAuth clients so you no longer need to edit the database directly. All
requests require the usual `X-Tenant-ID` header.

| Method | Path                              | Description                                  |
|--------|-----------------------------------|----------------------------------------------|
| GET    | `/api/v1/oauth/clients`           | List clients for the tenant                  |
| POST   | `/api/v1/oauth/clients`           | Create a client (include secret for confidential clients) |
| GET    | `/api/v1/oauth/clients/:clientID` | Fetch a specific client                      |
| PUT    | `/api/v1/oauth/clients/:clientID` | Update metadata, redirect URIs, scopes, type |
| DELETE | `/api/v1/oauth/clients/:clientID` | Delete a client                              |

Example request to create a confidential client:

```bash
curl -X POST http://localhost:8082/api/v1/oauth/clients \
    -H "Content-Type: application/json" \
    -H "X-Tenant-ID: demo-tenant" \
    -d '{
        "client_id": "admin-portal",
        "name": "Admin Portal",
        "client_type": "confidential",
        "redirect_uris": ["https://admin.example.com/callback"],
        "allowed_scopes": ["openid", "profile"],
        "client_secret": "replace-me"
    }'
```

Successful responses return the client metadata (excluding the secret hash). Validation errors surface as `400` with a JSON body
`{"error": "…"}`, missing clients return `404`, and unexpected failures emit `500`.

#### Admin CLI helper

For quick experiments, a lightweight CLI lives in `cmd/admincli`. Run it with Go directly:

```bash
go run ./cmd/admincli list -tenant demo-tenant

go run ./cmd/admincli create \
    -tenant demo-tenant \
    -client-id admin-portal \
    -name "Admin Portal" \
    -type confidential \
    -redirects https://admin.example.com/callback \
    -scopes openid,profile \
    -secret super-secret
```

Override `-base-url` if `govsvc` is not running on `http://localhost:8082`.

## Contributing

... (To be added)
