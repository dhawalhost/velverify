# WardSeal Service & Platform Details

This document provides deep technical details on the platform's internal mechanisms, multi-tenancy enforcement, and service-to-service communication.

## 1. Multi-Tenant Request Pattern

All Identity and Governance APIs operate under a strict multi-tenant model. Callers must include the `X-Tenant-ID` header with a valid UUID.

```bash
curl -H "X-Tenant-ID: <TENANT_UUID>" https://api.wardseal.local/api/v1/...
```

The tenant middleware validates this header before any business logic is executed. Requests without it are rejected with `400 Bad Request`.

## 2. Internal Service Communication

### Service-to-Service Authentication
Internal endpoints (starting with `/internal/*`) are protected by a shared secret handshake.
- **Header**: `X-Service-Token` (configurable via `SERVICE_AUTH_HEADER`).
- **Value**: Must match the `SERVICE_AUTH_TOKEN` environment variable on both the source and destination services.

### Credential Verification Logic
To maintain security, password hashes are never exposed outside the `dirsvc`. The `authsvc` verifies credentials via a secure internal loop:
- `POST /internal/credentials/verify` — Validates email/password against the tenant-scoped directory and returns the profile only on success.

## 3. Data Isolation

WardSeal enforces **Logical Isolation** at the database layer. Every table (Logins, Identities, Memberships, etc.) carries a `tenant_id` foreign key. Row-level filters are applied at the repository layer to prevent cross-tenant data leakage.

## 4. OAuth2 / OpenID Connect Implementation

### Authorization Code + PKCE
WardSeal implements the OIDC-compliant Authorization Code flow with Proof Key for Code Exchange (PKCE) for all modern clients.
- **/oauth2/authorize**: Supports `code_challenge` and `S256` methods.
- **/oauth2/token**: Requires `code_verifier` matching the original challenge.
- **Client Metadata**: Stored in the `oauth_clients` table, including redirect URIs, allowed scopes, and client types (`public` or `confidential`).

### Client Management API
The Governance service (`govsvc`) provides tenant-scoped CRUD for OAuth clients:

| Method | Path | Description |
|---|---|---|
| GET | `/api/v1/oauth/clients` | List tenant clients |
| POST | `/api/v1/oauth/clients` | Create a new client |
| GET | `/api/v1/oauth/clients/:id` | Fetch client metadata |
| PUT | `/api/v1/oauth/clients/:id` | Update client configuration |
| DELETE| `/api/v1/oauth/clients/:id` | Revoke/Delete a client |

## 5. Administrative Tools

### Admin CLI
A lightweight CLI for platform bootstrapping and experimentation.
```bash
go run ./cmd/admincli list -tenant <TENANT_UUID>
```
Supported commands: `list`, `create`, `delete`. Use `-help` for full parameter lists.
