# API Reference

Complete API documentation for WardSeal services.

## Base URLs

| Service | Port | Base URL |
|---------|------|----------|
| **Auth Hub** | 8080 | `http://auth.wardseal.local` |
| **Directory** | 8081 | `http://api.wardseal.local` (via Gateway) |
| **Governance** | 8082 | `http://api.wardseal.local` (via Gateway) |

## Authentication

All API requests require:
- `X-Tenant-ID` header: Your tenant UUID (Required for isolation).
- `Authorization` header: `Bearer {token}`.

### SCIM Bearer Token Strategies

For SCIM and Directory endpoints, WardSeal accepts three token tiers:
1. **Internal Service Token**: Pre-shared secret for intra-cluster communication.
2. **JWT Access Tokens**: Decoded via the platform's RSA public key.
3. **API Keys**: Long-lived secrets verified via prefix lookup and Bcrypt comparison.


---

## Auth Service (8080)

### Login

```
POST /login
```

| Field | Type | Required |
|-------|------|----------|
| username | string | ✓ |
| password | string | ✓ |

### MFA Login

```
POST /login/mfa
```

| Field | Type | Required |
|-------|------|----------|
| pending_token | string | ✓ |
| totp_code | string | ✓ |
| user_id | string | ✓ |

### Logout

```
POST /logout
```

### OAuth2 Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/oauth2/authorize` | GET | Start authorization flow |
| `/oauth2/token` | POST | Exchange code for tokens |
| `/oauth2/introspect` | POST | Validate token |
| `/oauth2/revoke` | POST | Revoke token |
| `/.well-known/jwks.json` | GET | Public keys |
| `/api/v1/oidc/resolve` | GET | Resolve tenant-specific issuer/discovery/JWKS by email |
| `/.well-known/webfinger` | GET | Return tenant issuer for `acct:user@domain` |

### OIDC Tenant Auto-Discovery

#### Resolve by email

```bash
curl "http://localhost:8080/api/v1/oidc/resolve?email=admin@wardseal.com"
```

```json
{
  "tenant_id": "admin-system",
  "tenant_slug": "admin",
  "issuer": "http://localhost:8080/t/admin",
  "discovery_url": "http://localhost:8080/t/admin/.well-known/openid-configuration",
  "jwks_uri": "http://localhost:8080/t/admin/.well-known/jwks.json",
  "authorization": "http://localhost:8080/t/admin/oauth2/authorize",
  "token_endpoint": "http://localhost:8080/t/admin/oauth2/token"
}
```

#### WebFinger

```bash
curl "http://localhost:8080/.well-known/webfinger?resource=acct:admin@wardseal.com"
```

```json
{
  "subject": "acct:admin@wardseal.com",
  "links": [
    {
      "rel": "http://openid.net/specs/connect/1.0/issuer",
      "href": "http://localhost:8080/t/admin"
    }
  ]
}
```

### MFA - TOTP

| Endpoint | Method | Body |
|----------|--------|------|
| `/api/v1/mfa/totp/enroll` | POST | `{user_id}` |
| `/api/v1/mfa/totp/verify` | POST | `{user_id, code}` |
| `/api/v1/mfa/totp/status` | GET | Query: `user_id` |
| `/api/v1/mfa/totp` | DELETE | Query: `user_id` |

### Developer Apps

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/apps` | GET | List apps |
| `/api/v1/apps` | POST | Create app |
| `/api/v1/apps/:id` | GET | Get app |
| `/api/v1/apps/:id` | PUT | Update app |
| `/api/v1/apps/:id` | DELETE | Delete app |
| `/api/v1/apps/:id/rotate-secret` | POST | Rotate secret |

### API Keys

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/api-keys` | GET | List keys |
| `/api/v1/api-keys` | POST | Create key |
| `/api/v1/api-keys/:id` | DELETE | Revoke key |

---

## Directory Service (8081)

### SCIM 2.0 Users

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/scim/v2/Users` | GET | List/search users |
| `/scim/v2/Users` | POST | Create user |
| `/scim/v2/Users/:id` | GET | Get user |
| `/scim/v2/Users/:id` | PUT | Replace user |
| `/scim/v2/Users/:id` | PATCH | Update user |
| `/scim/v2/Users/:id` | DELETE | Delete user |

### SCIM 2.0 Groups

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/scim/v2/Groups` | GET | List groups |
| `/scim/v2/Groups` | POST | Create group |
| `/scim/v2/Groups/:id` | GET | Get group |
| `/scim/v2/Groups/:id` | PATCH | Update group |
| `/scim/v2/Groups/:id` | DELETE | Delete group |

---

## Governance Service (8082)

### Organizations

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/organizations` | GET | List orgs |
| `/api/v1/organizations` | POST | Create org |
| `/api/v1/organizations/:id` | GET | Get org |
| `/api/v1/organizations/:id` | PUT | Update org |
| `/api/v1/organizations/:id` | DELETE | Delete org |
| `/api/v1/organizations/:id/domain-verification/generate` | POST | Gen token |
| `/api/v1/organizations/:id/domain-verification/verify` | POST | Verify |

### Roles

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/roles` | GET | List roles |
| `/api/v1/roles` | POST | Create role |
| `/api/v1/roles/:id` | DELETE | Delete role |

### Access Requests

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/access-requests` | GET | List requests |
| `/api/v1/access-requests` | POST | Submit request |
| `/api/v1/access-requests/:id/approve` | POST | Approve |
| `/api/v1/access-requests/:id/reject` | POST | Reject |

### Audit Logs

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/audit-logs` | GET | List audit logs |
| `/api/v1/audit-logs/export` | GET | Export CSV |

### Webhooks

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/webhooks` | GET | List webhooks |
| `/api/v1/webhooks` | POST | Create webhook |
| `/api/v1/webhooks/:id` | DELETE | Delete webhook |

---

## Error Responses

All errors return JSON:

```json
{
  "error": "error_code",
  "error_description": "Human readable message"
}
```

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `invalid_request` | 400 | Missing/invalid parameters |
| `invalid_credentials` | 401 | Wrong username/password |
| `account_locked` | 429 | Too many failed attempts |
| `mfa_required` | 200 | Need TOTP code |
| `invalid_grant` | 400 | Invalid/expired token |
