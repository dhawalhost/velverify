# Authentication Guide

WardSeal provides comprehensive authentication capabilities including password-based login, multi-factor authentication, social login, and enterprise SSO.

## Table of Contents

- [Password Login](#password-login)
- [Multi-Factor Authentication (MFA)](#multi-factor-authentication)
- [Social Login](#social-login)
- [SAML SSO](#saml-sso)
- [OAuth 2.0 / OIDC](#oauth-20--oidc)
- [Sessions & Tokens](#sessions--tokens)

---

## Password Login

**Endpoint:** `POST /login`

```bash
curl -X POST http://auth.wardseal.local/login \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: admin-system" \
  -d '{
    "username": "admin@wardseal.com",
    "password": "password123"
  }'
```

**Response:**
```json
{
  "token": "eyJhbGciOiJSUzI1NiIs..."
}
```

### If MFA is Enabled

If the user has TOTP enabled, you'll receive:

```json
{
  "mfa_required": true,
  "pending_token": "eyJhbGciOi...",
  "user_id": "admin@wardseal.com"
}
```

Complete the login with the TOTP code:

```bash
curl -X POST http://auth.wardseal.local/login/mfa \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: admin-system" \
  -d '{
    "pending_token": "eyJhbGciOi...",
    "totp_code": "123456",
    "user_id": "admin@wardseal.com"
  }'
```

---

## Multi-Factor Authentication

WardSeal supports two MFA methods:

### TOTP (Authenticator Apps)

Compatible with Google Authenticator, Authy, 1Password, etc.

#### Enroll TOTP

**Endpoint:** `POST /api/v1/mfa/totp/enroll`

```bash
curl -X POST http://localhost:8080/api/v1/mfa/totp/enroll \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: YOUR_TENANT_ID" \
  -d '{"user_id": "user@wardseal.com"}'
```

**Response:**
```json
{
  "secret": "JBSWY3DPEHPK3PXP",
  "qr_code": "data:image/png;base64,...",
  "otpauth_url": "otpauth://totp/WardSeal:user@wardseal.com?..."
}
```

#### Verify & Activate

```bash
curl -X POST http://localhost:8080/api/v1/mfa/totp/verify \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: YOUR_TENANT_ID" \
  -d '{
    "user_id": "user@wardseal.com",
    "code": "123456"
  }'
```

### WebAuthn (Passkeys)

Support for hardware security keys and biometric authentication.

**Register:**
1. Call `POST /api/v1/mfa/webauthn/register/begin`
2. Use browser WebAuthn API with returned options
3. Call `POST /api/v1/mfa/webauthn/register/finish`

---

## Social Login & Identity Federation

WardSeal supports Identity Federation, allowing users to sign in via external Identity Providers (IdPs) using standard OIDC/OAuth2.

### Features
- **JIT Provisioning**: Automatically creates new user profiles upon first successful external authentication.
- **Auto-Linking**: Maps external identities to existing local accounts via email verification.

### Configuration

SSO providers are configured per tenant. Ensure the `X-Tenant-ID` header is provided in all requests.

### Authentication Endpoint

`POST /social/login`

Exchanges an authorization code from an external provider for a WardSeal JWT.

#### Request Payload

```json
{
  "provider": "google",
  "code": "auth_code_from_provider",
  "redirect_uri": "https://app.wardseal.com/callback"
}
```

#### Response Payload (Success)

```json
{
  "access_token": "eyJhbGci...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

#### Response Payload (MFA Required)

```json
{
  "pending_token": "step_up_token_jwt",
  "error": "mfa_required",
  "message": "Additional authentication required"
}
```


---

## SAML SSO

WardSeal acts as a SAML 2.0 Identity Provider (IdP).

### Metadata

Get your IdP metadata:
```
GET http://localhost:8080/saml/metadata
```

### Configure Service Provider

```bash
curl -X POST http://localhost:8080/api/v1/saml/providers \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: YOUR_TENANT_ID" \
  -d '{
    "name": "My App",
    "entity_id": "https://myapp.com/saml/metadata",
    "acs_url": "https://myapp.com/saml/acs",
    "metadata_url": "https://myapp.com/saml/metadata"
  }'
```

---

## OAuth 2.0 / OIDC

WardSeal is a fully compliant OAuth 2.0 and OpenID Connect provider.

### Tenant Auto-Discovery (Recommended)

For multi-tenant setups, clients can resolve the correct tenant issuer automatically from user email.

#### 1) Resolve issuer/discovery/JWKS by email

**Endpoint:** `GET /api/v1/oidc/resolve?email=user@company.com`

```bash
curl "http://localhost:8080/api/v1/oidc/resolve?email=admin@wardseal.com"
```

**Response:**
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

Use the returned `issuer` (or `discovery_url`) in your OIDC client config.

#### 2) WebFinger issuer discovery (OIDC clients)

**Endpoint:** `GET /.well-known/webfinger?resource=acct:user@company.com`

```bash
curl "http://localhost:8080/.well-known/webfinger?resource=acct:admin@wardseal.com"
```

**Response:**
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

Many OIDC RPs can use this to auto-locate the tenant issuer.

### Endpoints

| Endpoint | URL |
|----------|-----|
| Authorization | `/oauth2/authorize` |
| Token | `/oauth2/token` |
| Introspect | `/oauth2/introspect` |
| Revoke | `/oauth2/revoke` |
| JWKS | `/.well-known/jwks.json` |

### Authorization Code Flow (with PKCE)

```javascript
// 1. Generate PKCE
const codeVerifier = generateRandomString(64);
const codeChallenge = base64url(sha256(codeVerifier));

// 2. Redirect to authorize
window.location = `http://localhost:8080/oauth2/authorize?
  response_type=code&
  client_id=YOUR_CLIENT_ID&
  redirect_uri=https://yourapp.com/callback&
  scope=openid profile email&
  code_challenge=${codeChallenge}&
  code_challenge_method=S256&
  state=random_state`;

// 3. Exchange code for tokens
const response = await fetch('/oauth2/token', {
  method: 'POST',
  body: new URLSearchParams({
    grant_type: 'authorization_code',
    code: 'AUTHORIZATION_CODE',
    redirect_uri: 'https://yourapp.com/callback',
    client_id: 'YOUR_CLIENT_ID',
    client_secret: 'YOUR_CLIENT_SECRET',
    code_verifier: codeVerifier
  })
});
```

---

## Sessions & Tokens

### Token Types

| Token | Lifetime | Purpose |
|-------|----------|---------|
| Access Token | 1 hour | API authorization |
| Refresh Token | 7 days | Get new access tokens |
| ID Token | 1 hour | User identity (OIDC) |

### httpOnly Cookies

WardSeal sets secure httpOnly cookies automatically:

| Cookie | Path | Purpose |
|--------|------|---------|
| `wardseal_access_token` | `/` | Access token |
| `wardseal_refresh_token` | `/oauth2/token` | Refresh token |

### Logout

```bash
curl -X POST http://localhost:8080/logout \
  -H "X-Tenant-ID: YOUR_TENANT_ID"
```

This clears authentication cookies.
