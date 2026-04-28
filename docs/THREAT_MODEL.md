# Threat Model

> Implementation status aligned with WardSeal codebase as of 2026-01-03

---

## Authentication Threats

| Threat | Mitigation | Status | Implementation |
|--------|------------|--------|----------------|
| Credential stuffing | Rate limiting | ✅ Implemented | `middleware.RateLimitMiddleware(20, 40)` |
| Credential stuffing | Account lockout | ✅ Implemented | `login_attempt_store.go` - 5 failures = 15min |
| MFA bypass | Policy enforcement | ✅ Implemented | Enforced for critical roles (Admin) and self-enrolled users |
| Phishing | Passkeys (WebAuthn) | ✅ Implemented | `webauthn.go`, `webauthn_api.go` |
| SCIM API Key Theft | Bcrypt Hashing | ✅ Implemented | `RequireSCIMBearerToken` in `scimauth.go` |


**Missing:** Dynamic per-user MFA policy toggle (currently role-based + self-enroll)

---

## OAuth Threats

| Threat | Mitigation | Status | Implementation |
|--------|------------|--------|----------------|
| Token replay | Refresh rotation | ✅ Implemented | `handleRefreshTokenGrant` - deletes old, issues new |
| Redirect abuse | Strict allowlists | ✅ Implemented | `oauth_clients.redirect_uris` validated |
| Authorization code interception | PKCE | ✅ Implemented | S256 code challenge in `service.go` |
| Spoofing IdP responses | OIDC validation | ✅ Implemented | `conf.Exchange` in `service_federation.go` |


---

## Session Threats

| Threat | Mitigation | Status | Implementation |
|--------|------------|--------|----------------|
| CSRF | Same-site cookies | ✅ Implemented | `SameSiteStrictMode` in `setAuthCookies` |
| Session fixation | Regeneration on auth | ✅ Implemented | New token on each login |
| XSS | httpOnly cookies | ✅ Implemented | `httpOnly: true` in `setAuthCookies` |
| Logout | Cookie clearing | ✅ Implemented | `/logout` endpoint with `clearAuthCookies` |


---

## Admin Threats

| Threat | Mitigation | Status | Implementation |
|--------|------------|--------|----------------|
| Privilege escalation | Audit logs | ✅ Implemented | `audit` package, `audit_logs` table |
| Silent config changes | Immutable audit | ✅ Implemented | Append-only audit log with export |
| Account takeover | MFA enforced | ✅ Implemented | TOTP + WebAuthn in login flow |

---

## Platform Threats

| Threat | Mitigation | Status | Implementation |
|--------|------------|--------|----------------|
| Tenant data leakage | Strict isolation | ✅ Implemented | `X-Tenant-ID` header, all queries filtered |
| Key compromise | KMS + rotation | ✅ Implemented | HashiCorp Vault Transit supported and enforced in Prod |
| Abuse | Rate limits | ✅ Implemented | Token bucket per-IP |
| Abuse | WAF | ❌ Not Implemented | No WAF integration |
| Circular graph DoS | MaxDepth constraint | ✅ Implemented | `MaxDepth = 10` in `engine.go` |


**Missing:** WAF integration

---

## Summary

| Status | Count |
|--------|-------|
| ✅ Fully Implemented | 16 |
| ⚠️ Partially Implemented | 0 |
| ❌ Not Implemented | 1 |

---

## Roadmap for Full Alignment

### Medium Priority
1. **MFA Policy** - Admin-configurable per-user/per-org MFA requirements
2. **WAF Integration** - Cloud WAF (Cloudflare/AWS WAF) for production

### Low Priority (Production Deployment)
3. **KMS Integration** - External secrets management for signing keys
