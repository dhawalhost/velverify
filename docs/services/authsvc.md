# Auth Service (`authsvc`)

The **Auth Service** is the heart of the WardSeal identity platform. It handles all authentication requests, session management, and protocol support for OIDC and SAML.

## Key Responsibilities

*   **Authentication**: Username/Password, Social Login, Enterprise Federation.
*   **MFA**: Multi-Factor Authentication (TOTP, WebAuthn/Passkeys).
*   **Protocol Support**:
    *   **OIDC Provider**: Issues ID Tokens and Access Tokens.
    *   **SAML Identity Provider**: Generates SAML assertions for legacy apps.
*   **Session Management**: Manages user sessions and refresh tokens.
*   **User Portal API**: Provides endpoints for the end-user dashboard (`/api/v1/user/apps`).

## Dependencies
*   **Directory Service**: To validate credentials and fetch user attributes.
*   **Policy Service**: To evaluate login policies (e.g. IP Allowlist).
*   **Vault**: For secure signing key operations (KMS).
*   **PostgreSQL**: Stores OAuth clients, refresh tokens, and audit logs.
*   **Redis**: Caches volatile session data.

## Key Configuration
| Env Variable | Description |
|---|---|
| `DIRECTORY_SERVICE_URL` | URL of the Directory Service. |
| `DEPLOYMENT_MODE` | `saas` or `selfhost`. |
| `VAULT_ADDR` | Address of HashiCorp Vault. |
