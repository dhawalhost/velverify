# Identity & Governance Platform: Product Roadmap

This document outlines the high-level roadmap for building the Identity & Governance Platform. It is based on the detailed specification in `identity-platform-spec.md` and the existing codebase.

## Phase 1: Core Identity & Authentication (The Foundation)

**Goal:** Establish a secure and scalable foundation for identity management and authentication. This phase focuses on implementing the core OIDC/OAuth2 functionality, user and group management, and the necessary infrastructure for a multi-tenant environment.

**Key Features:**

*   **OIDC Provider:** Fully compliant OpenID Connect provider with support for the Authorization Code flow (with PKCE) and Client Credentials flow.
*   **Token Service:** Secure JWT generation, signing, and validation. Includes a public JWKS endpoint for token verification.
*   **Directory Service:** Robust user and group management APIs, including support for custom schema attributes.
*   **Multi-tenancy:** Foundational support for multi-tenancy with tenant isolation at the data level.
*   **Database & Migrations:** Solidified database schema with a reliable migration strategy.
*   **CI/CD:** Automated build, test, and deployment pipeline for all services.
*   **Observability:** Basic observability stack with logging, metrics, and tracing.

## Phase 2: Enterprise SSO & Provisioning

**Goal:** Expand the platform's capabilities to support enterprise single sign-on (SSO) and automated user provisioning.

**Key Features:**

*   **SAML 2.0 IdP:** Implementation of a SAML 2.0 Identity Provider to connect with enterprise applications.
*   **SCIM 2.0 Service:** A SCIM 2.0 compliant server to automate user and group provisioning from external systems.
*   **Connector Framework:** A pluggable framework for building connectors to various systems (e.g., HR systems, other directories).
*   **First-party Connectors:** Development of connectors for key systems like Active Directory, Azure AD, and Google Workspace.
*   **Admin UI:** A basic administrative user interface for managing users, groups, and connections.

## Phase 3: Identity Governance & Administration (IGA)

**Goal:** Introduce advanced identity governance features to manage the entire identity lifecycle and ensure compliance.

**Key Features:**

*   **Access Requests:** A workflow for users to request access to applications and resources.
*   **Certification Campaigns:** The ability to create and manage access certification campaigns (attestations).
*   **Role-Based Access Control (RBAC):** A comprehensive RBAC system for managing permissions.
*   **Policy Engine:** Integration of a policy engine (e.g., OPA) for fine-grained authorization decisions.
*   **Audit & Reporting:** A comprehensive audit trail for all identity and access events, with reporting capabilities.

## Phase 4: Hardening & Scalability

**Goal:** Focus on security, scalability, and reliability to ensure the platform is enterprise-ready.

**Key Features:**

*   **Security Hardening:** Advanced security measures, including key management (KMS/HSM), secrets management (Vault), and regular penetration testing.
*   **Scalability & Performance:** Performance tuning, load testing, and optimization to handle large-scale deployments.
*   **High Availability & Disaster Recovery:** Implementation of a high-availability architecture with a clear disaster recovery plan.
*   **Developer Experience:** A dedicated developer portal with API documentation, SDKs, and tutorials.
*   **Compliance:** Achieving compliance with standards like SOC2 and GDPR.

## Phase 5: Zero Trust Capabilities

**Goal:** Implement advanced features to fully align the platform with a Zero Trust security model. Zero Trust means "never trust, always verify" — every access decision is made dynamically based on identity + device + context.

### Pillar 1: Identity (Continuous Verification)

*   **Adaptive MFA Step-Up** *(Quick Win)*: When the risk engine scores a login as MEDIUM risk, return a step-up challenge instead of a session token. The user completes TOTP and receives the full token.
*   **IP Allow/Block + Geo Policy** *(Quick Win)*: Per-tenant IP CIDR block lists and country-level geo-restrictions enforced at login time via the risk engine.
*   **RBAC Claims in JWT** *(Quick Win)*: Inject user roles and permissions into access and ID token claims so downstream apps can enforce policy without extra API calls.
*   **Passwordless Login:** WebAuthn/Passkeys as the primary authentication factor (not just 2nd factor).
*   **Continuous Access Evaluation (CAE):** Real-time session invalidation via Redis pub/sub when a security event (password change, device compromise) fires after token issuance.
*   **Per-app Session Policies:** Force re-authentication for sensitive applications (e.g., shorter token TTL, mandatory MFA).

### Pillar 2: Device (Posture Enforcement)

*   **Device Posture Gate:** Require device registration for policy-protected apps; block access from unregistered or unmanaged devices.
*   **MDM/EDR Integration:** Poll Jamf, Microsoft Intune, or CrowdStrike for real-time device compliance status and incorporate into device risk score.
*   **mTLS / Device Certificate Issuance:** Integrate Vault PKI to issue short-lived device certificates, enabling certificate-based device authentication.

### Pillar 3: Network (Context-Aware)

*   **IP Allow/Block Lists:** Per-tenant CIDR-level allow and deny policies (part of quick wins above).
*   **Geo-Restriction Policies:** Block logins originating from high-risk or sanctioned countries.
*   **Anonymous Proxy / VPN / Tor Detection:** Integrate with an IP intelligence feed (MaxMind GeoIP2) to flag anonymized network access.

### Pillar 4: Application (Least Privilege)

*   **Entitlement-Aware Tokens:** RBAC roles and permissions embedded in JWT claims (quick win above).
*   **Per-app Re-auth Policies:** App-level session lifetime overrides enforced at the authorization endpoint.
*   **Just-In-Time Access (JIT):** Temporary, request-based access grants with automatic expiry (governance access request workflow).

### Pillar 5: Visibility & Data

*   **Anomaly Detection:** Rule-based flagging of suspicious login patterns (impossible travel, off-hours access, credential stuffing) from the audit stream.
*   **SIEM Native Connectors:** Direct push integrations for Splunk, Elastic SIEM, and Microsoft Sentinel beyond the current webhook model.
*   **Micro-segmentation Support:** Integration with service meshes (Istio, Linkerd) for identity-based network policy enforcement.
