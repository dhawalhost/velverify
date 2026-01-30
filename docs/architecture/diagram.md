# System Architecture

The following diagram illustrates the high-level architecture of the WardSeal platform using the C4 Container model.

```mermaid
C4Container
    title Container Diagram for WardSeal Identity Platform

    Person(user, "End User", "A user of the platform (employee, customer)")
    Person(admin, "Administrator", "Identity Administrator managing the platform")

    System_Boundary(wardseal, "WardSeal Platform") {
        Container(webapp, "Web Admin Console & User Portal", "React, Vite", "Single Page Application for management and user self-service")
        
        Container(gateway, "API Gateway / Ingress", "Nginx/Ingress", "Entry point for all requests")

        Container(authsvc, "Auth Service", "Go", "Handles Authentication, SSO (OIDC/SAML), MFA, and Sessions")
        Container(dirsvc, "Directory Service", "Go", "Manages Users, Groups, and Identity storage")
        Container(govsvc, "Governance Service", "Go", "Manages Access Reviews, Campaigns, and Entitlements")
        Container(policysvc, "Policy Service", "Go", "Evaluates Access Policies (PBAC/RBAC)")
        Container(provsvc, "Provisioning Service", "Go", "Handles SCIM and Connector provisioning to downstream apps")

        ContainerDb(db, "Primary Database", "PostgreSQL", "Stores Users, Policies, Reviews, Audit Logs")
        ContainerDb(vault, "Vault", "HashiCorp Vault", "Secure storage for Signing Keys and Secrets")
        ContainerDb(redis, "Cache", "Redis", "Session cache and ephemeral state")
    }

    System_Ext(apps, "Downstream Applications", "SaaS Apps (Slack, GitHub) or Internal Apps")
    System_Ext(idp, "External IdP", "Google, Azure AD (for Federation)")

    Rel(user, webapp, "Uses", "HTTPS")
    Rel(admin, webapp, "Uses", "HTTPS")

    Rel(webapp, gateway, "API Calls", "JSON/HTTPS")
    
    Rel(gateway, authsvc, "Routes Auth Req", "gRPC/HTTP")
    Rel(gateway, dirsvc, "Routes Dir Req", "gRPC/HTTP")
    Rel(gateway, govsvc, "Routes Gov Req", "gRPC/HTTP")

    Rel(authsvc, dirsvc, "Generic User Lookup", "gRPC")
    Rel(authsvc, policysvc, "Policy Checks", "gRPC")
    Rel(authsvc, vault, "Sign/Verify Tokens", "gRPC")
    Rel(authsvc, redis, "Session Store", "TCP")
    Rel(authsvc, db, "Read/Write Auth Data", "SQL")

    Rel(dirsvc, db, "Read/Write Identity Data", "SQL")

    Rel(govsvc, dirsvc, "Fetch Users/Groups", "gRPC")
    Rel(govsvc, provsvc, "Trigger Remediation", "gRPC")
    Rel(govsvc, db, "Store Reviews", "SQL")

    Rel(provsvc, apps, "Provisions Users", "SCIM/REST")
    Rel(provsvc, vault, "Fetch App Credentials", "gRPC")

    Rel(authsvc, idp, "Federates with", "OIDC/SAML")
```

## Service Interactions

1.  **Authentication Flow**:
    *   User accesses **Web App**, redirects to **Auth Service**.
    *   **Auth Service** verifies credentials against **Directory Service** (or External IdP).
    *   **Auth Service** checks **Policy Service** for login policies (e.g. MFA requirements).
    *   On success, **Auth Service** mints tokens signed by keys in **Vault**.

2.  **Governance Flow**:
    *   **Governance Service** initiates a Campaign.
    *   Reads reviewers and targets from **Directory Service**.
    *   When access is revoked, **Governance Service** calls **Provisioning Service** to deprovision access in downstream **Apps**.
