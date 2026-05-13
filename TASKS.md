# Identity & Governance Platform: Development Tasks

This document provides a granular checklist of tasks to be completed for each phase of the project. It is intended to be a living document, updated as development progresses.

## Phase 1: Core Identity & Authentication

### 1.1. Project Setup & Foundation

-   [x] Define product spec and success metrics (`identity-platform-spec.md`)
-   [x] Set up monorepo with `go mod`
-   [x] Establish project structure and microservice layout
-   [x] Configure CI/CD pipeline (`.github/workflows/ci.yml`)
-   [x] Define and implement a comprehensive logging strategy (`pkg/logger`)
-   [x] Set up a local development environment with `docker-compose`

### 1.2. Directory Service (`dirsvc`)

-   [x] Finalize database schema for users and groups (`migrations`)
-   [x] Implement CRUD APIs for users
-   [x] Implement CRUD APIs for groups
-   [x] Add support for custom user attributes (JSONB)
-   [x] Implement API authentication and authorization
-   [x] Write unit and integration tests

### 1.3. Auth Service (`authsvc`)

-   [x] Implement OIDC provider core
    -   [x] Authorization endpoint (`/oauth2/authorize`)
    -   [x] Token endpoint (`/oauth2/token`)
        -   [x] Authorization Code + PKCE flow
        -   [x] Client Credentials flow
        -   [x] Refresh Token flow
-   [x] Implement token introspection and revocation endpoints
-   [x] Secure token generation
    -   [x] Use a secure key management system (e.g., Vault, KMS) instead of in-memory keys
    -   [x] Implement key rotation
-   [x] Implement password hashing (e.g., bcrypt or Argon2)
-   [x] Implement JWKS endpoint (`/.well-known/jwks.json`)
-   [x] Write unit and integration tests for OIDC flows

### 1.4. Multi-tenancy

-   [x] Add `tenant_id` to all relevant database tables
-   [x] Enforce tenant isolation in all API endpoints
-   [x] Implement a middleware for tenant resolution (e.g., from hostname or JWT)

### 1.5. Observability

-   [x] Add Prometheus metrics to all services (`pkg/observability`)
-   [x] Set up a Grafana dashboard for key metrics (`deploy/observability/grafana/wardseal-overview-dashboard.json`)
-   [x] Implement distributed tracing with OpenTelemetry

## Phase 2: Enterprise SSO & Provisioning

### 2.1. SAML 2.0 IdP

-   [x] Implement SAML 2.0 IdP endpoint
-   [x] Support SP-initiated and IdP-initiated flows (partial)
-   [x] Implement SAML assertion generation and signing
-   [x] Add support for configuring SAML service providers

### 2.2. SCIM 2.0 Service

-   [x] Implement SCIM 2.0 server endpoints (`/scim/v2`)
-   [x] Support core SCIM resources: `User`, `Group`
-   [x] Implement SCIM filtering and pagination
-   [x] Write unit and integration tests for SCIM flows (`internal/scim/service_test.go`)

### 2.3. Connector Framework (`provsvc`)

-   [x] Design and implement a pluggable connector framework
-   [x] Define the connector interface and lifecycle
-   [x] Implement a message queue for asynchronous provisioning tasks (DB-backed)

### 2.4. First-party Connectors

-   [x] Develop a connector for Active Directory/LDAP
-   [x] Develop a connector for Azure AD (Microsoft Graph API)
-   [x] Develop a connector for Google Workspace

### 2.5. Admin UI

-   [x] Choose a frontend framework (e.g., React, Vue, Angular)
-   [x] Implement a basic UI for user and group management
-   [x] Add a UI for configuring SSO connections (OIDC & SAML)
-   [x] Add a UI for managing SCIM connectors

## Phase 3: Identity Governance & Administration (IGA)

### 3.1. Access Requests

-   [x] Design and implement a workflow for access requests
-   [x] Create APIs for submitting and approving access requests
-   [x] Integrate with the provisioning service to automate fulfillment

### 3.2. Certification Campaigns

-   [x] Design and implement a system for creating and managing certification campaigns
-   [x] Create APIs for campaign creation, scheduling, and review
-   [x] Develop a UI for reviewers to approve or revoke access

### 3.3. RBAC & Policy

-   [x] Implement a role management system (CRUD for roles)
-   [x] Associate permissions with roles
-   [x] Integrate a policy engine (e.g., OPA) for fine-grained authorization
-   [x] Create a UI for managing roles and policies

### 3.4. Audit & Reporting

-   [x] Create an immutable audit trail for all events
-   [x] Implement a service for querying and exporting audit logs
-   [x] Develop pre-built reports for compliance (e.g., access reviews, user activity)

## Phase 4: Hardening & Scalability

### 4.1. Security

-   [x] Integrate with a secure key management system (KMS or HSM)
-   [x] Integrate with a secrets management system (e.g., HashiCorp Vault)
-   [x] Conduct a full security audit and penetration test
-   [x] Implement rate limiting and other security measures at the API gateway

### 4.2. Scalability & Performance

-   [x] Conduct load testing and performance benchmarking
-   [x] Optimize database queries and other performance bottlenecks
-   [x] Develop a strategy for horizontal scaling of services

#### 4.2.1. Shared State Readiness (horizontal scaling prerequisite)

-   [x] Move OAuth authorization code storage to a shared persistent store (`SQLAuthorizationCodeStore`)
-   [x] Move refresh token storage to a shared persistent store (`SQLRefreshTokenStore`)
-   [x] Move token revocation checks to a shared persistent store (`SQLRevocationStore`)
-   [x] Add pluggable WebAuthn session store with optional Redis backend and in-memory fallback
-   [x] Replace remaining in-memory auth flow session state (MFA/WebAuthn transient sessions) with Redis-backed storage
-   [x] Add runtime guardrails that fail fast if production starts with in-memory critical stores

#### 4.2.2. Edge and Ingress Scale Plan

-   [x] Introduce Traefik as edge proxy in local and staging environments
-   [x] Keep static Admin UI serving separate from API routing responsibilities
-   [x] Define and test path routing parity for `/t/*`, `/api/v1/*`, `/scim/*`, `/login/lookup`, and `/.well-known/*`
-   [x] Enable sticky-session-free routing (all auth endpoints must be stateless across replicas)

#### 4.2.3. Distributed Rate Limiting

-   [x] Replace per-instance in-memory IP limiter with Redis-backed distributed limiter
-   [x] Add tenant-aware and endpoint-aware limits (login, token, setup, webhook)
-   [x] Add safe fallback behavior for Redis outages (degraded mode with strict defaults)

#### 4.2.4. Service Autoscaling and Resilience

-   [x] Add HPA policies for `authsvc`, `dirsvc`, and `govsvc` (CPU targets implemented)
-   [x] Add PodDisruptionBudgets and anti-affinity for critical services
-   [x] Tune readiness/liveness probes and startup probes for scale-out stability
-   [x] Validate database connection pool sizing against max replica counts

#### 4.2.5. Capacity Verification and SLOs

-   [x] Define SLOs (availability, p95/p99 latency, token issuance success rate)
-   [x] Create repeatable k6/Gatling load profiles for auth flows (login, PKCE, refresh, setup-link redemption)
-   [x] Run baseline (single replica) vs scaled (N replicas) benchmarks and publish results
-   [x] Add dashboards/alerts for saturation, queueing, 5xx, and auth error rates

### 4.3. High Availability & Disaster Recovery

-   [x] Implement a high-availability architecture with redundant services (HPAs implemented)
-   [x] Develop and test a disaster recovery plan

### 4.4. Developer Experience

-   [x] Create a dedicated developer portal
-   [x] Publish comprehensive API documentation
-   [x] Provide SDKs for common languages (Go, TypeScript, Java)
-   [x] Write quickstart guides and tutorials

## Phase 5: Zero Trust Capabilities

### 5.1. Device Posture

-   [x] Design a system for collecting device health information
-   [x] Integrate with common EDR/MDM solutions
-   [x] Add device posture as a factor in authorization policies

### 5.2. Continuous Access Evaluation

-   [x] Implement a mechanism for continuous evaluation of access policies
-   [x] Subscribe to events that may trigger re-evaluation (e.g., change in user risk, device posture)
-   [x] Propagate access changes in real-time

### 5.3. Risk-Based Authentication

-   [x] Develop a risk scoring engine
-   [x] Ingest signals for risk calculation (e.g., location, time of day, user behavior)
-   [x] Dynamically adjust authentication requirements based on risk score

### 5.4. Advanced MFA

-   [x] Add support for FIDO2/WebAuthn as an MFA method
-   [x] Implement certificate-based authentication for devices and services
