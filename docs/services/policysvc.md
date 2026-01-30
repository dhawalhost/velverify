# Policy Service (`policysvc`)

The **Policy Service** is the decision engine for the platform. It evaluates complex rules to authorize actions within WardSeal and potentially for downstream applications.

## Key Responsibilities

*   **Policy Evaluation**: Evaluates requests against defined policies (e.g. "Can User X access Resource Y?").
*   **PBAC/RBAC**: Supports Policy-Based and Role-Based Access Control models.
*   **Login Policies**: Determines if a user authentication attempt should be allowed (e.g. Time of day, IP Geolocation).

## Dependencies
*   **PostgreSQL**: Stores policy definitions.
*   **OPA / OpenFGA** (Conceptually): May utilize internal logic or external engines for evaluation.

## Integration
*   Called by **Auth Service** during login (Pre-Auth checks).
*   Called by **Governance Service** to check if a request violates any Segregation of Duties (SoD) policies.
