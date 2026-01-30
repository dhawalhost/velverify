# Governance Service (`govsvc`)

The **Governance Service** provides Identity Governance and Administration (IGA) capabilities. It ensures that users have the right access to the right resources.

## Key Responsibilities

*   **Access Reviews**: Orchestrates certification campaigns where managers or owners review user access.
*   **Entitlement Management**: Tracks who has access to what (Permissions/Roles).
*   **Access Requests**: Manages workflows for users requesting new access.
*   **Remediation**: Triggers revocation actions when access is denied during a review.

## Dependencies
*   **Directory Service**: To fetch user details and manager relationships.
*   **Provisioning Service**: To execute access changes (Revoke/Grant) in target systems.
*   **PostgreSQL**: Stores campaign definitions, decisions, and audit trails.

## Terminology
*   **Campaign**: A scoped review process (e.g. "Q1 Engineering Access Review").
*   **Decision**: The outcome of a review item (Approve/Revoke).
