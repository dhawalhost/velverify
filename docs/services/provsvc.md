# Provisioning Service (`provsvc`)

The **Provisioning Service** is responsible for outward-facing identity operations. It synchronizes identity state from WardSeal to downstream applications.

## Key Responsibilities

*   **SCIM Client**: Pushes users and groups to SCIM-compliant applications (e.g. Slack, GitHub Enterprise).
*   **Connectors**: Manages integrations with non-SCIM applications via proprietary APIs.
*   **Lifecycle Management**: Handles Joiner, Mover, and Leaver (JML) events.
    *   **Joiner**: Auto-provision birthright access.
    *   **Leaver**: Auto-deprovision access upon termination.

## Dependencies
*   **Vault**: Retrieves API keys and credentials for connecting to downstream apps.
*   **PostgreSQL**: Stores connector configurations and sync state/logs.

## Integration
*   Triggered by **Directory Service** events (User Created/Deleted).
*   Triggered by **Governance Service** (remediation actions).
