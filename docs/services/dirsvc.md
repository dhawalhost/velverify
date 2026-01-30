# Directory Service (`dirsvc`)

The **Directory Service** acts as the central source of truth for identity data within WardSeal. It manages the lifecycle of Users and Groups.

## Key Responsibilities

*   **User Management**: CRUD operations for Users (`Create`, `Read`, `Update`, `Delete`).
*   **Group Management**: CRUD operations for Groups and Membership management.
*   **Identity Storage**: Persists identity data to the primary database.
*   **Tenant Isolation**: Ensures data is logically separated by Tenant ID.
*   **Internal API**: Provides gRPC/HTTP endpoints for other services to query identity data.

## Data Model
*   **User**: `ID`, `Email`, `PasswordHash`, `Status`, `ProfileAttributes`.
*   **Group**: `ID`, `Name`, `Description`, `Members`.

## Dependencies
*   **PostgreSQL**: Primary storage for identity records.

## Integration
*   Used by **Auth Service** to verify credentials during login.
*   Used by **Governance Service** to resolve campaign reviewers and targets.
