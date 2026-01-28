# WardSeal Documentation

Welcome to the technical documentation for the **WardSeal Identity Platform**.

## Architecture
*   [System Architecture Diagram](architecture/diagram.md) - High-level overview of services and interactions.

## Core Microservices
WardSeal is built as a microservices architecture. Below are the detailed documentation for each core service:

| Service | Description | Links |
|---|---|---|
| **Auth Service** | Authentication, SSO, MFA, and User Portal API. | [Docs](services/authsvc.md) |
| **Directory Service** | Identity store for Users and Groups. | [Docs](services/dirsvc.md) |
| **Governance Service** | Access Reviews, Campaigns, and Requests. | [Docs](services/govsvc.md) |
| **Policy Service** | PBAC/RBAC policy evaluation engine. | [Docs](services/policysvc.md) |
| **Provisioning Service** | SCIM and downstream application provisioning. | [Docs](services/provsvc.md) |

## Guides
*   [Getting Started](../GETTING_STARTED.md)
*   [Quickstart Guide](../QUICKSTART.md)
*   [Developer Tasks](../TASKS.md)

## API Reference
*   See `api/` directory for Protocol Buffer definitions (if applicable).
