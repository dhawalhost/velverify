# Service Level Objectives (SLOs) - WardSeal

This document defines the target Service Level Objectives (SLOs) and Service Level Indicators (SLIs) for the WardSeal Identity Platform.

## 1. Availability

| Service / Endpoint | SLI | SLO Target |
| :--- | :--- | :--- |
| **Authentication Gateway** (`/oauth2/*`, `/login`) | Ratio of successful HTTP responses (2xx, 3xx, 4xx excluding 429/5xx) to total requests. | **99.9%** |
| **Directory APIs** (`/api/v1/users`, `/scim/*`) | Ratio of successful HTTP responses to total requests. | **99.5%** |

## 2. Latency

| Service / Endpoint | Metric | SLO Target |
| :--- | :--- | :--- |
| **Token Issuance** (`/oauth2/token`) | p95 Latency | **< 200ms** |
| **User Lookup** (`/api/v1/users/{id}`) | p95 Latency | **< 150ms** |
| **WebAuthn Authentication** | p95 Latency | **< 300ms** |

## 3. Quality / Success Rate

| Indicator | SLI | SLO Target |
| :--- | :--- | :--- |
| **Token Validation** | Ratio of valid tokens successfully verified to total validation requests. | **99.99%** |

## 4. Monitoring & Alerting
- **Burn Rate Alerts**: Page on-call if the error budget burn rate threatens the 30-day SLO.
