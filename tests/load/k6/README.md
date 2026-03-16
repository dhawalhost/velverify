# Scalability Load Testing (k6)

This directory contains load testing scripts utilizing [Grafana k6](https://k6.io/) to benchmark the performance and reliability of the Wardseal Identity Platform.

## Prerequisites

1. You must have `k6` installed locally.
   * **macOS:** `brew install k6`
   * **Linux:** `sudo apt-get install k6`
   * **Docker:** `docker run --rm -i grafana/k6 run - <script.js>`
2. The Wardseal microservices must be running (e.g., via `docker compose up -d`).

## Test Scenarios

### Authentication Flow (`auth_flow.js`)

Simulates a localized "morning rush" (thousands of users attempting to access the OpenID configuration and login page concurrently).

* Targets: `authsvc`
* Evaluates: Read-heavy traffic, static configuration caching.

**Execution:**

```bash
k6 run tests/load/k6/auth_flow.js
```

### SCIM Provisioning Flow (`scim_provisioning.js`)

Simulates heavy writes from an upstream HR system or master directory performing bulk synchronization against Wardseal.

* Targets: `dirsvc` (and PostgreSQL)
* Evaluates: Write-heavy throughput, database locking, connection pooling.

**Execution:**

```bash
k6 run tests/load/k6/scim_provisioning.js
```

## Interpreting Results

When the scripts conclude, `k6` provides a summary metric block. Pay specific attention to:

* `http_req_duration`: Look at `p(95)` and `avg`.
  * **Goal:** `< 250ms` for Auth (Read-heavy). `< 400ms` for SCIM (Write-heavy).
* `errors`: Custom rate tracking the percentage of 5xx servers errors or timeouts.
  * **Goal:** Must remain below `1%` error rate during peak load. If higher, you may be hitting connection pool exhaustion in the Go applications or database.
