# WardSeal Deployment & Infrastructure Handbook
# ============================================

This document outlines the architecture and workflows for deploying the WardSeal platform across various environments, from local development to production.

## 1. Architectural Overview
WardSeal is a microservices-based platform designed for high availability and scalability.

- **Infrastructure Layer**: PostgreSQL (Persistent Storage), Redis (Cache/Bus), Traefik (Edge Gateway).
- **Service Layer**: Go-based services (Auth, Directory, Governance, etc.) communicating via REST and internal GRPC.
- **UI Layer**: React-based Single Page Applications (SPAs) served via Nginx.

## 2. Local Development (The DevOps 2.0 Way)
We use a modular Docker Compose setup to minimize resource usage while maintaining environment parity.

### Prerequisites
- Docker & Docker Compose (v2.20+)
- Go 1.24+
- OpenSSL

### First-Time Setup
```bash
make setup
```
This generates development keys and initializes your `.env` file.

### Running the Stack
- **Full Stack (Build everything)**: `make dev`
- **Infrastructure Only (Run apps on host)**: `make infra-up`
- **Stop Everything**: `make down`
- **Deep Clean (Remove volumes)**: `make clean`

## 3. Community Edition (CE) - Zero-Conf
For users who want to run WardSeal without building from source.

```bash
make community
```
This pulls pre-built images from `ghcr.io/dhawalhost/wardseal-*`.

## 4. Production Deployment Best Practices
WardSeal follows the **Cloud Native Maturity Model**.

### 1. Hardened Containers
- Multi-stage builds reduce image size.
- Non-root users (`wardseal`) prevent privilege escalation.
- Read-only root filesystems are supported.

### 2. Configuration Management
- All secrets should be injected via environment variables (use Vault or AWS Secret Manager).
- Never commit `.env` files.

### 3. Kubernetes (Staging/Production)
We utilize Helm for orchestration.
- **Charts Location**: `deploy/charts/wardseal`
- **CI/CD Pipeline**: Automated builds and deployments via GitHub Actions.

## 5. Troubleshooting & Debugging
### Streaming Logs
```bash
make logs
```

### Interactive Debugging
You can run services with the Delve debugger. 
*(Workflow: `make debug-svc NAME=authsvc`)*

## 6. CI/CD Operations
WardSeal uses GitHub Actions for the following:
- **Linting**: Go (golangci-lint).
- **Testing**: Unit & Integration (using infra compose).
- **Security**: Container scanning and dependency checks.
- **Release**: Automated image tagging and pushing to GHCR.
