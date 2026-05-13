# Horizontal Scaling Strategy

## Overview
WardSeal is designed for high-availability and horizontal scalability. As the platform transitions to Phase 4 (Hardening & Scalability), all internal states and bottlenecks preventing multi-replica deployments have been addressed. This document outlines the strategy for scaling WardSeal services in a distributed environment (e.g., Kubernetes).

## 1. Stateless Architecture
To support arbitrary scaling (N replicas) without session stickiness:
- **Authorization Codes & Refresh Tokens**: Moved from in-memory caches to a distributed SQL backing store (`SQLAuthorizationCodeStore` and `SQLRefreshTokenStore`).
- **Rate Limiting**: The in-memory IP limiter has been replaced with a Redis-backed distributed rate limiter. This ensures global enforcement of rate limits across all nodes.
- **WebAuthn Sessions**: Transient session states for MFA challenges are backed by Redis, with safe fallbacks and runtime guardrails preventing startup if critical external stores are unreachable.

## 2. Edge Proxy and Ingress
- **Traefik**: Used as the primary edge proxy and ingress controller.
- **Routing**: API routing (`/api/v1/*`, `/t/*`, `/.well-known/*`) is entirely decoupled from the Admin UI static serving. 
- **Load Balancing**: Since services are stateless, round-robin or least-connection load balancing at the ingress level will evenly distribute the load without requiring sticky sessions.

## 3. Database Connection Pooling (PgBouncer)
As the number of Go application replicas increases, the number of direct database connections scales linearly ($Replicas \times MaxOpenConns$).
- **Challenge**: PostgreSQL connection exhaustion.
- **Strategy**: 
  - Deploy **PgBouncer** in transaction-pooling mode between the WardSeal services and the PostgreSQL database.
  - Tune the Go application `MaxIdleConns` and `MaxOpenConns` appropriately, offloading connection multiplexing to PgBouncer.
  - Size the database connection pool limit against the maximum expected replica count defined in the Horizontal Pod Autoscaler (HPA).

## 4. Caching Hot Paths
While services are stateless, fetching repetitive data (like JWKS keys or tenant configuration) from the database per request introduces latency.
- **Strategy**: Utilize a centralized Redis cache for read-heavy, rarely-mutated data. This ensures all replicas share the same cached state and avoids redundant database queries across the cluster.
- **Invalidation**: Cache invalidation is handled directly by deleting or updating the keys in Redis when a tenant configuration or policy changes, immediately reflecting the change across all replicas.

## 5. Kubernetes Autoscaling
- **HPA**: Horizontal Pod Autoscalers are configured for `authsvc`, `dirsvc`, and `govsvc` based on CPU and memory targets.
- **PDB**: Pod Disruption Budgets ensure a minimum number of available replicas during node drains or voluntary disruptions.
- **Probes**: Liveness and readiness probes are tuned to prevent traffic from hitting unready pods during scale-out events.

## 6. Disaster Recovery and Degradation
- **Redis Outages**: The rate limiter degrades safely if Redis is unreachable, falling back to strict defaults or in-memory tracking to prevent cascading failures.
- **Multi-Region**: Future scale-out plans include active-active multi-region deployments, requiring read-replicas for PostgreSQL and global Redis deployments.
