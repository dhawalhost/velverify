# Runbook: Regional Disaster Recovery (Failover)

This runbook outlines the required steps to complete a regional failover of the Wardseal Identity Platform from the Primary Region to the designated Disaster Recovery (DR) Region.

> **Target RTO:** 2 Hours  
> **Target RPO:** 5-15 Minutes

## Prerequisites
* Executive approval has been given to declare a regional disaster and enact a failover.
* You possess Cloud Provider (AWS/GCP) administrative access in the secondary region.
* You possess DNS Provider administrative access.
* The GitOps deployment repository (`wardseal-config`) is accessible.

## Phase 1: Database Promotion

1. Navigate to your Cloud Provider's Database Management Console (e.g., AWS RDS) in the **Secondary (DR) region**.
2. Locate the existing Cross-Region Read Replica for the `wardseal-postgres` cluster.
3. Execute the `Promote to Primary` action on the read-replica.
4. Note the newly promoted Primary Database Endpoint URL. 

## Phase 2: Configuration Update

The Kubernetes clusters resolve configuration from Git.

1. Clone or Branch the configuration repository.
2. Edit the target environmental overrides file:
   **File:** `deploy/charts/wardseal/values-production.yaml`
   ```yaml
   database:
     host: <NEW_PROMOTED_DR_DATABASE_URL>
   ```
3. Commit and push the changes to the `main` branch.

## Phase 3: Infrastructure Bootup

1. Access the secondary Kubernetes cluster via your local `kubectl` context.
2. Since the DR compute is kept cold (0 replicas) or is freshly provisioned: Ensure that ArgoCD is installed in the namespace. 
3. Apply the ArgoCD Application manifest:
   ```bash
   kubectl apply -f deploy/argocd/application.yaml
   ```
4. Verify deployment health:
   ```bash
   argocd app get wardseal
   kubectl get pods -n wardseal-prod
   ```
5. All pods (`authsvc`, `dirsvc`, `govsvc`) should successfully reach `Running` state.

## Phase 4: DNS Switchover

1. Ensure the ingress controllers in the DR region are reporting a healthy external IP or LoadBalancer canonical name.
2. Navigate to your DNS provider (e.g., Cloudflare, Route53, NS1).
3. Update the `A` or `CNAME` records for the unified endpoints to point to the DR region's load balancer:
   * `auth.wardseal.com`
   * `api.wardseal.com`
   * `console.wardseal.com`
4. Time to live (TTL) expiry will enforce the traffic swap to the new region. 

## Phase 5: Verification

1. Attempt to login to the Admin UI using a known administrator credential.
2. Spot check that standard user logins via OpenID Connect (OIDC) resolve successfully and issue valid JWTs.
3. Monitor the Prometheus/Grafana dashboards in the new region for 5xx errors or unusual connection latency patterns regarding the database.
