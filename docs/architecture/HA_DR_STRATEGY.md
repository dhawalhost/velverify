# High Availability & Disaster Recovery Strategy

Wardseal Identity Platform is designed to operate as a strongly consistent, Tier-1 service. Because downstream applications rely on Wardseal for their authentication and authorization, an outage of the identity platform implies an outage for all connected applications. 

To meet the 99.99% uptime SLA required by modern enterprises, Wardseal employs a comprehensive High Availability (HA) and Disaster Recovery (DR) posture.

## 1. High Availability (HA)

High Availability emphasizes keeping the platform operational through localized failures (e.g., node deaths, rack failures, localized network drops) without noticeable downtime.

### Active/Active Kubernetes Deployments
Wardseal is deployed as stateless container workloads (`authsvc`, `dirsvc`, `govsvc`) managed by Kubernetes. We support an **Active/Active** topology within a single multi-zone cluster.
* **ReplicaSets:** All critical services run a minimum of 3 replicas.
* **Pod Anti-Affinity:** Kubernetes schedules service replicas across separate underlying hardware nodes and separate Availability Zones (AZs) by leveraging Pod Anti-Affinity rules.
* **Horizontal Pod Autoscaling (HPA):** To survive traffic spikes (e.g., morning login rushes), HPA automatically scales pods based on CPU and memory utilization metrics scraped by Prometheus.

### Database Redundancy
The state of the Wardseal platform (configurations, active sessions, and directory graphs) resides in PostgreSQL.
* **Multi-AZ Deployments:** Wardseal recommends deploying PostgreSQL in a Managed Service environment (e.g., AWS RDS Multi-AZ, Google Cloud SQL HA). 
* **Primary-Replica Failover:** In the event of primary database node failure, the managed service automatically promotes a standby read-replica to primary. The application utilizes a connection pooler (e.g., PgBouncer) to mask the underlying failover connection drops.

### Caching and Message Brokers
* **Redis Cluster:** Revocation lists and hot caches are placed in a Redis cluster to survive individual node failure.
* **NATS/Kafka:** Asynchronous webhooks and asynchronous connector operations rely on clustered brokers to ensure message delivery without dropping state.

---

## 2. Disaster Recovery (DR)

Disaster recovery assumes the worst-case scenario: the complete destruction or severe degradation of the primary geographic region (e.g., `us-east-1` goes completely offline). Wardseal relies heavily on GitOps principles to standardize recovery times.

### Recovery Objectives
* **RTO (Recovery Time Objective):** 2 Hours. The time it takes to spin up the entire cluster in the secondary region and resolve DNS routing.
* **RPO (Recovery Point Objective):** 5-15 Minutes. Determined by the asynchronous block replication intervals of the managed PostgreSQL provider.

### DR Reference Architecture (Active/Passive)

1. **Storage Replication:** The primary region's PostgreSQL instance asynchronously replicates its transactions (via cross-region read-replicas) to the designated secondary DR region.
2. **Configuration Synchronization (GitOps):** The desired state of the entire platform (Helm charts, ConfigMaps, Secrets mapping) lives in Git. ArgoCD continuously monitors this Git repository.
3. **Failover Execution:** When a disaster is declared:
   * **Promote DB:** Operations promotes the read-replica in the secondary region to act as the primary, writable database.
   * **Spin Up Compute:** ArgoCD is initialized in the secondary Kubernetes cluster. It immediately reads the configuration repository and spins up `authsvc`, `dirsvc`, and `govsvc` pods pointing them toward the newly promoted database.
   * **Failover DNS:** Update the global DNS load balancer (e.g., Route53 or Cloudflare) to route `auth.wardseal.com` from the dead region to the DR region ingress controllers.

For step-by-step failover execution instructions, please refer to `/docs/runbooks/DISASTER_RECOVERY.md`.
