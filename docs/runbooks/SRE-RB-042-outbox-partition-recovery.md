# SRE-RB-042: Outbox Broker Partition Recovery & Split-Brain Remediation

| Document ID | SRE-RB-042 |
| :--- | :--- |
| **Title** | Transactional Outbox Broker Partition Failure, Consumer Group Rebalance, and Split-Brain Recovery |
| **Classification** | Critical Engineering & Operations Runbook |
| **Target Systems** | PostgreSQL 16+ (`transactional_outbox`), Redis 7+ / Apache Kafka / Redpanda Message Bus, `database/outbox.py`, `workers/sync_worker.py`, Neo4j 5+ Cluster |
| **Service Tier** | Tier-1 Core Financial Ingestion & Regulatory Surveillance |
| **Recovery Objectives** | **RTO:** < 15 minutes &nbsp;|&nbsp; **RPO:** 0 (Zero transaction event loss guaranteed by transactional outbox) |
| **Owner** | Site Reliability Engineering (SRE) & Distributed Platform Data Team |

---

## 1. Incident Overview & Failure Topology

The AML system employs an atomic **Transactional Outbox Pattern** to ensure strict dual-write consistency between PostgreSQL (the system of record) and downstream event consumers (Kafka/Redis brokers, the Neo4j graph cluster, and async neural scoring workers).

```
 ┌───────────────────────────────────────────────────────────────┐
 │                   PostgreSQL Primary Cluster                  │
 │                                                               │
 │  ┌───────────────────────┐         ┌───────────────────────┐  │
 │  │      transactions     │ ◄-ACID-►│  transactional_outbox │  │
 │  │   (Financial Ledger)  │         │  (Pending Event Log)  │  │
 │  └───────────────────────┘         └───────────┬───────────┘  │
 └────────────────────────────────────────────────┼──────────────┘
                                                  │
                 ┌────────────────────────────────┴───────────────────────────────┐
                 │                                                                │
     [Relay Pod A (Lease Active)]                                     [Relay Pod B (Crash/Rebalance)]
                 │                                                                │
                 ▼                                                                ▼
   ┌───────────────────────────┐                                    ┌───────────────────────────┐
   │ Broker Partition 0        │                                    │ Broker Partition 1        │
   │ (Tenant Hash: T1..T5)     │                                    │ (Tenant Hash: T6..T10)    │
   └─────────────┬─────────────┘                                    └─────────────┬─────────────┘
                 │                                                                │
                 ▼                                                                ▼
   ┌────────────────────────────────────────────────────────────────────────────────────────────┐
   │                     Neo4j Graph & Async Scoring Consumers (sync_worker.py)                 │
   └────────────────────────────────────────────────────────────────────────────────────────────┘
```

### When This Runbook Applies
This runbook must be invoked when:
1. **Outbox Relay Lag Alert Fires:** `AmlOutboxLagCritical` or `max(aml_outbox_lag_seconds) > 300s`.
2. **Broker Partition Rebalance Loop:** Kafka/Redpanda consumer groups trigger repeated rebalances, stalling downstream message consumption.
3. **Outbox Lease Starvation / Split-Brain:** Multiple outbox relay workers compete or crash during execution, leaving events locked in `status = 'PROCESSING'` with expired leases.
4. **Graph Desynchronization:** Transactions are successfully committed in PostgreSQL, but correspondent node-edge relationships fail to populate in Neo4j or lag by > 10,000 events.

---

## 2. Detection & Alerting Signatures

### Prometheus & Grafana Metrics
| Metric Name | Threshold | Severity | Description |
| :--- | :--- | :--- | :--- |
| `aml_outbox_unprocessed_total` | `> 5,000` for 5m | **P2 - HIGH** | Backlog of un-relayed events accumulating in Postgres. |
| `aml_outbox_unprocessed_total` | `> 25,000` for 2m | **P1 - CRITICAL** | Severe outbox relay blockage threatening RTO. |
| `aml_outbox_lag_seconds` | `> 300s` | **P1 - CRITICAL** | Age of oldest un-relayed outbox event exceeds 5 minutes. |
| `aml_outbox_dead_letter_total` | `> 10` in 5m | **P2 - HIGH** | Messages exhausting max retry threshold (poison pills). |
| `aml_queue_health_status` | `DEGRADED (2)` | **P2 - HIGH** | Elevated pending queue depth surfaced via `/api/v1/health`. |

---

## 3. Immediate Blast Radius Assessment

> [!IMPORTANT]
> **Transaction Ingestion Remains 100% Operational:** Because transaction ingestion writes atomically to `transactions` and `transactional_outbox` in the same PostgreSQL transaction, user-facing `/api/v1/transactions/ingest` requests **do not fail**.
> 
> **Downstream Impact:** Async graph cycle detection (Tarjan SCC), multi-hop taint propagation, and asynchronous rule evaluations are temporarily delayed until outbox relay processing resumes.

---

## 4. Phase 0: Pre-Flight Safety Checks

Before initiating active recovery, open an incident channel (`#incident-aml-outbox-sev1`) and execute read-only diagnostic queries:

```bash
# 1. Verify PostgreSQL Primary health and connection pool
psql "$PRIMARY_DB_URL" -c "SELECT pg_is_in_recovery(), count(*) FROM pg_stat_activity WHERE datname = 'aml_db';"

# 2. Check transactional outbox status breakdown
psql "$PRIMARY_DB_URL" -c "
SELECT status, count(*), min(created_at) as oldest, max(created_at) as newest
FROM transactional_outbox
GROUP BY status;
"

# 3. Inspect stale/orphaned leases (> 120s past lease expiration)
psql "$PRIMARY_DB_URL" -c "
SELECT count(*) AS orphaned_in_flight
FROM transactional_outbox
WHERE status = 'PROCESSING'
  AND lease_expires_at < NOW();
"
```

---

## 5. Step-by-Step Remediation Procedure

### Step 1: Quarantine & Halt Outbox Relay Pods (Prevent Split-Brain Writes)
To prevent competing workers from generating interleaved duplicate broker batches during state realignment, temporarily scale the relay workers to zero:

```bash
# For Kubernetes deployments:
kubectl scale deployment aml-outbox-relay --replicas=0 -n aml-production

# Verify all pods have terminated cleanly:
kubectl get pods -l app=aml-outbox-relay -n aml-production --watch
```

### Step 2: Reclaim Orphaned Leases in PostgreSQL
Clear expired lease tokens and reset stalled `PROCESSING` records back to `PENDING` so they can be picked up cleanly:

```sql
-- Connect to Primary Database
BEGIN;

-- 1. Unlock orphaned in-flight leases whose lease has expired
UPDATE transactional_outbox
SET status = 'PENDING',
    lease_id = NULL,
    lease_expires_at = NULL,
    updated_at = NOW()
WHERE status = 'PROCESSING'
  AND lease_expires_at < NOW();

-- 2. Inspect poison pills exceeding maximum retry threshold (5 retries)
UPDATE transactional_outbox
SET status = 'DEAD_LETTER',
    error_message = COALESCE(error_message, '') || ' [SRE-RB-042: Quarantined to DLQ during partition recovery]',
    updated_at = NOW()
WHERE status = 'PENDING'
  AND retry_count >= 5;

COMMIT;
```

### Step 3: Broker Consumer Group & Partition Health Verification
Ensure Kafka / Redpanda broker topic partitions are healthy and free from split-brain leader elections:

```bash
# If running Apache Kafka / Redpanda:
rpk cluster status
rpk topic describe aml.transactions.v1

# Inspect consumer group lag for the AML sync consumers:
rpk group describe aml-graph-sync-group
```

If partition leadership is partitioned or rebalancing indefinitely:
```bash
# Restart broker topic partition leaders gracefully:
rpk cluster partitions restart --topics aml.transactions.v1
```

### Step 4: Staged Re-engagement of Outbox Relay (Controlled Throttle)
Re-enable the outbox relay service with a single replica to drain the accumulated backlog under controlled throughput without overwhelming Kafka or Neo4j:

```bash
# Scale to 1 replica first:
kubectl scale deployment aml-outbox-relay --replicas=1 -n aml-production

# Monitor outbox relay logs in real-time:
kubectl logs -f deployment/aml-outbox-relay -n aml-production --tail=100
```

Confirm that the relay is claiming batches using the atomic CTE:
```
[INFO] Claimed batch of 250 outbox events with lease_id=rel-5a9b...
[INFO] Successfully relayed 250 events to broker. Committed status=COMPLETED.
```

### Step 5: Dual-Path Graph & Database Reconciliation
Once the backlog in `transactional_outbox` has dropped below 1,000 events, trigger the offline graph reconciler to backfill any missing Neo4j transactions:

```bash
# Run the idempotent graph sync worker in reconciliation-only mode:
kubectl exec -it deployment/aml-sync-worker -n aml-production -- \
    python workers/sync_worker.py --reconcile-window-hours=48 --batch-size=500
```

### Step 6: Scale Relay Deployment to Steady-State
Once queue depth returns to normal levels (`< 500`), restore full horizontal autoscaling:

```bash
# Scale back to multi-replica steady state:
kubectl scale deployment aml-outbox-relay --replicas=3 -n aml-production
```

---

## 6. Post-Recovery Validation Queries

Execute these verification checks before declaring the incident resolved:

```bash
# 1. Outbox backlog should be 0 or near-zero:
psql "$PRIMARY_DB_URL" -c "
SELECT status, count(*) 
FROM transactional_outbox 
WHERE created_at >= NOW() - INTERVAL '1 hour'
GROUP BY status;
"

# 2. Check health endpoint for QUEUE_HEALTH component:
curl -s http://localhost:8000/api/v1/health | jq .components.queue_health

# 3. Verify graph node-to-transaction parity in Neo4j:
python -c "
import asyncio
from database.postgres import get_async_db_conn
from database.neo4j_db import get_async_neo4j_driver

async def verify():
    async with get_async_db_conn() as conn:
        pg_count = await conn.fetchval('SELECT count(*) FROM transactions WHERE status = \'COMPLETED\';')
    
    driver = await get_async_neo4j_driver()
    async with driver.session() as session:
        result = await session.run('MATCH ()-[r:TRANSACTED]->() RETURN count(r) AS neo4j_count;')
        record = await result.single()
        neo4j_count = record['neo4j_count']
        
    print(f'PostgreSQL completed transactions: {pg_count}')
    print(f'Neo4j transacted relationships:   {neo4j_count}')
    diff = abs(pg_count - neo4j_count)
    print(f'Absolute Discrepancy: {diff} ({(diff / max(pg_count, 1)) * 100:.2f}%)')
    assert diff == 0 or (diff / max(pg_count, 1)) < 0.005, 'Parity divergence exceeds 0.5% threshold!'

asyncio.run(verify())
"
```

---

## 7. Escalation Contacts & Runbook Review Cycle

- **Lead SRE On-Call:** `#sre-oncall` (PagerDuty: `AML-Core-Platform`)
- **Database Administrator (DBA):** `#data-platform-dba`
- **FinCEN / Compliance Systems Officer:** `#aml-compliance-eng`
- **Review Cadence:** Semi-annual disaster recovery simulation or within 5 business days following any Sev-1 incident.
