# AML Sentinel — Multi-Region Cell-Sharding, Future `transactions` Partitioning & DR Blueprint (Stage 3)

## 1. Horizontal Sharding Trigger Policy (Anti-Premature-Sharding Guardrail)

AML Sentinel intentionally operates on a **single-cell vertical Primary + 2+ Streaming Read Replicas** architecture until empirical telemetry crosses **any** of the following hard triggers:

| Metric | Action Trigger | Current Stage 3 Mitigation |
|---|---|---|
| **Primary Write IOPS** | Sustained `> 60%` of largest vertical DB instance class (e.g. `db.r7g.16xlarge` / 64 vCPU) | PgBouncer transaction pooling + Async Queue Load Leveling (`aml.transactions.raw`) + weekly `transactional_outbox` partitioning |
| **Primary Storage / Hot Index RAM** | `transactions` active B-Tree index exceeds `50%` of Primary RAM (`~50M–100M+` rows) | Monthly `audit_log` + weekly `transactional_outbox` partitioning already active (Migration `040`); trigger `transactions` composite-FK partitioning (Section 3) |
| **Data Residency / Regional Sovereignty** | Institutional customer mandates EU/UK/ME data residency in-region | Deploy dedicated regional Cell (Section 2) |

---

## 2. Tenant-Key Cellular Architecture (Shared-Nothing Regional Cells)

Each **Cell** is an isolated, self-contained blast-radius boundary capable of serving `50,000` concurrent users:

```text
Global Edge (Cloudflare / Route53 Geo + Tenant Directory)
   │
   ├── Control Plane Cell Directory (tenant_id -> cell_id, read-only cached at Edge & Gateway)
   │
   ├── Cell A (cell-us-east-1)
   │     ├── Stateless FastAPI Tier (HPA 3..30 across >= 3 AZs, Adaptive Load Shedding)
   │     ├── HA PgBouncer -> PostgreSQL Primary + 2+ Streaming Standbys
   │     ├── State Redis (noeviction) + HA Cache Redis (allkeys-lfu)
   │     ├── 3-Node Redpanda (12p topics + DLQs) + KEDA Workers
   │     └── S3 WORM Evidence Bucket (5-yr BSA Object Lock)
   │
   └── Cell B (cell-eu-central-1)
         └── Identical isolated blast-radius stack (zero cross-cell writes)
```

### Application Routing Seam Already Wired
- `config.py` exposes `DEPLOYMENT_CELL_ID`, `DEPLOYMENT_REGION`, and `TENANT_CELL_ROUTING_JSON`.
- `observability/load_shedding.resolve_tenant_cell(tenant_id)` provides a zero-overhead deterministic lookup seam for API gateways, tenant migration tooling, and future cell-aware routing without adding multi-shard query overhead today.

---

## 3. Expand-and-Contract Blueprint for Future `transactions` Partitioning (`>= 50M` Rows)

Because 3 child tables currently reference `transactions(id)` via Foreign Keys (`alerts_transaction_id_fkey`, `ml_feedback_samples_transaction_id_fkey`, `ctr_filings_transaction_id_fkey`) and `transactions` carries a unique deduplication index on `(tenant_id, idempotency_key)`, partitioning `transactions` by `created_at` requires a disciplined 4-step **zero-downtime expand-and-contract rollout**:

1. **Expand Child Tables:** Add nullable `transaction_created_at TIMESTAMPTZ` to `alerts`, `ml_feedback_samples`, and `ctr_filings`, backfill in chunked batches (`10,000` rows/tx), then enforce `NOT NULL` via `CHECK (...) NOT VALID` + `VALIDATE CONSTRAINT`.
2. **Global Idempotency Authority:** Rely on the unpartitioned `idempotency_records` table (with `FORCE ROW LEVEL SECURITY` and `UNIQUE (tenant_id, idempotency_key)`) for cross-month deduplication while keeping per-partition `(tenant_id, idempotency_key, created_at)` uniqueness on `transactions`.
3. **Shadow Partitioned Table + Dual-Write Trigger:** Create `transactions_partitioned PARTITION BY RANGE (created_at)` with `PRIMARY KEY (id, created_at)`, backfill historical months via `pg_dump`/chunked copy, and verify row-count + `SUM(amount_base_usd)` parity.
4. **Atomic Swap:** Inside a sub-second `lock_timeout = '2s'` transaction, swap `transactions` ↔ `transactions_partitioned` and attach composite Foreign Keys `(transaction_id, transaction_created_at) REFERENCES transactions(id, created_at)`.

---

## 4. Quarterly DR, PITR & Replica-Promotion Failover Drill SOP

- **Recovery Objectives:** `RPO <= 5 minutes` (continuous WAL archiving + daily encrypted `aml-pitr-backup` CronJob), `RTO <= 15 minutes`.
- **Automated Verification:** `aml-pitr-restore-drill` CronJob executes `scripts/dr_failover_drill.py` quarterly (`0 4 1 1,4,7,10 *`), validating:
  1. `wal_level = replica` on Primary.
  2. Active streaming standbys and `replay_lag <= 2.0s`.
  3. Weekly `transactional_outbox` & monthly `audit_log` partition continuity.
  4. `FORCE ROW LEVEL SECURITY` enforcement across all core compliance tables.
- **GameDay Failover Procedure:** Documented in `docs/runbooks/SRE-RB-042-outbox-partition-recovery.md` (Section 2 — updated for Option A `aml-postgres-replica-0` / `aml-postgres-replica-1`).
