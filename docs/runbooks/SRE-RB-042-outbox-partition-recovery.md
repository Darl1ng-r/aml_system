# SRE-RB-042: Transactional Outbox, PostgreSQL & Redis Recovery Runbook

- **Service:** AML Sentinel Core Platform (`aml-fastapi-app`, `aml-outbox-relay`, `aml-postgres`, `aml-redis`, `aml-redpanda`)
- **Namespace:** `aml-system`
- **Severity:** SEV-1 / SEV-2 (Compliance Event Delivery & Availability)
- **Primary Metrics:** `outbox_pending_events`, `http_requests_total`, `transactions_ingested_total`, `transactions_scored_total`

---

## 1. Outbox Backlog / Relay Stall Recovery

### Symptoms
- Prometheus gauge `outbox_pending_events` > `500` for > 2 minutes.
- `aml-outbox-relay` pods logging broker publish errors or stuck `PROCESSING` leases.

### Diagnostic Commands
```bash
# 1. Check dedicated Outbox Relay Deployment & pod logs
kubectl get pods -n aml-system -l app=aml-outbox-relay
kubectl logs -n aml-system -l app=aml-outbox-relay --tail=100

# 2. Inspect transactional_outbox backlog & expired leases in PostgreSQL primary
kubectl exec -n aml-system aml-postgres-0 -- psql -U postgres -d aml_db -c "
SELECT status, COUNT(*), MIN(created_at) AS oldest_event
FROM transactional_outbox
GROUP BY status;
"

# 3. Verify Redpanda broker health & topic partitions
kubectl exec -n aml-system aml-redpanda-0 -- rpk cluster health
kubectl exec -n aml-system aml-redpanda-0 -- rpk topic describe aml.transactions.raw
```

### Remediation Steps
1. **Requeue Stuck `PROCESSING` Leases (> 5 min old):**
   `OutboxRelayEngine` automatically recovers leases older than 300s (`headers->>'leased_at'`). To expedite manual recovery:
   ```bash
   kubectl exec -n aml-system aml-postgres-0 -- psql -U postgres -d aml_db -c "
   UPDATE transactional_outbox
   SET status = 'PENDING'
   WHERE status = 'PROCESSING'
     AND (headers->>'leased_at')::timestamptz < NOW() - INTERVAL '5 minutes';
   "
   ```
2. **Replay Dead-Lettered (`FAILED`) Events After Broker Recovery:**
   ```bash
   kubectl exec -n aml-system aml-postgres-0 -- psql -U postgres -d aml_db -c "
   UPDATE transactional_outbox
   SET status = 'PENDING', retry_count = 0, last_error = NULL
   WHERE status = 'FAILED' AND created_at > NOW() - INTERVAL '24 hours';
   "
   ```
3. **Scale Outbox Relay Replicas Safely (`SKIP LOCKED` safe):**
   ```bash
   kubectl scale deployment/aml-outbox-relay -n aml-system --replicas=4
   kubectl rollout status deployment/aml-outbox-relay -n aml-system --timeout=120s
   ```

---

## 2. PostgreSQL Primary Failover Procedure

1. Verify replication lag on `aml-postgres-1` before promoting:
   ```bash
   kubectl exec -n aml-system aml-postgres-1 -- psql -U postgres -d aml_db -c "SELECT pg_is_in_recovery(), pg_last_wal_receive_lsn(), pg_last_wal_replay_lsn();"
   ```
2. Promote standby `aml-postgres-1` to primary if `aml-postgres-0` is unrecoverable:
   ```bash
   kubectl exec -n aml-system aml-postgres-1 -- pg_ctl promote -D /var/lib/postgresql/data/pgdata
   ```
3. Patch `aml-postgres-primary` Service selector to `aml-postgres-1` and restart PgBouncer (`kubectl rollout restart deployment/aml-pgbouncer -n aml-system`).
4. **Long-Term HA:** Migrate `aml-postgres` StatefulSet to CloudNativePG or Patroni for automated leader election.

---

## 3. Redis Outage Recovery

- **Expected Behavior:**
  - `RateLimiter(fail_closed=True)` returns `HTTP 503` in `production` (no silent bypass).
  - `_verify_token_version()` automatically falls back to PostgreSQL `users.token_version` (zero revocation bypass).
  - Distributed locks fall back to PostgreSQL `resource_locks` table.
- **Recovery:**
  ```bash
  kubectl get pods -n aml-system -l app=aml-redis
  kubectl logs -n aml-system aml-redis-0 --tail=100
  kubectl rollout restart statefulset/aml-redis -n aml-system
  ```
