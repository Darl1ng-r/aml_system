# Professional Technical Assessment
## AML Compliance & Transaction Monitoring System

---

## Executive Summary

This is a **genuinely impressive and architecturally ambitious project**. For a compliance-grade financial system in early development, the design decisions show a strong understanding of enterprise-level concerns. The multi-database polyglot architecture, asynchronous processing pipeline, and Kafka-compatible streaming integration are all industry-correct choices for this domain. That said, there are meaningful gaps in security hardening, ML depth, and production-readiness that would need to be addressed before any form of pilot or production deployment.

---

## 1. Frontend

### ✅ Strengths
- The redesigned dashboard now has **genuinely distinct page purposes** aligned to the `frontend_requirements.md` PRD: the Executive Hub for operations overview, the Alert Inbox for triage, and the Phonetic Sandbox for ad-hoc compliance investigations.
- The **Plus Jakarta Sans typography** and warm beige palette are a major step up — professional-grade corporate design language.
- **Sandbox mock mode** is a smart DX decision. The dashboard degrades gracefully and stays demo-able when all databases are offline.
- The **interactive SVG network graph** in the Case Investigation Portal is a solid concept for a product at this stage. Clicks reveal node properties.
- SHAP attribution bar charts are well-designed for analyst explainability.

### ⚠️ Issues
- **The ML model is essentially a hand-coded sigmoid formula**, not a real ML model. The "SHAP attributions" are not actual SHAP values — they're just proportional contributions of the activation terms. This is fundamentally misleading for a regulatory system where explainability must be auditable and honest. Risk: non-compliance with EU AI Act transparency requirements.
- The SVG graph is **fully hardcoded static nodes**. The money-flow graph should be rendering real data from the Neo4j graph database, not a fixed SVG layout. As-is, Tab 2's graph looks good but shows the same Alice/ACME/Bob topology regardless of which case you open.
- The frontend calls `http://localhost:8000` hardcoded — not configurable. This means the dashboard would break the moment it's deployed behind a CDN, reverse proxy, or different port.
- No **pagination** on the triage inbox table. If a bank has 5,000 active alerts, the browser renders all of them.

---

## 2. Middleware & API Layer (FastAPI)

### ✅ Strengths
- **FastAPI is the right choice** here. Async-native, excellent OpenAPI docs generation, Pydantic schema validation, and strong ecosystem compatibility.
- **Router structure** is clean and well-organized: `/api/v1/onboard`, `/api/v1/transactions`, `/api/v1/alerts`, `/api/v1/screening`.
- **Pydantic v2 with `pydantic-settings`** for config is a good modern pattern.
- Background task publishing via `BackgroundTasks.add_task(publish_transaction, ...)` for the Redpanda stream is exactly right — the HTTP response is not blocked waiting for Kafka acknowledgement.
- The `generate_sar_xml()` method using `xml.etree.ElementTree` produces valid structured XML. The FinCEN-compatible format is a thoughtful touch.

### ⚠️ Issues
- **`allow_origins=["*"]` is a critical security issue**. This CORS configuration allows any website on the internet to make authenticated API requests to your endpoints from a browser. In production, this would need to be locked to specific allowed origins.
- **There is no authentication or authorization layer at all.** Any client with network access can call any API endpoint — POST a transaction, query all alerts, or close a SAR. For a compliance system, this is a showstopper. Minimum requirements would be JWT/Bearer tokens with role-based access (analyst vs. admin vs. read-only auditor).
- **There is no rate limiting.** The ingest endpoint can be called indefinitely without throttling.
- The **`/dashboard` route reads the HTML file using `open()` on every request**, bypassing FastAPI's static file caching. This is fine for development, but wasteful. StaticFiles already mounted would handle this more efficiently.
- **`import json` inside a function call** (line 94 of `transactions.py`) — minor but it should be at the top of the file.

---

## 3. Backend & Data Architecture

### ✅ Strengths — Polyglot Persistence is Correct
This is the most mature design decision in the system. Using the right database for each use case:
| Database | Purpose | Verdict |
|---|---|---|
| **PostgreSQL** | Accounts, Transactions, Alerts (relational ledger) | ✅ Correct |
| **Neo4j** | UBO/corporate ownership graphs, money flow topology | ✅ Correct |
| **Redis** | 24-hour velocity counters (sorted sets via ZADD/ZRANGEBYSCORE) | ✅ Correct |
| **Elasticsearch** | Fuzzy phonetic sanctions name matching | ✅ Correct |
| **Redpanda** | Scored event streaming (Kafka-compatible) | ✅ Correct |

The Redis velocity tracking using **sorted sets (ZADD/ZRANGEBYSCORE)** to implement a 24-hour sliding window counter is technically excellent. This is exactly how financial velocity tracking is done at production scale.

The Neo4j UBO onboarding using `MERGE` with proper Cypher relationships (`BELONGS_TO`, `OWNS_UBO`) shows understanding of the graph data model.

### ⚠️ Issues
- **Dual PostgreSQL clients: `pg8000` and `asyncpg`.** The codebase simultaneously uses a hand-rolled sync connection pool (`SimplePGPool` via `pg8000`) and a properly async `asyncpg` pool. The `pg8000` pool is never actually used — the routers all use `get_async_db_conn()` from `asyncpg`. The `SimplePGPool` is dead code adding confusion and startup errors. Remove it entirely.
- **Database startup errors are swallowed silently.** If PostgreSQL fails to initialize, the app starts anyway and routers return 500 errors. For a compliance platform, the app should fail fast on startup rather than serving error responses.
- **No database migrations framework.** There is no Alembic, Flyway, or equivalent tool managing schema versioning. This makes schema evolution risky and non-reproducible across environments.
- **The Neo4j graph is only written to during corporate onboarding** — there's no code that updates it when transactions occur. The transaction ingestion pipeline publishes to Redpanda, but there's no consumer written that processes those events and creates `SENT`/`RECEIVED` edges in Neo4j. This means the graph stays empty for transactional data and the graph visualization in the frontend has no real data source.
- **Hardcoded credentials in `docker-compose.yml` and `config.py`** (`postgrespassword`, `passwordpassword`). These should be environment variables only, never in committed config files.
- **Elasticsearch has `xpack.security.enabled=false`**. This means the sanctions database has no access controls whatsoever.

---

## 4. ML & Risk Scoring

### ✅ Strengths
- The **logistic sigmoid normalization pattern** is technically sound — it correctly maps a raw score to a bounded `[0.0, 1.0]` probability-like output.
- The bias tuning (`bias = -1.8`) to ensure baseline transactions score ~0.05–0.15 is a sophisticated calibration decision. This is how production fraud models prevent overwhelming analysts with false positives.
- The attribution proportional decomposition gives a crude but presentable XAI narrative.

### ❌ Critical Weaknesses
- **This is not a machine learning model.** It has no training data, no training loop, no feature encoding, no cross-validation, no evaluation metrics, and no concept drift handling. It's a deterministic mathematical formula that will produce identical outputs for identical inputs forever.
- **A real AML risk model needs:** historical labeled transaction data, trained gradient boosting or neural network, precision/recall/AUC evaluation, F1 tuning for the specific compliance threshold, regular retraining on new fraud patterns.
- **The SHAP values are not SHAP values.** SHAP (SHapley Additive exPlanations) requires a trained model. Using the word "SHAP" in regulatory documentation for a surrogate formula could create legal exposure.
- **No false positive rate analysis.** The threshold of `ai_score >= 0.75` for triggering a hold is arbitrary. In production, this would be calibrated against actual fraud rate to balance analyst workload against missed catches.

---

## 5. Performance

### ✅ Strengths
- The asyncpg pool (`min_size=5, max_size=20`) is well-configured for I/O bound workloads.
- Redis pipeline with `ZADD`/`ZRANGEBYSCORE` is the correct O(log n) velocity tracking pattern.
- `BackgroundTasks` correctly offloads Redpanda publishing from the response critical path.

### ⚠️ Issues
- **Transaction ingest makes 3 sequential database round trips** per request: (1) fetch sender, (2) fetch receiver, (3) velocity count — all in separate awaits. These could be parallelized or combined into a single query.
- **`AMLAnomalyModel()` is instantiated fresh on every transaction POST request** (line 63, `transactions.py`). The model weights should be a module-level singleton.
- **The Levenshtein distance function in `screening.py` is O(n×m)** with a pure Python nested loop. For high-throughput environments, this should use `rapidfuzz` or `jellyfish` (C extensions). At 1,000 names/sec this becomes a bottleneck.
- **No caching layer on the sanctions screening results.** The same name being screened multiple times hits Elasticsearch and runs Levenshtein each time. Results should be cached in Redis with a TTL.
- No connection **keep-alive** configuration for the Elasticsearch client.

---

## 6. Security

| Risk | Severity | Description |
|---|---|---|
| No authentication | 🔴 CRITICAL | Every API endpoint is publicly accessible |
| `allow_origins=["*"]` | 🔴 CRITICAL | Open CORS allows cross-site API exploitation |
| Hardcoded credentials | 🔴 CRITICAL | DB passwords in committed config files |
| Elasticsearch unauthenticated | 🔴 CRITICAL | Sanctions data is fully open |
| No rate limiting | 🟠 HIGH | API can be enumerated or DoS'd |
| No input sanitization on account numbers | 🟠 HIGH | SQL injection via crafted account numbers |
| SAR XML uses `minidom` which is vulnerable to XXE attacks | 🟡 MEDIUM | XML parsing risk |
| No audit log of analyst actions | 🟡 MEDIUM | Who closed a SAR? When? Not recorded. |
| `timestamp` accepted as raw string from client | 🟡 MEDIUM | No strict validation, timezone manipulation possible |

---

## 7. Scalability

### Design is Scalable — Execution Needs Work
The **architecture is horizontally scalable**: stateless FastAPI app instances behind a load balancer, Redis for distributed shared state, Redpanda for decoupled event streaming, and Neo4j/PostgreSQL/Elasticsearch as separately scalable services. **This is the right blueprint.**

### Gaps
- **Single Redpanda node** (`--smp 1`) is a single point of failure. Production requires a 3-node cluster with replication.
- **No Redpanda consumer exists** in this codebase. Events are published to the topic but nothing processes them. The graph database update pipeline is incomplete.
- **No Kubernetes manifests, Helm charts, or cloud deployment config.** The docker-compose is useful for local dev but doesn't translate to production.
- **No horizontal pod autoscaling config** for the FastAPI app.
- **No read replicas** configured for PostgreSQL under read-heavy reporting workloads.

---

## Overall Rating

| Dimension | Score | Notes |
|---|---|---|
| Architecture Design | 8.5/10 | Strong polyglot decisions, correct async patterns |
| Code Quality | 6.5/10 | Clean structure but dual PG clients, dead code, missing auth |
| Frontend UX | 7.5/10 | Great visual design, but graph data is hardcoded |
| ML / Risk Engine | 3.5/10 | Deterministic formula, not real ML, SHAP misrepresented |
| Security | 2.0/10 | No auth, open CORS, hardcoded secrets — unacceptable for prod |
| Performance | 6.0/10 | Async correctly used, but several easy wins missed |
| Scalability | 7.0/10 | Blueprint is scalable; Kafka consumer and replicas missing |
| **Overall** | **5.9/10** | Strong foundation, significant hardening required |

---

## Top 5 Priorities Before Any Pilot Deployment

1. **Add JWT authentication + RBAC** to every endpoint immediately.
2. **Replace the "ML model" with a real scikit-learn or XGBoost model** trained on labeled data.
3. **Write the Redpanda consumer** that processes scored transactions and updates Neo4j edges.
4. **Remove all hardcoded credentials** and move them to `.env` / secrets vault.
5. **Wire the SVG graph to real Neo4j query results** so it shows actual money flow topology per case.
