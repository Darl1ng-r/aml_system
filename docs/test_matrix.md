# AML Compliance System Regulatory Test Matrix

Documented test matrix for regulatory compliance audits (FinCEN, FATF, OCC BSA/AML guidelines).

## 1. Unit & Algorithm Test Coverage Matrix

| Test Domain | Target Module | Test Cases & Assertions | Regulatory Requirement |
|---|---|---|---|
| **Anomaly Scoring** | `services/isolation_forest.py` | Outlier score > normal score, BST `c(n)` average path length calculation, boundary score normalization `[0.0, 1.0]`. | FinCEN Model Risk Management (SR 11-7) |
| **Sanctions Fuzzy Matching** | `routers/screening.py` | RapidFuzz Levenshtein similarity ratio, exact match (1.0), fuzzy match (≥0.75), case-insensitivity. | OFAC Sanctions List Screening Guidelines |
| **SAR XML Generation** | `routers/alerts.py` | FinCEN BSA E-Filing XML schema validation, root tag `SuspiciousActivityReport`, Header, ActivitySummary, Transaction, Sender, Receiver tags. | FinCEN Electronic SAR Filing Specifications |
| **E-Filing Signature** | `services/fincen_efiling.py` | Explicit HMAC-SHA256 digest calculation against RFC 4231 test vectors. | BSA E-Filing Security & Authenticity Standard |
| **Distributed Rate Limiting** | `services/rate_limiter.py` | Redis ZSET sliding window pipeline (`ZREMRANGEBYSCORE`, `ZADD`, `ZCARD`, `PEXPIRE`), HTTP 429 status code on burst exceedance, fail-open resilience. | NIST SP 800-53 SC-5 Denial of Service Protection |
| **TLS & Startup Security** | `services/tls_manager.py` | Strict certificate file existence assertions (`cert.crt`, `key.key`, `ca.crt`), refuse startup on invalid cert configuration. | FIPS 140-2 / NIST SP 800-52 Transport Layer Security |
| **Multi-Tenant Isolation** | `routers/screening.py` | PostgreSQL Row-Level Security (RLS) policies, parameterization of `tenant_id` in fallback queries (`WHERE tenant_id = $1 OR tenant_id IS NULL`). | FFIEC Multi-Tenant Data Scoping Requirements |

---

## 2. Automated Test Execution Commands

```powershell
# Run full compliance test suite
.\.venv\Scripts\python.exe -m pytest -v
```

---

## 3. Continuous Integration & Deployment (CI)

Automated testing is executed on every GitHub commit and pull request via `.github/workflows/ci.yml`.
