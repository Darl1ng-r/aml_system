# AML Compliance & Transaction Monitoring Platform

A high-performance Anti-Money Laundering (AML) transaction monitoring and compliance platform. The system combines real-time rule engine execution, behavioral profiling, and graph analytics to identify suspicious financial flows, structure evaders, and sanctions matches.

---

## Technical Architecture

The platform follows a hybrid pipeline architecture combining synchronous transaction ingestion, real-time risk scoring, and asynchronous graph/database synchronization.

### Tech Stack
- **Web Engine**: FastAPI (Python 3.10+)
- **Relational Database**: PostgreSQL (for ledger, accounts, alerts, and historical transaction baselines)
- **Graph Database**: Neo4j (for corporate UBO mapping, circular flows, fan-in/fan-out topologies, and intermediary detection)
- **Cache / Store**: Redis (for 24h sliding window structuring/velocity state caching)
- **Search Engine**: Elasticsearch (for fuzzy sanctions/KYC screening matching)
- **Message Broker**: Redpanda / Kafka (for asynchronous decoupled synchronization)

---

## Core Detection Features

### Phase 1: Rules Engine
Exposes a deterministic, configurable compliance rule engine (`rules_config.json`):
1. **Large Transaction Detection**: Flags transactions strictly greater than a configurable threshold.
2. **Structuring (Smurfing)**: Detects sliding 24-hour windows where multiple transactions individually under the threshold sum to greater than the threshold.
3. **Velocity Monitoring**: Calculates daily transaction count and amount spikes against a historical average and standard deviation (Z-score > threshold).
4. **Rapid Movement of Funds**: Monitors accounts where inbound funds are immediately (e.g. within 10 minutes) transferred outbound at a high ratio (e.g. >90%).
5. **Dormant Account Activation**: Identifies long inactive accounts suddenly executing high-value transactions.
6. **Geographic & Sanctions Risk**: Flags transactions involving high-risk SWIFT BICs or individuals fuzzy-matched to sanctions list.

### Phase 2: Behavioral Analytics
Profiles historical transaction characteristics to detect anomalies:
- Automated recalculation of customer behavior baselines (daily/weekly frequencies, average/median amounts, top merchants, channels, countries, and devices).
- System-wide Isolation Forest training to detect structural anomalies.
- Blended Dynamic Scorer that combines Rule triggers, Logistic Regression ML anomaly scores, and Behavioral Z-score deviations.

### Phase 3: Graph Intelligence
Maps transactions to a Neo4j topology to trace relationship risks:
- **Strongly Connected Components (SCC)**: Detects circular loop transaction patterns (cycles of size $\ge$ 2) using Tarjan's algorithm.
- **Fan-In / Fan-Out Topologies**: Pinpoints potential money mules (many sources transferring to a single account) and layering distributors (one source distributing to many targets).
- **Transit Intermediaries**: Measures Brandes' Betweenness Centrality to rank the primary middleman transit nodes in the network.

---

## Getting Started

### 1. Prerequisites & Services
Start the required relational, graph, caching, and search services using Docker Compose:
```bash
docker-compose up -d
```

### 2. Python Environment Setup
Install dependencies and activate the virtual environment:
```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

### 3. Database Initialization & Seeding
Initialize schema structures and seed initial compliance entities (tenants, accounts, sanctions list index):
```bash
.venv\Scripts\python.exe scripts/init_db.py
```

### 4. Running the Platform
Launch the ingestion server locally:
```bash
.venv\Scripts\python.exe -m uvicorn main:app --host 0.0.0.0 --port 8000
```
Visit `http://localhost:8000/dashboard` or `http://localhost:8000/docs` to interact with the analyst console.

---

## Verification & Testing

The platform is backed by component tests and a full integration suite.

### Running Component Unit Tests
Verify Phase 1, Phase 2, and Phase 3 components individually:
```bash
# 1. Rules Engine
.venv\Scripts\python.exe tests/test_aml_rules.py

# 2. Behavioral Analytics
.venv\Scripts\python.exe tests/test_behavioral_analysis.py

# 3. Graph/Network Intelligence
.venv\Scripts\python.exe tests/test_network_analysis.py
```

### Running the End-to-End Integration Flow
Ensure the FastAPI app server is running, then verify the full compliance lifecycles (screening, corporate UBO onboarding, transaction scoring, case management alerts resolution, SAR XML filing, and Neo4j async sync):
```bash
.venv\Scripts\python.exe tests/test_flow.py
```
