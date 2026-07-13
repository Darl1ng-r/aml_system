Here is the comprehensive implementation plan for **SitePulse**, designed as a scalable, secure, and production-ready system.  
  
**1. High-Level Architecture**  
The system uses an **Event-Driven, Microservices-based Architecture** to ensure that high-volume IoT data streams do not lock up or slow down the user dashboard. [1, 2]  
[Physical IoT/Low-Current Devices] (CCTV, Access Control, Temperature)  
│ (MQTT / TLS 1.3)  
▼  
[EMQX Broker] (Message Ingestion)  
│  
▼  
[Go/Node.js Ingestion Service] (Decouples data stream from DB)  
│  
├──► [TimescaleDB] (Time-series data: Temps, Logs)  
│  
▼  
[Redis Cache] (Stores "Latest State" of devices for instant UI load)  
▲  
│ (WebSockets / WSS)  
[NestJS / .NET Real-time Service] ◄──► [React.js Admin Dashboard]  
  
**2. Technology Stack**  
  
**Ingestion Broker:** **EMQX** or **Mosquitto** (Handles thousands of concurrent MQTT connections).  
**Backend & APIs:** **.NET 8/9 Core** (for enterprise alignment with Optimiza) or **NestJS** (for rapid TypeScript development).  
**Real-time Communication:** **SignalR** (.NET) or **Socket.io** (Node.js) using WebSockets over TLS.  
**Frontend:** **React.js** + **Vite** + **TailwindCSS** + **Shadcn/ui** (UI components) + **Recharts** (Data visualization).  
**Containerization:** **Docker** and **Docker Compose** (for local setup and easy handover). [3, 4, 5, 6, 7]  
  
**3. Database Design**  
IoT data requires two types of storage: **Relational** (for device registry) and **Time-Series** (for rapid telemetry streams). We will use **PostgreSQL with the TimescaleDB extension**. [8, 9, 10, 11, 12]  
**devices Table (Standard Relational)**  
Stores the metadata of the hardware installed by Optimiza's Low Current team.  
CREATE TABLE devices (  
id UUID PRIMARY KEY DEFAULT gen_random_uuid(),  
serial_number VARCHAR(100) UNIQUE NOT NULL,  
device_type VARCHAR(50) NOT NULL, _-- 'CCTV', 'THERMAL', 'ACCESS_CONTROL'_  
location_building VARCHAR(100) NOT NULL,  
location_floor INT NOT NULL,  
status VARCHAR(20) DEFAULT 'OFFLINE',  
created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()  
);  
**telemetry_logs Table (TimescaleDB Hypertable)**  
Stores millions of raw data points without lagging.  
CREATE TABLE telemetry_logs (  
time TIMESTAMP WITH TIME ZONE NOT NULL,  
device_id UUID REFERENCES devices(id),  
metric_name VARCHAR(50) NOT NULL, _-- 'temperature', 'motion_detected', 'door_state'_  
metric_value_numeric NUMERIC,  
metric_value_string VARCHAR(255)  
);  
  
_-- Convert to hypertable for automatic time-based partitioning_  
SELECT create_hypertable('telemetry_logs', 'time');  
  
**4. API & Real-Time Contract**  
**REST Endpoints (Management)**  
  
GET /api/v1/devices - Fetch all registered infrastructure hardware.  
POST /api/v1/devices - Provision a new Low-Current device on-site.  
GET /api/v1/devices/{id}/analytics - Fetch historical time-series data for charts.  
**WebSocket (WSS) Events (Real-time Stream)**  
  
**Subscribe Topic (Client):** room:building_A (Client joins a specific building's stream).  
**Server Emit:** telemetry:update  
{  
"device_id": "8f3b9c2a-...",  
"type": "THERMAL",  
"metric": "temperature",  
"value": 24.5,  
"timestamp": "2026-07-11T11:45:00Z"  
}  
  
**5. Step-by-Step Development Milestones**  
**Phase 1: The Mock Data Simulator (Day 1)**  
Since you don't have physical hardware, write a simple 50-line Node.js or Python script that uses an MQTT library (mqtt.js or paho-mqtt) to connect to your broker and send random temperature fluctuations and fake "motion detected" events every 2 seconds. [13]  
**Phase 2: Ingestion & Backend (Day 2)**  
  
Set up your Docker Compose file to spin up PostgreSQL and your MQTT broker.  
Build your backend API. Create an internal MQTT subscriber service that listens to incoming hardware data, saves it to PostgreSQL, and simultaneously pushes it to a Redis cache. [14, 15]  
**Phase 3: Frontend & Real-time UI (Day 3-4)**  
  
Build a clean, dark-mode React dashboard.  
Create a grid of cards representing Optimiza's hardware units (e.g., "Server Room AC", "Main Gate Camera").  
Connect the frontend to your WebSocket gateway. Watch the UI cards flash or update numerical values in real-time without refreshing the page. [16, 17]  
  
**6. Security Framework**
To make this enterprise-grade for Optimiza's government clients, bake these security layers directly into your plan:  
  
**Transport Security:** All MQTT traffic must use **MQTTS** (MQTT over TLS/SSL port 8883), and all web traffic must use **HTTPS/WSS**. [18, 19]  
**Device Authentication:** Devices cannot just publish data freely. The MQTT broker must validate connections via a unique device token passed in the password field during the MQTT handshake. [20]  
**User Authorization:** Implement Role-Based Access Control (RBAC). A "Technician" role can only view temperature logs, while an "Admin" role can change device configurations via the REST API. [21, 22]


**Core Architecture & Tech Stack**  
**1. Real-Time Data Streaming & Ingestion**  
Your software must ingest millions of financial transactions per second without data loss.  
  
**Apache Kafka / Redpanda**: Use for distributed message queuing and log storage.  
**Apache Flink / Spark Streaming**: Use for complex event processing (CEP) and real-time computation.  
**2. Databases & Storage Strategy**  
AML software relies on different data shapes, requiring a polyglot persistence architecture.  
  
**Neo4j / Amazon Neptune**: Graph databases are essential to uncover hidden networks, shell companies, and layered transactions.  
**PostgreSQL / CockroachDB**: Use for highly secure, ACID-compliant relational data like user profiles and audit logs.  
**Elasticsearch / OpenSearch**: Use for ultra-fast fuzzy matching against global PEP and sanction lists.  
**3. AI & Analytics Core**  
Static rules are easily bypassed; your engine needs machine learning to detect anomalies.  
  
**Python (Scikit-learn, PyTorch)**: Use to train models on behavioral profiling and risk scoring.  
**Graph Neural Networks (GNNs)**: Use to automatically flag suspicious clusters of accounts.  
  
**Key Modules to Build**  
[ Data Ingestion API ] ──> [ Risk Engine (AI + Rules) ] ──> [ Graph Analysis Core ] ──> [ Alert & Case Manager ]  
  
**KYC/KYB Onboarding Engine**: Integrates with global government registries to verify identity documents, corporate structures, and Ultimate Beneficial Owners (UBO).  
**Sanction & PEP Screening**: A deterministic matching module that checks names against lists (like OFAC or UN) using advanced phonetics (e.g., Double Metaphone) to handle spelling variations.  
**Transaction Monitoring System (TMS)**: A hybrid engine combining deterministic rules (e.g., "Flag transactions over $10,000") with probabilistic AI models.  
**Case Management Dashboard**: A secure UI where compliance officers investigate flagged alerts, view network graphs, and auto-generate Suspicious Activity Reports (SARs).  
  
**Initial Development Steps**  
  
**Define Your Niche**: Do not compete with giants like LexisNexis everywhere. Focus on a specific pain point, like instant AML compliance for Web3/Crypto, or automated UBO tracking for mid-sized real estate firms.  
**Procure Clean Data Feeds**: You cannot build screening tools without data. Partner with premium risk intelligence data aggregators (like Dow Jones Risk & Compliance or World-Check) to feed your screening database via API.  
**Prioritize Security Certifications**: Financial institutions will not look at your software without strict compliance. Design the architecture from day one to pass **SOC 2 Type II**, **ISO 27001**, and regional data privacy laws (**GDPR / CCPA**).
