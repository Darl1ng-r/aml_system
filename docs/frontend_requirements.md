# Frontend Requirements & UI Design Specifications
## AML Case Management Console

This document serves as the Frontend Product Requirements Document (PRD) and UI Design Guide for the **Compliance Case Management Console**. It outlines the app's purpose, core views, interactive components, and styling conventions.

---

## 1. Product Purpose
The frontend dashboard acts as the primary control center for compliance officers and fraud analysts. Its job is to turn massive streaming telemetry and complex graph relations into an actionable, intuitive workspace.

The app's primary goals are:
* **Minimize Review Time (Triage):** Present the most critical risk indicators upfront so analysts can make fast, accurate decisions.
* **Trace Transaction Flows Visually:** Map complex relational paths (e.g., money passing through multiple intermediary accounts/companies) using interactive network graphs.
* **Provide Defensible Decisions (XAI):** Show clear, plain-english reasons explaining why machine learning models flagged an transaction.

---

## 2. Core Views & Page Structures

### A. Dashboard Overview (Executive Hub)
Provides an aggregated snapshot of the organization's risk profile.

* **Metrics & KPIs:**
  * **Alert Summary Cards:** Total active cases, average time-to-resolution, escalation rate, and active cases by severity (Critical, High, Medium, Low).
  * **Alert Frequency Chart:** A line chart showing daily alerts generated vs. daily alerts resolved.
  * **Category Distribution:** A doughnut chart grouping alerts by rule category (e.g., *Sanction Match*, *Smurfing Ring*, *High-Value Out of Pattern*).
  * **Analyst Workload Leaderboard:** Shows active cases assigned to each team member.

### B. Alert Inbox (Triage Queue)
A high-performance data table displaying all pending investigations.

* **Key Columns:**
  * `Alert ID` (Unique hash / hyperlink)
  * `Threat Level` (Visual badges: Critical, High, Medium, Low)
  * `Risk Score` (Aggregate percentage of AI + Rule weights)
  * `Trigger Name` (e.g., `RAPID_FUNDS_MOVEMENT`, `PEP_MATCH`)
  * `Target Entity` (Account number / Customer name)
  * `Triggered At` (Timestamp)
  * `Assignee` (Compliance analyst name / dropdown to assign)
* **Interactive Operations:**
  * **Filter Bar:** Filter queue by risk level, assignee, status (`NEW`, `UNDER_INVESTIGATION`, `RESOLVED`), or trigger type.
  * **Search Bar:** Real-time query matching on name, account number, or transaction ID.
  * **Bulk Actions:** Select checkboxes to bulk-assign, bulk-dismiss, or bulk-escalate.

### C. Case Investigation Portal (Detailed View)
A split-screen investigation dashboard giving a 360-degree view of a single flagged case.

#### Left Column: Relational Ledger & Risk Explainability
1. **Entity Profile:** 
   * Name, KYC verification status (Green check / Red flag), risk tier, address, nationality, and connected corporate entity structure.
2. **Explainable AI (XAI) Panel:**
   * Dynamic waterfall or bar chart detailing the exact features contributing to the AI risk score (e.g., *40% Layering Pattern detected, 30% Account Age < 10 days, 20% Country Risk*).
3. **Transaction History Ledger:**
   * Sortable timeline ledger of all transactions. Flagged transactions are highlighted in red/orange alerts.

#### Right Column: Interactive Graph Map & Actions
1. **Interactive Network Graph (Vis.js / React Flow):**
   * Visualizes the flow of money. 
   * Nodes represent accounts, companies, or individuals.
   * Edges represent transactions (with hover tooltips showing amount, date, and currency).
   * **Node Context Menu:** Right-click a node to:
     * *Expand connections* (Fetch next tier of transaction partners from Neo4j).
     * *Copy account identifier*.
     * *Pin node to map*.
2. **Action Console:**
   * **Dismiss Alert:** Archive case as a "False Positive". A text area is required for justification notes.
   * **File SAR (Suspicious Activity Report):** Escalates the alert and auto-generates a FinCEN/EU-compliant SAR XML data file with pre-filled fields.

### D. Phonetic Sandbox (PEP/Sanctions Screening Tool)
A utility page for compliance officers to run ad-hoc searches.
* **Fields:** Target Name, Birth Date, Matching Threshold slider.
* **Results Table:** Shows potential spelling matches, matched database source (e.g., OFAC, Interpol, EU list), and phonetic score.

---

---

## 4. Key Libraries Recommended (Frontend)
* **Framework:** React.js (Vite template).
* **Styling:** TailwindCSS + Shadcn/ui (Radix Primitives).
* **Charts & Analytics:** Recharts (React-native SVG charts).
* **Graph Visualization:** Vis.js Network or React Flow (for node/edge interactions).
* **Icons:** Lucide React.
