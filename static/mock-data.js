/**
 * Standalone Mock Fixture Dataset for Simulated Evaluation Mode
 * =============================================================
 * Separated from production bundle to eliminate mock PII and realistic synthetic records
 * from production client payload delivery (Finding #21).
 */

window.AML_MOCK_DATA = {
    mockAlerts: [
        {
            alert_id: "aml-2026-04471",
            short_id: "4471",
            title: "Wire transfer — $9,480.00 → offshore holding entity",
            rule_name: "STRUCTURING_THRESHOLD",
            threat_level: "CRITICAL",
            ai_risk_score: 0.92,
            status: "NEW",
            created_at: new Date(Date.now() - 5400000).toISOString(),
            assignee: "analyst.compliance",
            threshold_proximity: "98.7%",
            channel: "Wire — SWIFT",
            counterparty_jurisdiction: "KY",
            prior_30d_txns: 6,
            account_tenure: "14 mo",
            rules_triggered_count: 3,
            model_version: "v4.2.1",
            transaction: {
                amount: 9480.00,
                currency: "USD",
                timestamp: new Date(Date.now() - 3600000).toISOString(),
                sender: "Synthesized Customer A",
                sender_account: "****4821",
                receiver: "Offshore Entity Ltd",
                receiver_account: "KY99201122"
            },
            rules_triggered: [
                { code: "R-STRUCT-04", desc: "— Transaction is within 5% of CTR reporting threshold", critical: true },
                { code: "R-VELOC-11", desc: "— Multiple similar-value transfers in trailing 30 days" },
                { code: "R-GEO-02", desc: "— Destination jurisdiction flagged high-risk per current watchlist" }
            ],
            explainability: {
                attributions: {
                    "threshold_proximity": 0.48,
                    "jurisdiction_risk": 0.32,
                    "velocity_30d": 0.12
                }
            },
            entity: {
                name: "Synthesized Customer A",
                nationality: "Cayman Islands / US",
                tier: "Critical Tier",
                connected: "Offshore Entity Ltd",
                customer_since: "Jul 2025",
                occupation: "Import/export, self-empl.",
                pep: "No",
                sanctions: "None",
                adverse_media: "1 hit"
            },
            linked_entities: [
                { name: "Associated Sibling", relation: "Shared address · sibling", avatar: "AS" },
                { name: "Offshore Entity Ltd", relation: "High-risk counterparty", avatar: "OE", high_risk: true }
            ],
            prior_alerts: [
                { title: "Structuring pattern", date: "Aug 21", status: "closed" }
            ],
            ledger: [
                { date: "Today", direction: "OUTGOING", partner: "Offshore Entity Ltd", amount: "$9,480.00", risk: "92%" }
            ]
        },
        {
            alert_id: "aml-2026-04472",
            short_id: "4472",
            title: "High-value round sum remittance — $14,200.00 → Foreign Shell Co",
            rule_name: "ROUND_SUM_SURGE",
            threat_level: "CRITICAL",
            ai_risk_score: 0.88,
            status: "NEW",
            created_at: new Date(Date.now() - 7200000).toISOString(),
            assignee: "analyst.compliance",
            threshold_proximity: "142%",
            channel: "Wire — FEDWIRE",
            counterparty_jurisdiction: "PA",
            prior_30d_txns: 4,
            account_tenure: "9 mo",
            rules_triggered_count: 2,
            model_version: "v4.2.1",
            transaction: {
                amount: 14200.00,
                currency: "USD",
                timestamp: new Date(Date.now() - 5400000).toISOString(),
                sender: "Synthesized Customer B",
                sender_account: "****1192",
                receiver: "Offshore Shell S.A.",
                receiver_account: "PA11223344"
            },
            rules_triggered: [
                { code: "R-HIGH-01", desc: "— Transfer exceeds threshold and triggers SAR reporting", critical: true },
                { code: "R-SHELL-09", desc: "— Counterparty entity registered in secrecy haven" }
            ],
            explainability: {
                attributions: {
                    "amount_anomaly": 0.54,
                    "counterparty_secrecy": 0.34
                }
            },
            entity: {
                name: "Synthesized Customer B",
                nationality: "Hungary / US",
                tier: "High Risk Tier",
                connected: "Offshore Shell S.A.",
                customer_since: "Oct 2025",
                occupation: "Commercial Real Estate",
                pep: "No",
                sanctions: "None",
                adverse_media: "Clean"
            },
            linked_entities: [
                { name: "Associated Customer A", relation: "Related sender", avatar: "AA", high_risk: true },
                { name: "Offshore Shell S.A.", relation: "Offshore beneficiary", avatar: "OS", high_risk: true }
            ],
            prior_alerts: [
                { title: "Rapid movement of funds", date: "Aug 10", status: "closed" }
            ],
            ledger: [
                { date: "Today", direction: "OUTGOING", partner: "Offshore Shell", amount: "$14,200.00", risk: "88%" }
            ]
        }
    ]
};
