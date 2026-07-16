"""
Automated STR (Suspicious Transaction Report) Batch Filing Engine
==================================================================
Aggregates individual SAR/STR alerts into standardized regulatory batch containers
for FinCEN, FIU, and global regulatory submission schedules.

Features:
  - Aggregates all un-batched CLOSED_SAR alerts.
  - Generates XML Batch Filing Container (<BatchSuspiciousActivityReport>).
  - Computes batch checksums (SHA-256) and total risk exposure totals.
  - Maintains audit trail of batch submission state in PostgreSQL.
"""

import hashlib
import json
import logging
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Dict, Any, List

from database.postgres import get_async_db_conn

logger = logging.getLogger(__name__)


class STRBatchEngine:
    """Engine responsible for compiling, validating, and sealing regulatory STR batch packages."""

    @staticmethod
    def construct_batch_xml(batch_id: str, alerts: List[Dict[str, Any]]) -> str:
        """Compiles individual alert SAR payloads into a single multi-record Batch Filing Container."""
        root = ET.Element("BatchSuspiciousActivityReport")
        root.set("batch_id", batch_id)
        root.set("generated_at", datetime.now(timezone.utc).isoformat())
        root.set("total_records", str(len(alerts)))

        header = ET.SubElement(root, "BatchHeader")
        ET.SubElement(header, "FilingAgency").text = "FinCEN / FIU Central Repository"
        ET.SubElement(header, "BatchID").text = batch_id
        ET.SubElement(header, "TransmitterTIN").text = "999887766"

        reports = ET.SubElement(root, "Reports")
        total_amount = 0.0

        for alert in alerts:
            total_amount += float(alert.get("amount", 0.0))
            report_el = ET.SubElement(reports, "SuspiciousActivityReport")
            report_el.set("report_id", str(alert["id"]))

            subject = ET.SubElement(report_el, "Subject")
            ET.SubElement(subject, "SenderAccount").text = str(alert.get("sender_acc", "UNKNOWN"))
            ET.SubElement(subject, "ReceiverAccount").text = str(alert.get("receiver_acc", "UNKNOWN"))

            tx_details = ET.SubElement(report_el, "TransactionDetails")
            ET.SubElement(tx_details, "Amount").text = str(alert.get("amount", 0.0))
            ET.SubElement(tx_details, "Currency").text = str(alert.get("currency", "USD"))
            ET.SubElement(tx_details, "ThreatLevel").text = str(alert.get("threat_level", "CRITICAL"))

            notes = ET.SubElement(report_el, "ComplianceJustification")
            ET.SubElement(notes, "RuleTriggered").text = str(alert.get("rule_name", "UNKNOWN"))

        header.set("total_batch_amount", f"{total_amount:.2f}")

        # Format XML string
        xml_bytes = ET.tostring(root, encoding="utf-8")
        return xml_bytes.decode("utf-8")

    async def generate_batch(self, tenant_id: str) -> Dict[str, Any]:
        """
        Queries all un-batched CLOSED_SAR alerts and compiles them into a sealed STR batch package.
        """
        async with get_async_db_conn(tenant_id=tenant_id) as conn:
            # Query pending un-batched alerts
            rows = await conn.fetch(
                """
                SELECT a.id, a.threat_level, a.rule_name, t.amount, t.currency,
                       s.account_number AS sender_acc, r.account_number AS receiver_acc
                FROM alerts a
                JOIN transactions t ON a.transaction_id = t.id
                JOIN accounts s ON t.sender_account_id = s.id
                JOIN accounts r ON t.receiver_account_id = r.id
                WHERE a.status = 'CLOSED_SAR' AND a.str_batch_id IS NULL
                ORDER BY a.created_at ASC;
                """
            )

            if not rows:
                return {
                    "batch_id": None,
                    "count": 0,
                    "message": "No pending un-batched STR reports found for compilation."
                }

            alerts_data = [dict(row) for row in rows]
            batch_id = f"STR-BATCH-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:8].upper()}"
            batch_xml = self.construct_batch_xml(batch_id, alerts_data)

            # Compute SHA-256 Checksum
            checksum = hashlib.sha256(batch_xml.encode("utf-8")).hexdigest()
            total_amount = sum(float(r["amount"]) for r in rows)

            # Save batch to PostgreSQL str_batches table
            await conn.execute(
                """
                INSERT INTO str_batches (id, tenant_id, record_count, total_amount, payload_xml, checksum, status)
                VALUES ($1, $2, $3, $4, $5, $6, 'GENERATED');
                """,
                batch_id, tenant_id, len(rows), total_amount, batch_xml, checksum
            )

            # Mark alerts as batched
            alert_ids = [r["id"] for r in rows]
            await conn.execute(
                """
                UPDATE alerts
                SET str_batch_id = $1
                WHERE id = ANY($2::uuid[]);
                """,
                batch_id, alert_ids
            )

            logger.info(
                f"[STR Batch Engine] Sealed batch {batch_id} with {len(rows)} records. "
                f"Total Amount: ${total_amount:,.2f} | Checksum: {checksum[:12]}..."
            )

            return {
                "batch_id": batch_id,
                "record_count": len(rows),
                "total_amount": total_amount,
                "checksum": checksum,
                "status": "GENERATED",
                "generated_at": datetime.now(timezone.utc).isoformat()
            }


str_batch_engine = STRBatchEngine()
