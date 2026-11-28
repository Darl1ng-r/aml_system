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
from decimal import Decimal, ROUND_HALF_UP
from typing import Dict, Any, List

from database.postgres import get_async_db_conn

logger = logging.getLogger(__name__)


def _alert_usd_decimal(alert: Dict[str, Any]) -> Decimal:
    """Single authoritative USD amount extractor shared between XML compilation and DB storage."""
    raw = alert.get("amount_base_usd")
    if raw is None:
        raw = alert.get("amount")
    if raw is None:
        return Decimal("0.00")
    return Decimal(str(raw))


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
        # Sum exact unrounded Decimals first, then quantize once (100% parity with DB total_amount)
        exact_total_usd = Decimal("0")

        for alert in alerts:
            raw_amt_val = alert.get("amount")
            raw_amt = Decimal(str(raw_amt_val if raw_amt_val is not None else 0)).quantize(
                Decimal("0.01"), rounding=ROUND_HALF_UP
            )
            usd_exact = _alert_usd_decimal(alert)
            usd_display = usd_exact.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
            exact_total_usd += usd_exact

            report_el = ET.SubElement(reports, "SuspiciousActivityReport")
            report_el.set("report_id", str(alert["id"]))

            subject = ET.SubElement(report_el, "Subject")
            ET.SubElement(subject, "SenderAccount").text = str(alert.get("sender_acc", "UNKNOWN"))
            ET.SubElement(subject, "ReceiverAccount").text = str(alert.get("receiver_acc", "UNKNOWN"))

            tx_details = ET.SubElement(report_el, "TransactionDetails")
            ET.SubElement(tx_details, "Amount").text = f"{raw_amt:.2f}"
            ET.SubElement(tx_details, "Currency").text = str(alert.get("currency", "USD")).upper()
            ET.SubElement(tx_details, "AmountUSD").text = f"{usd_display:.2f}"
            ET.SubElement(tx_details, "ThreatLevel").text = str(alert.get("threat_level", "CRITICAL"))

            rule_name = str(alert.get("rule_name", "UNKNOWN"))
            threat_level = str(alert.get("threat_level", "CRITICAL"))
            notes = ET.SubElement(report_el, "ComplianceJustification")
            ET.SubElement(notes, "RuleTriggered").text = rule_name
            ET.SubElement(notes, "Narrative").text = (
                f"Automated STR filing record for alert {alert['id']} triggered by {rule_name} (threat={threat_level})."
            )

        total_amount_usd = exact_total_usd.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
        header.set("total_batch_amount", f"{total_amount_usd:.2f}")
        header.set("reporting_currency", "USD")

        # Format XML string
        xml_bytes = ET.tostring(root, encoding="utf-8")
        return xml_bytes.decode("utf-8")

    async def generate_batch(self, tenant_id: str) -> Dict[str, Any]:
        """
        Queries all un-batched CLOSED_SAR alerts using `FOR UPDATE OF a SKIP LOCKED` (T-05)
        to prevent concurrent duplicate batches, sums exposure strictly in USD (V-06),
        and seals them into an STR batch package.
        """
        async with get_async_db_conn(tenant_id=tenant_id) as conn:
            # Query pending un-batched alerts with row-level lock to prevent concurrent double-batching
            rows = await conn.fetch(
                """
                SELECT a.id, a.threat_level, a.rule_name,
                       t.amount, t.currency,
                       COALESCE(t.amount_base_usd, t.amount) AS amount_base_usd,
                       s.account_number AS sender_acc, r.account_number AS receiver_acc
                FROM alerts a
                JOIN transactions t ON a.transaction_id = t.id
                JOIN accounts s ON t.sender_account_id = s.id
                JOIN accounts r ON t.receiver_account_id = r.id
                WHERE a.status = 'CLOSED_SAR' AND a.str_batch_id IS NULL
                ORDER BY a.id ASC
                FOR UPDATE OF a SKIP LOCKED;
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

            # Compute SHA-256 Checksum & USD Decimal sum (identical sum-then-round helper as XML)
            checksum = hashlib.sha256(batch_xml.encode("utf-8")).hexdigest()
            total_amount_dec = sum(
                (_alert_usd_decimal(r) for r in alerts_data),
                Decimal("0"),
            ).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
            total_amount = float(total_amount_dec)

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
