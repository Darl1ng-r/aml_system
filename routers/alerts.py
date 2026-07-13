from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from database.postgres import get_async_db_conn
import xml.etree.ElementTree as ET
from xml.dom import minidom
from datetime import datetime
import uuid
import json

router = APIRouter(prefix="/api/v1/alerts", tags=["Alerts"])


class AlertAction(BaseModel):
    action: str # CLOSE_SAR or CLOSE_FALSE_POSITIVE
    justification: str
    sar_xml_generate: bool = False

@router.get("")
async def list_alerts():
    try:
        async with get_async_db_conn() as conn:
            rows = await conn.fetch(
                """
                SELECT a.id, a.rule_name, a.threat_level, a.ai_risk_score, a.explainability_payload, a.status, a.created_at,
                       t.amount, t.currency, t.timestamp,
                       s.account_number as sender, r.account_number as receiver
                FROM alerts a
                JOIN transactions t ON a.transaction_id = t.id
                JOIN accounts s ON t.sender_account_id = s.id
                JOIN accounts r ON t.receiver_account_id = r.id
                ORDER BY a.created_at DESC;
                """
            )
            alerts = []
            for row in rows:
                alerts.append({
                    "alert_id": str(row[0]),
                    "rule_name": row[1],
                    "threat_level": row[2],
                    "ai_risk_score": float(row[3]) if row[3] else None,
                    "explainability": json.loads(row[4]) if isinstance(row[4], str) else row[4],
                    "status": row[5],
                    "created_at": row[6].isoformat(),
                    "transaction": {
                        "amount": float(row[7]),
                        "currency": row[8],
                        "timestamp": row[9].isoformat(),
                        "sender": row[10],
                        "receiver": row[11]
                    }
                })
            return alerts
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to list alerts: {str(e)}")

@router.post("/{id}/action")
async def resolve_alert(id: str, payload: AlertAction):
    if payload.action not in ["CLOSE_SAR", "CLOSE_FALSE_POSITIVE"]:
        raise HTTPException(status_code=400, detail="Invalid action. Must be CLOSE_SAR or CLOSE_FALSE_POSITIVE")

    status = "CLOSED_SAR" if payload.action == "CLOSE_SAR" else "CLOSED_FALSE_POSITIVE"

    try:
        async with get_async_db_conn() as conn:
            # Check alert exists
            alert = await conn.fetchrow(
                """
                SELECT a.id, a.rule_name, a.threat_level, a.ai_risk_score,
                       t.amount, t.currency, t.timestamp,
                       s.account_number, s.owner_name,
                       r.account_number, r.owner_name
                FROM alerts a
                JOIN transactions t ON a.transaction_id = t.id
                JOIN accounts s ON t.sender_account_id = s.id
                JOIN accounts r ON t.receiver_account_id = r.id
                WHERE a.id = $1;
                """,
                uuid.UUID(id)
            )
            if not alert:
                raise HTTPException(status_code=404, detail="Alert not found")

            # Update Alert Status
            await conn.execute(
                "UPDATE alerts SET status = $1 WHERE id = $2;",
                status, uuid.UUID(id)
            )

        # Generate SAR XML if requested
        sar_xml = None
        if payload.action == "CLOSE_SAR" and payload.sar_xml_generate:
            sar_xml = generate_sar_xml(alert, payload.justification)

        return {
            "alert_id": id,
            "status": status,
            "justification": payload.justification,
            "sar_xml": sar_xml
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Alert update failed: {str(e)}")

def generate_sar_xml(alert_data, justification: str) -> str:
    """
    Generates a regulatory FinCEN-compatible Suspicious Activity Report XML payload
    """
    alert_id, rule_name, threat, score, amt, curr, ts, s_acc, s_owner, r_acc, r_owner = alert_data

    # Build XML structure
    root = ET.Element("SuspiciousActivityReport")
    
    header = ET.SubElement(root, "Header")
    ET.SubElement(header, "ReportID").text = str(alert_id)
    ET.SubElement(header, "FilingDate").text = datetime.now().strftime("%Y-%m-%d")
    
    summary = ET.SubElement(root, "ActivitySummary")
    ET.SubElement(summary, "Reason").text = rule_name
    ET.SubElement(summary, "ThreatLevel").text = threat
    ET.SubElement(summary, "RiskScore").text = str(score)
    ET.SubElement(summary, "Description").text = justification

    transaction = ET.SubElement(root, "Transaction")
    ET.SubElement(transaction, "Amount").text = str(amt)
    ET.SubElement(transaction, "Currency").text = curr
    ET.SubElement(transaction, "Timestamp").text = ts.isoformat()

    sender = ET.SubElement(transaction, "Sender")
    ET.SubElement(sender, "AccountNumber").text = s_acc
    ET.SubElement(sender, "OwnerName").text = s_owner

    receiver = ET.SubElement(transaction, "Receiver")
    ET.SubElement(receiver, "AccountNumber").text = r_acc
    ET.SubElement(receiver, "OwnerName").text = r_owner

    # Format XML beautifully
    xml_str = ET.tostring(root, encoding="utf-8")
    reparsed = minidom.parseString(xml_str)
    return reparsed.toprettyxml(indent="  ")
