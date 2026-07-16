from fastapi import APIRouter, HTTPException, Depends, Response
from pydantic import BaseModel
from database.postgres import get_async_db_conn
from database.neo4j_db import get_async_neo4j_driver
from services.auth import get_current_user, RoleChecker
from services.rate_limiter import RateLimiter
import xml.etree.ElementTree as ET
# minidom import removed for XXE hardening
from datetime import datetime
import uuid
import json

import logging
logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/alerts", tags=["Alerts"])


class AlertAction(BaseModel):
    action: str # CLOSE_SAR or CLOSE_FALSE_POSITIVE
    justification: str
    sar_xml_generate: bool = False

@router.get("")
async def list_alerts(
    response: Response,
    page: int = 1,
    limit: int = 100,
    current_user: dict = Depends(RoleChecker(["ADMIN", "ANALYST", "AUDITOR"])),
    _rate_limit=Depends(RateLimiter(limit=60, window=60))
):
    try:
        tenant_id = current_user.get("tenant_id")
        async with get_async_db_conn(tenant_id=tenant_id) as conn:
            # Get total count of alerts (ignoring pagination)
            total_count = await conn.fetchval("SELECT COUNT(*) FROM alerts;")
            
            # Compute limit and offset
            offset = (page - 1) * limit
            
            rows = await conn.fetch(
                """
                SELECT a.id, a.rule_name, a.threat_level, a.ai_risk_score, a.explainability_payload, a.status, a.created_at,
                       t.amount, t.currency, t.timestamp,
                       s.account_number as sender, r.account_number as receiver
                FROM alerts a
                JOIN transactions t ON a.transaction_id = t.id
                JOIN accounts s ON t.sender_account_id = s.id
                JOIN accounts r ON t.receiver_account_id = r.id
                ORDER BY a.created_at DESC
                LIMIT $1 OFFSET $2;
                """,
                limit, offset
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
            
            # Expose and set custom total count header for frontend
            response.headers["X-Total-Count"] = str(total_count)
            response.headers["Access-Control-Expose-Headers"] = "X-Total-Count"
            return alerts
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to list alerts: {str(e)}")

@router.get("/{id}/graph")
async def get_alert_graph(
    id: str,
    current_user: dict = Depends(RoleChecker(["ADMIN", "ANALYST", "AUDITOR"])),
    neo4j_driver=Depends(get_async_neo4j_driver),
    _rate_limit=Depends(RateLimiter(limit=60, window=60))
):
    try:
        alert_uuid = uuid.UUID(id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid alert ID format")

    try:
        tenant_id = current_user.get("tenant_id")
        async with get_async_db_conn(tenant_id=tenant_id) as conn:
            row = await conn.fetchrow(
                """
                SELECT s.account_number, r.account_number
                FROM alerts a
                JOIN transactions t ON a.transaction_id = t.id
                JOIN accounts s ON t.sender_account_id = s.id
                JOIN accounts r ON t.receiver_account_id = r.id
                WHERE a.id = $1;
                """,
                alert_uuid
            )
            if not row:
                raise HTTPException(status_code=404, detail="Alert not found")
            sender, receiver = row[0], row[1]
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database query failed: {str(e)}")

    nodes = []
    edges = []
    node_ids = set()
    edge_ids = set()

    def add_node(node_id, label, node_type, props):
        if node_id not in node_ids:
            node_ids.add(node_id)
            nodes.append({
                "id": node_id,
                "label": label,
                "type": node_type,
                "properties": props
            })

    try:
        # Query Neo4j to build network graph surrounding sender/receiver and company structures/UBOs
        query = """
        MATCH (a:Account) WHERE a.account_number IN [$sender, $receiver]
        OPTIONAL MATCH (a)-[t:TRANSFERS_TO]-(other:Account)
        OPTIONAL MATCH (a)-[b:BELONGS_TO]->(c:Company)
        OPTIONAL MATCH (p:Person)-[u:OWNS_UBO]->(c)
        RETURN a, t, other, b, c, p, u LIMIT 50;
        """
        async with neo4j_driver.session() as session:
            result = await session.run(query, sender=sender, receiver=receiver)
            async for record in result:
                # Process core account nodes
                a_node = record.get("a")
                if a_node:
                    add_node(a_node.element_id, a_node.get("account_number"), "Account", dict(a_node))

                # Process other account nodes
                other_node = record.get("other")
                if other_node:
                    add_node(other_node.element_id, other_node.get("account_number"), "Account", dict(other_node))

                # Process transaction edges
                t_edge = record.get("t")
                if t_edge and a_node and other_node:
                    edge_id = f"tx_{t_edge.element_id}"
                    if edge_id not in edge_ids:
                        edge_ids.add(edge_id)
                        edges.append({
                            "id": edge_id,
                            "source": t_edge.start_node_element_id,
                            "target": t_edge.end_node_element_id,
                            "type": "TRANSFERS_TO",
                            "properties": {
                                "amount": t_edge.get("amount"),
                                "timestamp": t_edge.get("timestamp"),
                                "status": t_edge.get("status")
                            }
                        })

                # Process company nodes
                c_node = record.get("c")
                if c_node:
                    add_node(c_node.element_id, c_node.get("name"), "Company", dict(c_node))

                # Process belongs_to edge
                b_edge = record.get("b")
                if b_edge and a_node and c_node:
                    edge_id = f"belongs_{b_edge.element_id}"
                    if edge_id not in edge_ids:
                        edge_ids.add(edge_id)
                        edges.append({
                            "id": edge_id,
                            "source": b_edge.start_node_element_id,
                            "target": b_edge.end_node_element_id,
                            "type": "BELONGS_TO",
                            "properties": {}
                        })

                # Process UBO Person nodes
                p_node = record.get("p")
                if p_node:
                    add_node(p_node.element_id, p_node.get("name"), "Person", dict(p_node))

                # Process owns_ubo edge
                u_edge = record.get("u")
                if u_edge and p_node and c_node:
                    edge_id = f"owns_{u_edge.element_id}"
                    if edge_id not in edge_ids:
                        edge_ids.add(edge_id)
                        edges.append({
                            "id": edge_id,
                            "source": u_edge.start_node_element_id,
                            "target": u_edge.end_node_element_id,
                            "type": "OWNS_UBO",
                            "properties": {
                                "percentage": u_edge.get("percentage")
                            }
                        })

        return {"nodes": nodes, "edges": edges}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Neo4j query failed: {str(e)}")

@router.post("/{id}/action")
async def resolve_alert(
    id: str, 
    payload: AlertAction, 
    current_user: dict = Depends(RoleChecker(["ADMIN", "ANALYST"])),
    _rate_limit=Depends(RateLimiter(limit=30, window=60))
):
    if payload.action not in ["CLOSE_SAR", "CLOSE_FALSE_POSITIVE"]:
        raise HTTPException(status_code=400, detail="Invalid action. Must be CLOSE_SAR or CLOSE_FALSE_POSITIVE")

    status = "CLOSED_SAR" if payload.action == "CLOSE_SAR" else "CLOSED_FALSE_POSITIVE"

    try:
        tenant_id = current_user.get("tenant_id")
        async with get_async_db_conn(tenant_id=tenant_id) as conn:
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

            # Update Alert Status and assign the resolving officer
            await conn.execute(
                "UPDATE alerts SET status = $1, assigned_officer_id = $2 WHERE id = $3;",
                status, uuid.UUID(current_user["id"]), uuid.UUID(id)
            )

        # Output structured audit trail log
        logger.info(
            f"AUDIT LOG: Analyst '{current_user['username']}' (ID: {current_user['id']}, Role: {current_user['role']}) "
            f"resolved Alert {id} with Action '{payload.action}' -> Status: '{status}'."
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

    # Format XML beautifully (hardening against XXE by avoiding minidom parsing)
    ET.indent(root, space="  ")
    return ET.tostring(root, encoding="utf-8").decode("utf-8")
