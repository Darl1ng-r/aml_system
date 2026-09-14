from fastapi import APIRouter, HTTPException, Depends, Response, BackgroundTasks, Query
from fastapi.responses import StreamingResponse, HTMLResponse
from pydantic import BaseModel
from database.postgres import get_async_db_conn, get_async_db_read_conn
from database.neo4j_db import get_async_neo4j_driver
from services.auth import get_current_user, RoleChecker, enforce_tenant_data_scope
from services.rate_limiter import RateLimiter
import xml.etree.ElementTree as ET
# minidom import removed for XXE hardening
from datetime import datetime, timezone
import uuid
import json
import io
import csv
from typing import List

import logging
logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/alerts", tags=["Alerts"])


from pydantic import Field, field_validator
from observability.sanitizer import sanitize_text

class AlertAction(BaseModel):
    action: str = Field(..., pattern=r"^(CLOSE_SAR|CLOSE_FALSE_POSITIVE)$")
    justification: str = Field(..., min_length=3, max_length=2000)
    sar_xml_generate: bool = False

    @field_validator("justification", mode="before")
    @classmethod
    def sanitize_justification(cls, v: str) -> str:
        return sanitize_text(v)

@router.get("")
async def list_alerts(
    response: Response,
    page: int = Query(default=1, ge=1),
    limit: int = Query(default=50, ge=1, le=100),
    search: str | None = Query(default=None, max_length=200),
    severity: str | None = None,
    status_filter: str | None = None,
    current_user: dict = Depends(RoleChecker(["ADMIN", "ANALYST", "AUDITOR"])),
    _rate_limit=Depends(RateLimiter(limit=60, window=60))
):
    try:
        tenant_id = enforce_tenant_data_scope(current_user)
        async with get_async_db_read_conn(tenant_id=tenant_id) as conn:
            where_clauses = ["a.tenant_id = $1"]
            params = [tenant_id]
            param_idx = 2

            if severity and severity.upper() != "ALL":
                where_clauses.append(f"a.threat_level = ${param_idx}")
                params.append(severity.upper())
                param_idx += 1

            if status_filter and status_filter.upper() != "ALL":
                where_clauses.append(f"a.status = ${param_idx}")
                params.append(status_filter.upper())
                param_idx += 1

            if search and search.strip():
                term = f"%{search.strip()}%"
                where_clauses.append(
                    f"(s.account_number ILIKE ${param_idx} OR s.owner_name ILIKE ${param_idx} "
                    f"OR r.account_number ILIKE ${param_idx} OR r.owner_name ILIKE ${param_idx} "
                    f"OR a.rule_name ILIKE ${param_idx})"
                )
                params.append(term)
                param_idx += 1

            where_sql = " AND ".join(where_clauses)

            count_query = f"""
                SELECT COUNT(*)
                FROM alerts a
                JOIN transactions t ON a.transaction_id = t.id
                JOIN accounts s ON t.sender_account_id = s.id
                JOIN accounts r ON t.receiver_account_id = r.id
                WHERE {where_sql};
            """
            total_count = await conn.fetchval(count_query, *params)
            
            offset = (page - 1) * limit
            
            query = f"""
                SELECT a.id, a.rule_name, a.threat_level, a.ai_risk_score, a.explainability_payload, a.status, a.created_at,
                       t.amount, t.currency, t.timestamp,
                       s.account_number as sender, r.account_number as receiver,
                       COALESCE(u.username, 'Unassigned') as assignee,
                       s.owner_name as sender_name, r.owner_name as receiver_name,
                       s.risk_category as sender_risk_tier, s.created_at as account_created_at,
                       t.channel, t.country
                FROM alerts a
                JOIN transactions t ON a.transaction_id = t.id
                JOIN accounts s ON t.sender_account_id = s.id
                JOIN accounts r ON t.receiver_account_id = r.id
                LEFT JOIN users u ON a.assigned_officer_id = u.id
                WHERE {where_sql}
                ORDER BY a.created_at DESC
                LIMIT ${param_idx} OFFSET ${param_idx + 1};
            """
            rows = await conn.fetch(query, *params, limit, offset)
            
            alerts = []
            for row in rows:
                def _to_iso(val):
                    if val is None:
                        return None
                    return val.isoformat() if hasattr(val, "isoformat") else str(val)

                alerts.append({
                    "alert_id": str(row[0]),
                    "rule_name": row[1],
                    "threat_level": row[2],
                    "ai_risk_score": float(row[3]) if row[3] else None,
                    "explainability": json.loads(row[4]) if isinstance(row[4], str) else row[4],
                    "status": row[5],
                    "created_at": _to_iso(row[6]),
                    "assignee": row[12],
                    "sender_risk_tier": row[15] if len(row) > 15 and row[15] else "STANDARD",
                    "account_created_at": _to_iso(row[16]) if len(row) > 16 else None,
                    "transaction": {
                        "amount": float(row[7]),
                        "currency": row[8],
                        "timestamp": _to_iso(row[9]),
                        "sender": row[10],
                        "receiver": row[11],
                        "sender_name": row[13] if len(row) > 13 and row[13] else row[10],
                        "receiver_name": row[14] if len(row) > 14 and row[14] else row[11],
                        "channel": row[17] if len(row) > 17 and row[17] else "Wire Transfer",
                        "country": row[18] if len(row) > 18 and row[18] else "DOMESTIC"
                    }
                })
            
            # Expose and set custom total count header for frontend
            response.headers["X-Total-Count"] = str(total_count or 0)
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
        tenant_id = enforce_tenant_data_scope(current_user)
        async with get_async_db_read_conn(tenant_id=tenant_id) as conn:
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

from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks

# ...

@router.post("/{id}/action")
async def resolve_alert(
    id: str, 
    payload: AlertAction, 
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(RoleChecker(["ADMIN", "ANALYST"])),
    _rate_limit=Depends(RateLimiter(limit=30, window=60))
):
    if payload.action not in ["CLOSE_SAR", "CLOSE_FALSE_POSITIVE"]:
        raise HTTPException(status_code=400, detail="Invalid action. Must be CLOSE_SAR or CLOSE_FALSE_POSITIVE")

    status = "CLOSED_SAR" if payload.action == "CLOSE_SAR" else "CLOSED_FALSE_POSITIVE"

    try:
        tenant_id = enforce_tenant_data_scope(current_user)
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

        # Output audit-grade structured log
        from observability.logging import log_audit_event
        log_audit_event(
            event_type="ALERT_RESOLUTION",
            actor_id=current_user["id"],
            actor_role=current_user["role"],
            action=payload.action,
            resource_type="ALERT",
            resource_id=id,
            tenant_id=tenant_id,
            details={
                "username": current_user["username"],
                "resulting_status": status,
                "justification": payload.justification,
                "sar_xml_generated": bool(payload.action == "CLOSE_SAR" and payload.sar_xml_generate)
            }
        )

        # Record human active learning feedback sample in background task
        from services.feedback_loop import feedback_service
        label = 0 if payload.action == "CLOSE_FALSE_POSITIVE" else 1
        background_tasks.add_task(
            feedback_service.record_feedback,
            alert_id=id,
            label=label,
            analyst_id=current_user["id"],
            justification=payload.justification
        )

        # Generate SAR XML if requested
        sar_xml = None
        if payload.action == "CLOSE_SAR" and payload.sar_xml_generate:
            sar_xml = generate_sar_xml(alert, payload.justification)

        return {"status": status, "sar_xml": sar_xml}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to resolve alert: {str(e)}")

class AlertAssignment(BaseModel):
    officer_username: str = Field(..., min_length=1, max_length=100)

    @field_validator("officer_username", mode="before")
    @classmethod
    def sanitize_officer(cls, v: str) -> str:
        return sanitize_text(v)

@router.post("/{id}/assign")
async def assign_alert(
    id: str,
    payload: AlertAssignment,
    current_user: dict = Depends(RoleChecker(["ADMIN", "ANALYST"])),
    _rate_limit=Depends(RateLimiter(limit=30, window=60))
):
    try:
        tenant_id = enforce_tenant_data_scope(current_user)
        async with get_async_db_conn(tenant_id=tenant_id) as conn:
            # Resolve user ID from username
            officer = await conn.fetchrow(
                "SELECT id FROM users WHERE username = $1;",
                payload.officer_username
            )
            if not officer:
                raise HTTPException(status_code=404, detail=f"Officer '{payload.officer_username}' not found.")

            # Update assigned_officer_id
            updated = await conn.execute(
                "UPDATE alerts SET assigned_officer_id = $1 WHERE id = $2;",
                officer["id"], uuid.UUID(id)
            )
            if updated == "UPDATE 0":
                raise HTTPException(status_code=404, detail="Alert not found.")

            # Broadcast WebSocket update
            from routers.metrics import ws_manager
            await ws_manager.broadcast({
                "event": "ALERT_ASSIGNED",
                "alert_id": id,
                "assigned_officer": payload.officer_username
            })

            return {"alert_id": id, "assigned_officer": payload.officer_username, "status": "ASSIGNED"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to assign alert: {str(e)}")


class AlertEscalate(BaseModel):
    justification: str | None = Field(None, max_length=2000)

    @field_validator("justification", mode="before")
    @classmethod
    def sanitize_just(cls, v: str | None) -> str | None:
        return sanitize_text(v) if v else None


@router.post("/{id}/escalate")
async def escalate_alert(
    id: str,
    payload: AlertEscalate | None = None,
    current_user: dict = Depends(RoleChecker(["ADMIN", "ANALYST"])),
    _rate_limit=Depends(RateLimiter(limit=30, window=60))
):
    """
    Escalates an alert to Senior Compliance Review Committee with persistence in PostgreSQL.
    """
    try:
        alert_uuid = uuid.UUID(id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid alert ID format")

    tenant_id = enforce_tenant_data_scope(current_user)
    justification = payload.justification if payload and payload.justification else "Escalated to Senior Review Committee."

    try:
        async with get_async_db_conn(tenant_id=tenant_id) as conn:
            user_uuid = uuid.UUID(str(current_user["id"]))
            updated = await conn.execute(
                """
                UPDATE alerts
                SET status = 'ESCALATED', assigned_officer_id = $1
                WHERE id = $2;
                """,
                user_uuid, alert_uuid
            )
            if updated == "UPDATE 0":
                raise HTTPException(status_code=404, detail="Alert not found")

            # Audit log
            from observability.logging import log_audit_event
            log_audit_event(
                event_type="ALERT_ESCALATION",
                actor_id=str(current_user["id"]),
                actor_role=current_user["role"],
                action="ESCALATE",
                resource_type="ALERT",
                resource_id=id,
                tenant_id=tenant_id,
                details={
                    "username": current_user["username"],
                    "justification": justification
                }
            )

            # Broadcast WebSocket notification
            from routers.metrics import ws_manager
            await ws_manager.broadcast({
                "event": "ALERT_ESCALATED",
                "alert_id": id,
                "status": "ESCALATED",
                "escalated_by": current_user["username"],
                "justification": justification
            })

            return {
                "alert_id": id,
                "status": "ESCALATED",
                "message": f"Alert {id} successfully escalated to Senior Review Committee."
            }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to escalate alert: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to escalate alert: {str(e)}")


class AlertPatch(BaseModel):
    status: str | None = Field(None, pattern=r"^(CLOSE_SAR|CLOSE_FALSE_POSITIVE|ESCALATED|OPEN)$")
    officer_username: str | None = Field(None, max_length=100)
    justification: str | None = Field(None, max_length=2000)
    sar_xml_generate: bool | None = False

    @field_validator("officer_username", "justification", mode="before")
    @classmethod
    def sanitize_patch_fields(cls, v: str | None) -> str | None:
        return sanitize_text(v) if v else None


@router.patch("/{id}")
async def patch_alert(
    id: str,
    payload: AlertPatch,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(RoleChecker(["ADMIN", "ANALYST"])),
    _rate_limit=Depends(RateLimiter(limit=30, window=60))
):
    """
    Canonical RESTful partial update for an alert resource.
    Supports status transitions (CLOSE_SAR, CLOSE_FALSE_POSITIVE, ESCALATED) and officer assignment.
    """
    try:
        alert_uuid = uuid.UUID(id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid alert ID format")

    tenant_id = enforce_tenant_data_scope(current_user)

    # 1. Handle officer assignment if requested
    if payload.officer_username:
        await assign_alert(
            id=id,
            payload=AlertAssignment(officer_username=payload.officer_username),
            current_user=current_user
        )

    # 2. Handle status change if requested
    if payload.status in ["CLOSE_SAR", "CLOSE_FALSE_POSITIVE"]:
        res = await resolve_alert(
            id=id,
            payload=AlertAction(
                action=payload.status,
                justification=payload.justification or "Resolved via REST PATCH",
                sar_xml_generate=payload.sar_xml_generate or False
            ),
            background_tasks=background_tasks,
            current_user=current_user
        )
        return {"alert_id": id, "status": payload.status, "detail": res}
    elif payload.status == "ESCALATED":
        res = await escalate_alert(
            id=id,
            payload=AlertEscalate(justification=payload.justification or "Escalated via REST PATCH"),
            current_user=current_user
        )
        return {"alert_id": id, "status": "ESCALATED", "detail": res}

    resp = {"alert_id": id, "status": "UPDATED", "message": "Alert updated successfully."}
    if payload.officer_username:
        resp["assigned_officer"] = payload.officer_username
    return resp


@router.get("/{id}")
@router.get("/{id}/details")
async def get_alert_details(
    id: str,
    current_user: dict = Depends(RoleChecker(["ADMIN", "ANALYST", "AUDITOR"])),
    _rate_limit=Depends(RateLimiter(limit=60, window=60))
):
    """
    Returns authentic, complete case details for the 3-Pane Cockpit:
      - Core alert data & explainability SHAP attributes
      - Complete transaction telemetry (channel, country, device)
      - Sender account KYC snapshot & tenure from PostgreSQL
      - Trailing 30-day transaction timeline for dynamic graph/timeline rendering
      - Trailing 12-month prior alerts for the same account
    """
    try:
        alert_uuid = uuid.UUID(id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid alert ID format")

    tenant_id = enforce_tenant_data_scope(current_user)
    try:
        async with get_async_db_read_conn(tenant_id=tenant_id) as conn:
            # 1. Fetch Alert + Transaction + Sender + Receiver + Assignee
            row = await conn.fetchrow(
                """
                SELECT a.id, a.rule_name, a.threat_level, a.ai_risk_score, a.explainability_payload,
                       a.status, a.created_at, COALESCE(u.username, 'Unassigned') as assignee,
                       t.id as txn_id, t.amount, t.currency, t.timestamp as txn_time,
                       t.country, t.channel, t.merchant, t.device,
                       s.id as sender_id, s.account_number as sender_account, s.owner_name as sender_name,
                       s.swift_bic as sender_bic, s.risk_score as sender_risk_score,
                       s.risk_category as sender_risk_tier, s.created_at as sender_created_at,
                       r.id as receiver_id, r.account_number as receiver_account, r.owner_name as receiver_name,
                       r.swift_bic as receiver_bic
                FROM alerts a
                JOIN transactions t ON a.transaction_id = t.id
                JOIN accounts s ON t.sender_account_id = s.id
                JOIN accounts r ON t.receiver_account_id = r.id
                LEFT JOIN users u ON a.assigned_officer_id = u.id
                WHERE a.id = $1;
                """,
                alert_uuid
            )
            if not row:
                raise HTTPException(status_code=404, detail="Alert not found")

            sender_id = row["sender_id"]

            # 2. Fetch Customer Profile if present
            profile = await conn.fetchrow(
                """
                SELECT kyc_risk_tier, jurisdiction_risk_score, avg_amount, monthly_frequency
                FROM customer_profiles
                WHERE account_id = $1;
                """,
                sender_id
            )

            # 3. Trailing 30-day transactions for dynamic timeline
            tx_rows = await conn.fetch(
                """
                SELECT id, amount, currency, timestamp, country, channel, status
                FROM transactions
                WHERE sender_account_id = $1
                  AND timestamp >= $2::timestamptz - INTERVAL '30 days'
                ORDER BY timestamp ASC;
                """,
                sender_id, row["txn_time"]
            )

            history = []
            for tx in tx_rows:
                history.append({
                    "id": str(tx["id"]),
                    "amount": float(tx["amount"]),
                    "currency": tx["currency"],
                    "timestamp": tx["timestamp"].isoformat(),
                    "country": tx["country"] or "DOMESTIC",
                    "channel": tx["channel"] or "Wire",
                    "status": tx["status"],
                    "is_flagged": str(tx["id"]) == str(row["txn_id"])
                })

            # 4. Trailing 12-month prior alerts
            prior_rows = await conn.fetch(
                """
                SELECT a.id, a.rule_name, a.threat_level, a.status, a.created_at
                FROM alerts a
                JOIN transactions t ON a.transaction_id = t.id
                WHERE t.sender_account_id = $1
                  AND a.id != $2
                  AND a.created_at >= $3::timestamptz - INTERVAL '365 days'
                ORDER BY a.created_at DESC
                LIMIT 10;
                """,
                sender_id, alert_uuid, row["created_at"]
            )

            prior_alerts = []
            for pa in prior_rows:
                prior_alerts.append({
                    "alert_id": str(pa["id"]),
                    "rule_name": pa["rule_name"],
                    "threat_level": pa["threat_level"],
                    "status": pa["status"],
                    "created_at": pa["created_at"].isoformat()
                })

            explain = json.loads(row["explainability_payload"]) if row["explainability_payload"] else {}

            return {
                "id": str(row["id"]),
                "alert_id": str(row["id"]),
                "rule_name": row["rule_name"],
                "threat_level": row["threat_level"],
                "ai_risk_score": float(row["ai_risk_score"]) if row["ai_risk_score"] else 0.5,
                "explainability": explain,
                "status": row["status"],
                "created_at": row["created_at"].isoformat(),
                "assignee": row["assignee"],
                "transaction": {
                    "id": str(row["txn_id"]),
                    "amount": float(row["amount"]),
                    "currency": row["currency"],
                    "timestamp": row["txn_time"].isoformat(),
                    "sender_account": row["sender_account"],
                    "sender_name": row["sender_name"],
                    "receiver_account": row["receiver_account"],
                    "receiver_name": row["receiver_name"],
                    "channel": row["channel"] or "Wire Transfer",
                    "country": row["country"] or "DOMESTIC",
                    "merchant": row["merchant"],
                    "device": row["device"]
                },
                "entity": {
                    "account_id": str(row["sender_id"]),
                    "name": row["sender_name"],
                    "account_number": row["sender_account"],
                    "swift_bic": row["sender_bic"],
                    "risk_tier": row["sender_risk_tier"] or (profile["kyc_risk_tier"] if profile else "STANDARD"),
                    "risk_score": float(row["sender_risk_score"]) if row["sender_risk_score"] else 0.0,
                    "customer_since": row["sender_created_at"].isoformat() if row["sender_created_at"] else None,
                    "jurisdiction_risk": float(profile["jurisdiction_risk_score"]) if profile and profile["jurisdiction_risk_score"] else 0.1
                },
                "timeline_30d": history,
                "prior_alerts": prior_alerts
            }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to load alert details: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to load alert details: {str(e)}")


class BulkAlertAction(BaseModel):
    alert_ids: List[str] = Field(..., min_length=1, max_length=100)
    action: str = Field(..., pattern=r"^(CLOSE_SAR|CLOSE_FALSE_POSITIVE)$")
    justification: str = Field(..., min_length=5, max_length=2000)

    @field_validator("justification", mode="before")
    @classmethod
    def sanitize_justification(cls, v: str) -> str:
        return sanitize_text(v)


@router.patch("")
@router.post("/bulk-action")
async def bulk_resolve_alerts(
    payload: BulkAlertAction,
    current_user: dict = Depends(RoleChecker(["ADMIN", "ANALYST"])),
    _rate_limit=Depends(RateLimiter(limit=10, window=60))
):
    """
    Executes atomic batch resolution for up to 100 alerts simultaneously in PostgreSQL.
    """
    status = "CLOSED_SAR" if payload.action == "CLOSE_SAR" else "CLOSED_FALSE_POSITIVE"
    try:
        alert_uuids = [uuid.UUID(aid) for aid in payload.alert_ids]
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid UUID format in alert_ids array.")

    try:
        tenant_id = enforce_tenant_data_scope(current_user)
        async with get_async_db_conn(tenant_id=tenant_id) as conn:
            # Batch update all targeted alert records in PostgreSQL
            result = await conn.execute(
                """
                UPDATE alerts
                SET status = $1, assigned_officer_id = $2
                WHERE id = ANY($3::uuid[]);
                """,
                status, uuid.UUID(current_user["id"]), alert_uuids
            )
            count = int(result.split(" ")[1]) if "UPDATE" in result else 0

            # Output audit-grade structured log
            from observability.logging import log_audit_event
            log_audit_event(
                event_type="BULK_ALERT_RESOLUTION",
                actor_id=current_user["id"],
                actor_role=current_user["role"],
                action=payload.action,
                resource_type="ALERT_BATCH",
                resource_id=f"batch_{len(payload.alert_ids)}",
                tenant_id=tenant_id,
                details={
                    "username": current_user["username"],
                    "count": count,
                    "alert_ids": payload.alert_ids,
                    "justification": payload.justification
                }
            )

            # Broadcast WebSocket notification
            from routers.metrics import ws_manager
            await ws_manager.broadcast({
                "event": "BULK_ALERTS_RESOLVED",
                "count": count,
                "action": payload.action,
                "resolved_by": current_user["username"]
            })

            return {
                "processed_count": count,
                "action": payload.action,
                "status": status,
                "message": f"Successfully processed {count} alerts in batch transaction."
            }
    except Exception as e:
        logger.error(f"Bulk alert action failed: {e}")
        raise HTTPException(status_code=500, detail=f"Bulk action failed: {str(e)}")


def sanitize_csv_cell(value: object) -> object:
    """Neutralizes CSV formula injection (CWE-1236) by escaping formula trigger characters."""
    if isinstance(value, str) and value:
        if value[0] in ("=", "+", "-", "@", "\t", "\r"):
            return f"'{value}"
    return value


@router.get("/export/csv")
async def export_alerts_csv(
    current_user: dict = Depends(RoleChecker(["ADMIN", "ANALYST", "AUDITOR"])),
    _rate_limit=Depends(RateLimiter(limit=10, window=60))
):
    """
    Exports PostgreSQL compliance alerts audit ledger as downloadable CSV file.
    Streams records in chunked batches to eliminate memory spikes and OOM risks,
    while escaping formula characters against CWE-1236 CSV injection.
    """
    tenant_id = enforce_tenant_data_scope(current_user)

    async def stream_csv_rows():
        try:
            async with get_async_db_read_conn(tenant_id=tenant_id) as conn:
                output = io.StringIO()
                writer = csv.writer(output)
                writer.writerow([
                    "Alert ID", "Threat Level", "AI Risk Score", "Rule Trigger",
                    "Status", "Triggered At", "Amount", "Currency", "Sender Account",
                    "Receiver Account", "Assigned Officer"
                ])
                yield output.getvalue()
                output.seek(0)
                output.truncate(0)

                offset = 0
                chunk_size = 1000
                while True:
                    rows = await conn.fetch(
                        """
                        SELECT a.id, a.threat_level, a.ai_risk_score, a.rule_name, a.status, a.created_at,
                               t.amount, t.currency, s.account_number AS sender, r.account_number AS receiver,
                               COALESCE(u.username, 'Unassigned') AS assignee
                        FROM alerts a
                        JOIN transactions t ON a.transaction_id = t.id
                        JOIN accounts s ON t.sender_account_id = s.id
                        JOIN accounts r ON t.receiver_account_id = r.id
                        LEFT JOIN users u ON a.assigned_officer_id = u.id
                        ORDER BY a.created_at DESC
                        LIMIT $1 OFFSET $2;
                        """,
                        chunk_size, offset
                    )
                    if not rows:
                        break

                    for row in rows:
                        writer.writerow([
                            sanitize_csv_cell(str(row["id"])),
                            sanitize_csv_cell(row["threat_level"]),
                            f"{round(float(row['ai_risk_score'] or 0) * 100, 1)}%",
                            sanitize_csv_cell(row["rule_name"]),
                            sanitize_csv_cell(row["status"]),
                            row["created_at"].isoformat(),
                            float(row["amount"]),
                            sanitize_csv_cell(row["currency"]),
                            sanitize_csv_cell(row["sender"]),
                            sanitize_csv_cell(row["receiver"]),
                            sanitize_csv_cell(row["assignee"])
                        ])

                    yield output.getvalue()
                    output.seek(0)
                    output.truncate(0)
                    offset += len(rows)
                    if len(rows) < chunk_size:
                        break
        except Exception as e:
            logger.error(f"CSV streaming failed: {e}")
            raise

    filename = f"aml_alerts_audit_export_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv"
    return StreamingResponse(
        stream_csv_rows(),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@router.get("/export/pdf")
async def export_alerts_pdf(
    current_user: dict = Depends(RoleChecker(["ADMIN", "ANALYST", "AUDITOR"])),
    _rate_limit=Depends(RateLimiter(limit=10, window=60))
):
    """
    Generates a printable audit report with FinCEN regulatory compliance layout.
    """
    tenant_id = enforce_tenant_data_scope(current_user)
    try:
        async with get_async_db_read_conn(tenant_id=tenant_id) as conn:
            rows = await conn.fetch(
                """
                SELECT a.id, a.threat_level, a.ai_risk_score, a.rule_name, a.status, a.created_at,
                       t.amount, t.currency, s.account_number AS sender, r.account_number AS receiver,
                       COALESCE(u.username, 'Unassigned') AS assignee
                FROM alerts a
                JOIN transactions t ON a.transaction_id = t.id
                JOIN accounts s ON t.sender_account_id = s.id
                JOIN accounts r ON t.receiver_account_id = r.id
                LEFT JOIN users u ON a.assigned_officer_id = u.id
                ORDER BY a.created_at DESC
                LIMIT 50;
                """
            )

            table_rows_html = ""
            for r in rows:
                score = f"{round(float(r['ai_risk_score'] or 0) * 100)}%"
                table_rows_html += f"""
                <tr>
                    <td style="padding: 6px; border-bottom: 1px solid #ddd; font-family: monospace;">{str(r['id'])[:8]}...</td>
                    <td style="padding: 6px; border-bottom: 1px solid #ddd;"><strong>{r['threat_level']}</strong></td>
                    <td style="padding: 6px; border-bottom: 1px solid #ddd;">{score}</td>
                    <td style="padding: 6px; border-bottom: 1px solid #ddd;">{r['rule_name']}</td>
                    <td style="padding: 6px; border-bottom: 1px solid #ddd;">${float(r['amount']):,.2f} {r['currency']}</td>
                    <td style="padding: 6px; border-bottom: 1px solid #ddd;">{r['status']}</td>
                    <td style="padding: 6px; border-bottom: 1px solid #ddd;">{r['assignee']}</td>
                </tr>
                """

            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>AML Compliance & Regulatory Audit Report</title>
                <style>
                    body {{ font-family: 'Helvetica Neue', Arial, sans-serif; margin: 20px; color: #1e293b; }}
                    h1 {{ color: #3d6b99; border-bottom: 2px solid #3d6b99; padding-bottom: 6px; }}
                    table {{ width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 12px; }}
                    th {{ background: #f1f5f9; text-align: left; padding: 8px; border-bottom: 2px solid #cbd5e1; }}
                    .footer {{ margin-top: 30px; font-size: 10px; color: #64748b; border-top: 1px solid #e2e8f0; padding-top: 10px; }}
                </style>
            </head>
            <body onload="window.print()">
                <h1>AML Audit Report & Case Ledger</h1>
                <p><strong>Generated At:</strong> {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
                <p><strong>Auditor / Officer:</strong> {current_user['username']} ({current_user['role']})</p>
                <table>
                    <thead>
                        <tr>
                            <th>Alert ID</th>
                            <th>Threat</th>
                            <th>Risk Score</th>
                            <th>Trigger Rule</th>
                            <th>Amount</th>
                            <th>Status</th>
                            <th>Assigned Officer</th>
                        </tr>
                    </thead>
                    <tbody>
                        {table_rows_html}
                    </tbody>
                </table>
                <div class="footer">
                    Confidential AML Regulatory Compliance Document — FinCEN / BSA Audit Log Record.
                </div>
            </body>
            </html>
            """
            return HTMLResponse(content=html_content)
    except Exception as e:
        logger.error(f"PDF/HTML report generation failed: {e}")
        raise HTTPException(status_code=500, detail=f"Report export failed: {str(e)}")

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
