"""
Alerts Triage, Investigation Workbench & Regulatory Export Router
=================================================================
Thin HTTP controller for listing, triaging, claiming, escalating, resolving,
graph-inspecting, and exporting AML alerts.
All PostgreSQL SQL, deterministic row locking, and transactional audit writes
live in `repositories/alert_repo.py`.
"""

import csv
import io
import json
import logging
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Annotated, List

from fastapi import APIRouter, BackgroundTasks, Depends, Header, HTTPException, Query, Request, Response, status
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel, Field, field_validator

from database.neo4j_db import get_async_neo4j_driver
from database.postgres import get_async_db_conn, get_async_db_read_conn
from observability.sanitizer import sanitize_text
from repositories.alert_repo import (
    ALERT_NOT_FOUND,
    DEFAULT_CHANNEL,
    DEFAULT_COUNTRY,
    UPDATE_ZERO,
    _fetch_counterparties_tx as _fetch_counterparties,
    _fetch_customer_timeline_and_alerts_tx as _fetch_customer_timeline_and_alerts,
    assign_alert_atomic,
    bulk_claim_or_assign_alerts_atomic,
    bulk_correlate_alerts_repo,
    bulk_resolve_alerts_atomic,
    claim_alert_atomic,
    escalate_alert_atomic,
    execute_alert_resolution_atomic,
    fetch_alert_pg_graph_rows_repo,
    fetch_alert_sender_receiver_repo,
    fetch_alert_workbench_bundle_repo,
    fetch_alerts_for_pdf_export_repo,
    get_row_field as _get_row_field,
    iter_alert_export_chunks_repo,
    list_alert_escalations_repo,
    list_alerts_grouped_by_entity_repo,
    list_alerts_page_repo,
)
from services.auth import RoleChecker, enforce_tenant_data_scope, get_current_user
from services.http_cache import build_conditional_json_response
from services.idempotency import run_idempotent_operation
from services.rate_limiter import RateLimiter
from services.state_machine import validate_alert_transition

logger = logging.getLogger(__name__)

INVALID_ALERT_ID = "Invalid alert ID format"

router = APIRouter(prefix="/api/v1/alerts", tags=["Alerts"])


class AlertAction(BaseModel):
    action: str = Field(..., pattern=r"^(CLOSE_SAR|CLOSE_FALSE_POSITIVE)$")
    justification: str = Field(..., min_length=3, max_length=2000)
    sar_xml_generate: bool = False

    @field_validator("justification", mode="before")
    @classmethod
    def sanitize_justification(cls, v: str) -> str:
        return sanitize_text(v)


def _serialize_alert_row(row, *, include_explainability: bool = True) -> dict:
    def _to_iso(val):
        if val is None:
            return None
        return val.isoformat() if hasattr(val, "isoformat") else str(val)

    def _get_val(idx, fallback):
        return row[idx] if len(row) > idx and row[idx] else fallback

    payload = {
        "id": str(row[0]),
        "alert_id": str(row[0]),
        "rule_name": row[1],
        "threat_level": row[2],
        "ai_risk_score": float(row[3]) if row[3] is not None else None,
        "status": row[5],
        "created_at": _to_iso(row[6]),
        "assignee": row[12],
        "sender_risk_tier": _get_val(15, "STANDARD"),
        "account_created_at": _to_iso(row[16]) if len(row) > 16 else None,
        "transaction": {
            "amount": float(row[7]) if row[7] is not None else 0.0,
            "amount_str": str(row[7]) if row[7] is not None else "0.0000",
            "currency": row[8] or "USD",
            "timestamp": _to_iso(row[9]),
            "sender": row[10],
            "receiver": row[11],
            "sender_name": _get_val(13, row[10]),
            "receiver_name": _get_val(14, row[11]),
            "channel": _get_val(17, DEFAULT_CHANNEL),
            "country": _get_val(18, DEFAULT_COUNTRY),
        },
    }
    if include_explainability:
        payload["explainability"] = json.loads(row[4]) if isinstance(row[4], str) else row[4]
    return payload


@router.get("")
async def list_alerts(
    response: Response,
    page: Annotated[int, Query(ge=1, le=1000)] = 1,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    cursor: Annotated[str | None, Query(max_length=512)] = None,
    search: Annotated[str | None, Query(max_length=200)] = None,
    severity: Annotated[str | None, Query(max_length=32)] = None,
    status_filter: Annotated[str | None, Query(max_length=64)] = None,
    fields: Annotated[str | None, Query(max_length=32)] = None,
    current_user: dict = Depends(RoleChecker(["ADMIN", "ANALYST", "AUDITOR", "MLRO"])),
    _rate_limit=Depends(RateLimiter(limit=60, window=60)),
):
    from database.pagination import encode_keyset_cursor

    try:
        tenant_id = enforce_tenant_data_scope(current_user)
        include_explainability = (fields or "").strip().lower() != "summary"
        total_count, rows = await list_alerts_page_repo(
            tenant_id=tenant_id,
            page=page,
            limit=limit,
            search=search,
            severity=severity,
            status_filter=status_filter,
            include_explainability=include_explainability,
            cursor=cursor,
            read_conn_factory=get_async_db_read_conn,
        )
        if cursor:
            has_more = len(rows) > limit
            rows = rows[:limit]
        else:
            has_more = ((page - 1) * limit + len(rows)) < total_count
        alerts = [_serialize_alert_row(row, include_explainability=include_explainability) for row in rows]
        if total_count >= 0:
            response.headers["X-Total-Count"] = str(total_count)
        response.headers["X-Has-More"] = "true" if has_more else "false"
        if alerts and has_more:
            last_row = rows[-1]
            if last_row[6] is not None and last_row[0] is not None:
                response.headers["X-Next-Cursor"] = encode_keyset_cursor(last_row[6], str(last_row[0]))
        response.headers["Access-Control-Expose-Headers"] = "X-Total-Count, X-Next-Cursor, X-Has-More"
        return alerts
    except HTTPException:
        raise
    except Exception:
        logger.exception("Failed to list alerts")
        raise HTTPException(status_code=500, detail="Failed to list alerts.")


def _add_neo4j_edge(edges, edge_ids, edge_key_prefix, edge, edge_type, properties):
    if not edge:
        return
    edge_id = f"{edge_key_prefix}_{edge.element_id}"
    if edge_id not in edge_ids:
        edge_ids.add(edge_id)
        edges.append(
            {
                "id": edge_id,
                "source": edge.start_node_element_id,
                "target": edge.end_node_element_id,
                "type": edge_type,
                "properties": properties,
            }
        )


def _process_neo4j_edges(record, a_node, other_node, c_node, p_node, edges, edge_ids):
    t_edge = record.get("t")
    if t_edge and a_node and other_node:
        _add_neo4j_edge(
            edges,
            edge_ids,
            "tx",
            t_edge,
            "TRANSFERS_TO",
            {
                "amount": t_edge.get("amount"),
                "timestamp": t_edge.get("timestamp"),
                "status": t_edge.get("status"),
            },
        )

    b_edge = record.get("b")
    if b_edge and a_node and c_node:
        _add_neo4j_edge(edges, edge_ids, "belongs", b_edge, "BELONGS_TO", {})

    u_edge = record.get("u")
    if u_edge and p_node and c_node:
        _add_neo4j_edge(edges, edge_ids, "owns", u_edge, "OWNS_UBO", {"percentage": u_edge.get("percentage")})


def _process_neo4j_alert_record(record, nodes, edges, node_ids, edge_ids):
    def add_node(node_id, label, node_type, props):
        if node_id not in node_ids:
            node_ids.add(node_id)
            nodes.append({"id": node_id, "label": label, "type": node_type, "properties": props})

    a_node = record.get("a")
    if a_node:
        add_node(a_node.element_id, a_node.get("account_number"), "Account", dict(a_node))

    other_node = record.get("other")
    if other_node:
        add_node(other_node.element_id, other_node.get("account_number"), "Account", dict(other_node))

    c_node = record.get("c")
    if c_node:
        add_node(c_node.element_id, c_node.get("name"), "Company", dict(c_node))

    p_node = record.get("p")
    if p_node:
        add_node(p_node.element_id, p_node.get("name"), "Person", dict(p_node))

    _process_neo4j_edges(record, a_node, other_node, c_node, p_node, edges, edge_ids)


async def _build_alert_graph_from_postgres(sender: str, receiver: str, tenant_id: str | None) -> dict:
    """PostgreSQL 1-to-2 hop graph fallback when Neo4j has no synced nodes for the alert."""
    nodes = []
    edges = []
    node_ids: set[str] = set()
    edge_ids: set[str] = set()

    def add_pg_node(acc_num: str, owner_name: str | None, risk_score: float | None, risk_cat: str | None):
        if not acc_num or acc_num in node_ids:
            return
        node_ids.add(acc_num)
        nodes.append(
            {
                "id": acc_num,
                "label": owner_name or acc_num,
                "type": "Account",
                "properties": {
                    "account_number": acc_num,
                    "owner_name": owner_name or acc_num,
                    "risk_score": float(risk_score or 0.0),
                    "risk_category": risk_cat or ("HIGH" if float(risk_score or 0.0) >= 0.7 else "LOW"),
                },
            }
        )

    rows = await fetch_alert_pg_graph_rows_repo(
        sender=sender,
        receiver=receiver,
        tenant_id=tenant_id,
        read_conn_factory=get_async_db_read_conn,
    )
    for row in rows:
        add_pg_node(row["s_acc"], row["s_name"], row["s_risk"], row["s_cat"])
        add_pg_node(row["r_acc"], row["r_name"], row["r_risk"], row["r_cat"])
        eid = f"pg_tx_{row['id']}"
        if eid not in edge_ids:
            edge_ids.add(eid)
            edges.append(
                {
                    "id": eid,
                    "source": row["s_acc"],
                    "target": row["r_acc"],
                    "type": "TRANSFERS_TO",
                    "properties": {
                        "amount": float(row["amount"] or 0.0),
                        "timestamp": row["timestamp"].isoformat() if row["timestamp"] else None,
                        "status": row["status"],
                    },
                }
            )
    return {"nodes": nodes, "edges": edges}


async def _build_alert_graph_from_neo4j(neo4j_driver, sender: str, receiver: str, tenant_id: str | None) -> dict:
    nodes = []
    edges = []
    node_ids = set()
    edge_ids = set()

    query = """
    MATCH (a:Account) WHERE a.account_number IN [$sender, $receiver]
      AND ($tenant_id IS NULL OR a.tenant_id = $tenant_id)
    OPTIONAL MATCH (a)-[t:TRANSFERS_TO]-(other:Account)
      WHERE ($tenant_id IS NULL OR (other.tenant_id = $tenant_id AND (t.tenant_id IS NULL OR t.tenant_id = $tenant_id)))
    OPTIONAL MATCH (a)-[b:BELONGS_TO]->(c:Company)
      WHERE ($tenant_id IS NULL OR c.tenant_id = $tenant_id)
    OPTIONAL MATCH (p:Person)-[u:OWNS_UBO]->(c)
      WHERE ($tenant_id IS NULL OR p.tenant_id = $tenant_id)
    RETURN a, t, other, b, c, p, u LIMIT 50;
    """
    async with neo4j_driver.session() as session:
        result = await session.run(
            query, sender=sender, receiver=receiver, tenant_id=str(tenant_id) if tenant_id else None
        )
        async for record in result:
            _process_neo4j_alert_record(record, nodes, edges, node_ids, edge_ids)

    return {"nodes": nodes, "edges": edges}


@router.get("/grouped-by-entity")
async def list_alerts_grouped_by_entity(
    limit: int = Query(default=50, ge=1, le=100),
    current_user: dict = Depends(RoleChecker(["L1_ANALYST", "L2_INVESTIGATOR", "ANALYST", "MLRO", "ADMIN", "AUDITOR"])),
    _rate_limit=Depends(RateLimiter(limit=60, window=60)),
):
    """Entity-Centric Alert Grouping (P1-1)."""
    tenant_id = enforce_tenant_data_scope(current_user)
    rows = await list_alerts_grouped_by_entity_repo(
        tenant_id=tenant_id,
        limit=limit,
        read_conn_factory=get_async_db_read_conn,
    )
    return {
        "total_entities": len(rows),
        "entities": [
            {
                "subject_account_id": str(r["subject_account_id"]),
                "account_number": r["account_number"],
                "owner_name": r["owner_name"],
                "alert_count": int(r["alert_count"] or 0),
                "max_risk_score": float(r["max_risk_score"] or 0.0),
                "total_exposure_usd": float(r["total_exposure_usd"] or 0.0),
                "total_exposure_usd_str": str(r["total_exposure_usd"] if r["total_exposure_usd"] is not None else "0.0000"),
                "alert_ids": list(r["alert_ids"] or []),
                "rules_fired": [x for x in (r["rules_fired"] or []) if x],
                "latest_alert_at": r["latest_alert_at"].isoformat() if r["latest_alert_at"] else None,
                "active_case_id": r["active_case_id"],
            }
            for r in rows
        ],
    }


@router.get("/{id}/graph")
async def get_alert_graph(
    id: str,
    current_user: dict = Depends(RoleChecker(["ADMIN", "ANALYST", "AUDITOR"])),
    neo4j_driver=Depends(get_async_neo4j_driver),
    _rate_limit=Depends(RateLimiter(limit=60, window=60)),
):
    try:
        alert_uuid = uuid.UUID(id)
    except ValueError:
        raise HTTPException(status_code=400, detail=INVALID_ALERT_ID)

    tenant_id = enforce_tenant_data_scope(current_user)
    try:
        sender, receiver = await fetch_alert_sender_receiver_repo(
            alert_uuid=alert_uuid,
            tenant_id=tenant_id,
            read_conn_factory=get_async_db_read_conn,
        )
    except HTTPException:
        raise
    except Exception:
        logger.exception("Failed to load alert sender/receiver for graph")
        raise HTTPException(status_code=500, detail="Failed to query alert graph data.")

    graph_payload = {"nodes": [], "edges": []}
    if neo4j_driver is not None:
        try:
            graph_payload = await _build_alert_graph_from_neo4j(neo4j_driver, sender, receiver, tenant_id)
        except Exception as e:
            logger.warning("Neo4j alert graph lookup failed; falling back to PostgreSQL: %s", e)

    if not graph_payload.get("nodes"):
        try:
            graph_payload = await _build_alert_graph_from_postgres(sender, receiver, tenant_id)
        except Exception:
            logger.exception("PostgreSQL alert graph fallback failed")
            raise HTTPException(status_code=500, detail="Graph query failed.")

    return graph_payload


async def _dispatch_resolution_side_effects(
    background_tasks: BackgroundTasks,
    id: str,
    payload: AlertAction,
    target_status: str,
    current_user: dict,
    tenant_id,
    alert,
):
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
            "resulting_status": target_status,
            "justification": payload.justification,
            "sar_xml_generated": bool(payload.action == "CLOSE_SAR" and payload.sar_xml_generate),
        },
    )

    from routers.metrics import ws_manager

    await ws_manager.broadcast(
        {
            "event": "ALERT_RESOLVED",
            "tenant_id": str(tenant_id),
            "alert_id": id,
            "status": target_status,
            "action": payload.action,
            "resolved_by": current_user["username"],
        },
        target_tenant_id=str(tenant_id),
    )

    from services.feedback_loop import feedback_service

    label = 0 if payload.action == "CLOSE_FALSE_POSITIVE" else 1
    background_tasks.add_task(
        feedback_service.record_feedback,
        alert_id=id,
        label=label,
        analyst_id=current_user["id"],
        justification=payload.justification,
    )

    sar_xml = None
    sar_narrative = None
    if payload.action == "CLOSE_SAR":
        from services.sar_narrative import generate_sar_narrative

        narrative_obj = await generate_sar_narrative(
            alert_id=id,
            tenant_id=str(tenant_id),
            analyst_id=current_user.get("username"),
            justification_notes=payload.justification,
        )
        sar_narrative = narrative_obj.get("narrative_text")
        if payload.sar_xml_generate:
            sar_xml = generate_sar_xml(alert, payload.justification)

    return sar_xml, sar_narrative


@router.post("/{id}/action")
async def resolve_alert(
    id: str,
    payload: AlertAction,
    background_tasks: BackgroundTasks,
    request: Request = None,
    current_user: dict = Depends(RoleChecker(["ADMIN", "ANALYST"])),
    _rate_limit=Depends(RateLimiter(limit=30, window=60)),
):
    try:
        uuid.UUID(id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid alert ID format.")

    if payload.action not in ["CLOSE_SAR", "CLOSE_FALSE_POSITIVE"]:
        raise HTTPException(status_code=400, detail="Invalid action. Must be CLOSE_SAR or CLOSE_FALSE_POSITIVE")

    target_status = "CLOSED_SAR" if payload.action == "CLOSE_SAR" else "CLOSED_FALSE_POSITIVE"
    tenant_id = enforce_tenant_data_scope(current_user)

    async def _execute_action():
        try:
            alert = await execute_alert_resolution_atomic(
                alert_id=id,
                action=payload.action,
                justification=payload.justification,
                sar_xml_generate=payload.sar_xml_generate,
                target_status=target_status,
                current_user=current_user,
                tenant_id=tenant_id,
                conn_factory=get_async_db_conn,
            )

            sar_xml, sar_narrative = await _dispatch_resolution_side_effects(
                background_tasks, id, payload, target_status, current_user, tenant_id, alert
            )
            return {"status": target_status, "sar_xml": sar_xml, "sar_narrative": sar_narrative}
        except HTTPException:
            raise
        except Exception:
            logger.exception("Failed to resolve alert")
            raise HTTPException(status_code=500, detail="Failed to resolve alert.")

    return await run_idempotent_operation(
        request=request,
        tenant_id=str(tenant_id),
        scope=f"alerts:action:{id}",
        body=payload.model_dump(),
        handler=_execute_action,
        required=True,
    )


@router.get("/{id}/narrative")
async def get_alert_sar_narrative(
    id: str,
    current_user: dict = Depends(RoleChecker(["ADMIN", "ANALYST", "MLRO", "AUDITOR"])),
    _rate_limit=Depends(RateLimiter(limit=30, window=60)),
):
    """Synthesizes an industry-standard 5-part FinCEN SAR narrative text block."""
    try:
        uuid.UUID(id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid alert ID format.")
    tenant_id = enforce_tenant_data_scope(current_user)
    try:
        from services.sar_narrative import generate_sar_narrative

        return await generate_sar_narrative(
            alert_id=id,
            tenant_id=str(tenant_id),
            analyst_id=current_user.get("username", "ANALYST"),
        )
    except HTTPException:
        raise
    except Exception:
        logger.exception("Failed to generate SAR narrative for alert %s", id)
        raise HTTPException(status_code=500, detail="Failed to generate SAR narrative.")


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
    _rate_limit=Depends(RateLimiter(limit=30, window=60)),
):
    try:
        alert_uuid = uuid.UUID(id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid alert ID format.")

    try:
        tenant_id = enforce_tenant_data_scope(current_user)
        await assign_alert_atomic(
            alert_uuid=alert_uuid,
            officer_username=payload.officer_username,
            tenant_id=tenant_id,
            conn_factory=get_async_db_conn,
        )

        from routers.metrics import ws_manager

        await ws_manager.broadcast(
            {
                "event": "ALERT_ASSIGNED",
                "tenant_id": str(tenant_id),
                "alert_id": id,
                "assigned_officer": payload.officer_username,
            },
            target_tenant_id=str(tenant_id),
        )

        return {"alert_id": id, "assigned_officer": payload.officer_username, "status": "ASSIGNED"}
    except HTTPException:
        raise
    except Exception:
        logger.exception("Failed to assign alert %s", id)
        raise HTTPException(status_code=500, detail="Failed to assign alert.")


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
    request: Request = None,
    current_user: dict = Depends(RoleChecker(["L1_ANALYST", "L2_INVESTIGATOR", "ADMIN", "ANALYST"])),
    _rate_limit=Depends(RateLimiter(limit=30, window=60)),
):
    """Escalates an alert to Senior Compliance Review Committee (mandatory Idempotency-Key)."""
    try:
        alert_uuid = uuid.UUID(id)
    except ValueError:
        raise HTTPException(status_code=400, detail=INVALID_ALERT_ID)

    tenant_id = enforce_tenant_data_scope(current_user)
    justification = payload.justification if payload and payload.justification else "Escalated to Senior Review Committee."

    async def _execute_escalate():
        try:
            user_uuid = None
            if current_user.get("id"):
                try:
                    user_uuid = uuid.UUID(str(current_user["id"]))
                except (ValueError, TypeError):
                    user_uuid = None

            correlated_case = await escalate_alert_atomic(
                alert_uuid=alert_uuid,
                tenant_id=tenant_id,
                user_uuid=user_uuid,
                username=current_user.get("username", "Analyst"),
                justification=justification,
                conn_factory=get_async_db_conn,
            )

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
                    "justification": justification,
                    "correlated_case": correlated_case,
                },
            )

            from routers.metrics import ws_manager

            await ws_manager.broadcast(
                {
                    "event": "ALERT_ESCALATED",
                    "tenant_id": str(tenant_id),
                    "alert_id": id,
                    "status": "ESCALATED",
                    "escalated_by": current_user["username"],
                    "justification": justification,
                    "correlated_case": correlated_case,
                },
                target_tenant_id=str(tenant_id),
            )

            resp_body = {
                "alert_id": id,
                "status": "ESCALATED",
                "message": f"Alert {id} successfully escalated to Senior Review Committee.",
            }
            if correlated_case:
                resp_body["correlated_case"] = correlated_case
            return resp_body
        except HTTPException:
            raise
        except Exception:
            logger.exception("Failed to escalate alert")
            raise HTTPException(status_code=500, detail="Failed to escalate alert.")

    return await run_idempotent_operation(
        request=request,
        tenant_id=str(tenant_id),
        scope=f"alerts:escalate:{id}",
        body={"justification": justification},
        handler=_execute_escalate,
        required=True,
    )


def _validate_claim_eligibility(alert_row, user_uuid, current_user_id, alert_id: str):
    if not alert_row:
        raise HTTPException(status_code=404, detail=ALERT_NOT_FOUND)

    assigned_officer = _get_row_field(alert_row, "assigned_officer_id")
    if isinstance(assigned_officer, (uuid.UUID, str)):
        officer_str = str(assigned_officer)
        if officer_str and officer_str != str(user_uuid) and officer_str != str(current_user_id):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Conflict: Alert {alert_id} is already claimed by another investigator.",
            )

    raw_status = _get_row_field(alert_row, "status", "OPEN")
    current_status = raw_status if isinstance(raw_status, str) else "OPEN"
    target_status = "IN_REVIEW" if current_status in ("NEW", "OPEN") else current_status
    validate_alert_transition(current_status, target_status)


@router.post("/{id}/claim")
async def claim_alert(
    id: str,
    request: Request = None,
    current_user: dict = Depends(RoleChecker(["L1_ANALYST", "L2_INVESTIGATOR", "ANALYST", "MLRO", "ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=60, window=60)),
):
    """Claims an alert for investigation with atomic CAS and mandatory Idempotency-Key."""
    try:
        alert_uuid = uuid.UUID(id)
    except ValueError:
        raise HTTPException(status_code=400, detail=INVALID_ALERT_ID)

    tenant_id = enforce_tenant_data_scope(current_user)
    user_uuid = None
    if current_user.get("id"):
        try:
            user_uuid = uuid.UUID(str(current_user["id"]))
        except (ValueError, TypeError):
            user_uuid = None

    async def _execute_claim():
        try:
            await claim_alert_atomic(
                alert_uuid=alert_uuid,
                alert_id=id,
                tenant_id=tenant_id,
                user_uuid=user_uuid,
                current_user_id=current_user.get("id"),
                validate_fn=_validate_claim_eligibility,
                conn_factory=get_async_db_conn,
            )

            from observability.logging import log_audit_event

            log_audit_event(
                event_type="ALERT_CLAIMED",
                actor_id=str(current_user["id"]),
                actor_role=current_user["role"],
                action="CLAIM",
                resource_type="ALERT",
                resource_id=id,
                tenant_id=tenant_id,
                details={"username": current_user.get("username")},
            )

            from routers.metrics import ws_manager

            await ws_manager.broadcast(
                {
                    "event": "ALERT_ASSIGNED",
                    "tenant_id": str(tenant_id),
                    "alert_id": id,
                    "assigned_officer": current_user.get("username"),
                },
                target_tenant_id=str(tenant_id),
            )

            return {
                "status": "CLAIMED",
                "alert_id": id,
                "assigned_officer": current_user.get("username"),
            }
        except HTTPException:
            raise
        except Exception:
            logger.exception("Failed to claim alert")
            raise HTTPException(status_code=500, detail="Failed to claim alert.")

    return await run_idempotent_operation(
        request=request,
        tenant_id=str(tenant_id),
        scope=f"alerts:claim:{id}",
        body={"alert_id": id, "actor_id": str(current_user.get("id", ""))},
        handler=_execute_claim,
        required=True,
    )


@router.get("/{id}/escalations")
async def get_alert_escalations(
    id: str,
    current_user: dict = Depends(RoleChecker(["L1_ANALYST", "L2_INVESTIGATOR", "ANALYST", "MLRO", "ADMIN", "AUDITOR"])),
    _rate_limit=Depends(RateLimiter(limit=60, window=60)),
):
    """Returns the complete escalation audit chain for an alert."""
    try:
        alert_uuid = uuid.UUID(id)
    except ValueError:
        raise HTTPException(status_code=400, detail=INVALID_ALERT_ID)

    tenant_id = enforce_tenant_data_scope(current_user)
    try:
        rows = await list_alert_escalations_repo(
            alert_uuid=alert_uuid,
            tenant_id=tenant_id,
            conn_factory=get_async_db_conn,
        )
        return [
            {
                "id": str(r["id"]),
                "alert_id": str(r["alert_id"]),
                "case_id": str(r["case_id"]) if r["case_id"] else None,
                "escalated_by": str(r["escalated_by"]),
                "escalated_by_name": r["escalated_by_name"],
                "escalated_to": str(r["escalated_to"]) if r["escalated_to"] else None,
                "escalated_to_name": r["escalated_to_name"],
                "escalated_at": r["escalated_at"].isoformat() if r["escalated_at"] else None,
                "from_tier": r["from_tier"],
                "to_tier": r["to_tier"],
                "escalation_reason": r["escalation_reason"],
                "resolved_at": r["resolved_at"].isoformat() if r["resolved_at"] else None,
                "resolution_action": r["resolution_action"],
            }
            for r in rows
        ]
    except Exception as e:
        logger.warning("Failed to fetch alert escalations: %s", e)
        return []


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
    _rate_limit=Depends(RateLimiter(limit=30, window=60)),
):
    """Canonical RESTful partial update for an alert resource."""
    try:
        uuid.UUID(id)
    except ValueError:
        raise HTTPException(status_code=400, detail=INVALID_ALERT_ID)

    enforce_tenant_data_scope(current_user)

    if payload.officer_username:
        await assign_alert(
            id=id,
            payload=AlertAssignment(officer_username=payload.officer_username),
            current_user=current_user,
        )

    if payload.status in ["CLOSE_SAR", "CLOSE_FALSE_POSITIVE"]:
        res = await resolve_alert(
            id=id,
            payload=AlertAction(
                action=payload.status,
                justification=payload.justification or "Resolved via REST PATCH",
                sar_xml_generate=payload.sar_xml_generate or False,
            ),
            background_tasks=background_tasks,
            current_user=current_user,
        )
        return {"alert_id": id, "status": payload.status, "detail": res}
    if payload.status == "ESCALATED":
        res = await escalate_alert(
            id=id,
            payload=AlertEscalate(justification=payload.justification or "Escalated via REST PATCH"),
            current_user=current_user,
        )
        return {"alert_id": id, "status": "ESCALATED", "detail": res}

    resp = {"alert_id": id, "status": "UPDATED", "message": "Alert updated successfully."}
    if payload.officer_username:
        resp["assigned_officer"] = payload.officer_username
    return resp


def _build_alert_details_response(row, profile, history, prior_alerts, linked_entities):
    raw_explain = row["explainability_payload"]
    explain = json.loads(raw_explain) if isinstance(raw_explain, (str, bytes, bytearray)) else (raw_explain or {})

    risk_tier = row["sender_risk_tier"]
    if not risk_tier and profile:
        risk_tier = profile["kyc_risk_tier"]
    if not risk_tier:
        risk_tier = "STANDARD"

    jurisdiction_risk = 0.1
    if profile and profile["jurisdiction_risk_score"]:
        jurisdiction_risk = float(profile["jurisdiction_risk_score"])

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
            "amount_str": str(row["amount"]),
            "currency": row["currency"],
            "timestamp": row["txn_time"].isoformat(),
            "sender_account": row["sender_account"],
            "sender_name": row["sender_name"],
            "receiver_account": row["receiver_account"],
            "receiver_name": row["receiver_name"],
            "channel": row["channel"] or DEFAULT_CHANNEL,
            "country": row["country"] or DEFAULT_COUNTRY,
            "merchant": row["merchant"],
            "device": row["device"],
        },
        "entity": {
            "account_id": str(row["sender_id"]),
            "name": row["sender_name"],
            "account_number": row["sender_account"],
            "swift_bic": row["sender_bic"],
            "risk_tier": risk_tier,
            "risk_score": float(row["sender_risk_score"]) if row["sender_risk_score"] else 0.0,
            "customer_since": row["sender_created_at"].isoformat() if row["sender_created_at"] else None,
            "jurisdiction_risk": jurisdiction_risk,
        },
        "timeline_30d": history,
        "prior_alerts": prior_alerts,
        "linked_entities": linked_entities,
    }


@router.get("/{id}/workbench")
async def get_alert_workbench(
    id: str,
    request: Request = None,
    current_user: dict = Depends(RoleChecker(["L1_ANALYST", "L2_INVESTIGATOR", "ADMIN", "ANALYST", "AUDITOR", "MLRO"])),
    _rate_limit=Depends(RateLimiter(limit=60, window=60)),
):
    """Composite BFF endpoint returning full alert details, escalation history, evidence count, and lock status."""
    try:
        alert_uuid = uuid.UUID(id)
    except ValueError:
        raise HTTPException(status_code=400, detail=INVALID_ALERT_ID)

    tenant_id = enforce_tenant_data_scope(current_user)
    try:
        bundle = await fetch_alert_workbench_bundle_repo(
            alert_uuid=alert_uuid,
            tenant_id=tenant_id,
            include_workbench_extras=True,
            read_conn_factory=get_async_db_read_conn,
            timeline_fn=_fetch_customer_timeline_and_alerts,
            counterparties_fn=_fetch_counterparties,
        )
        alert_details = _build_alert_details_response(
            bundle["row"],
            bundle["profile"],
            bundle["history"],
            bundle["prior_alerts"],
            bundle["linked_entities"],
        )

        lock_info = None
        try:
            from services.locking import get_resource_lock_status

            lock_info = await get_resource_lock_status("ALERT", str(alert_uuid), tenant_id=str(tenant_id))
        except Exception:
            lock_info = None

        payload = {
            "alert": alert_details,
            "escalations": [
                {
                    "id": str(e["id"]),
                    "escalated_by_name": e["escalated_by_name"],
                    "from_tier": e["from_tier"],
                    "to_tier": e["to_tier"],
                    "escalation_reason": e["escalation_reason"],
                    "created_at": e["created_at"].isoformat() if e["created_at"] else None,
                }
                for e in bundle["esc_rows"]
            ],
            "evidence_count": bundle["evidence_count"],
            "lock": lock_info,
        }
        return build_conditional_json_response(request, payload)
    except HTTPException:
        raise
    except Exception:
        logger.exception("Failed to load alert workbench bundle")
        raise HTTPException(status_code=500, detail="Failed to load alert workbench bundle.")


@router.get("/{id}")
@router.get("/{id}/details")
async def get_alert_details(
    id: str,
    current_user: dict = Depends(RoleChecker(["ADMIN", "ANALYST", "AUDITOR"])),
    _rate_limit=Depends(RateLimiter(limit=60, window=60)),
):
    """Returns complete case details for the 3-Pane Cockpit."""
    try:
        alert_uuid = uuid.UUID(id)
    except ValueError:
        raise HTTPException(status_code=400, detail=INVALID_ALERT_ID)

    tenant_id = enforce_tenant_data_scope(current_user)
    try:
        bundle = await fetch_alert_workbench_bundle_repo(
            alert_uuid=alert_uuid,
            tenant_id=tenant_id,
            include_workbench_extras=False,
            read_conn_factory=get_async_db_read_conn,
            timeline_fn=_fetch_customer_timeline_and_alerts,
            counterparties_fn=_fetch_counterparties,
        )
        return _build_alert_details_response(
            bundle["row"],
            bundle["profile"],
            bundle["history"],
            bundle["prior_alerts"],
            bundle["linked_entities"],
        )
    except HTTPException:
        raise
    except Exception:
        logger.exception("Failed to load alert details")
        raise HTTPException(status_code=500, detail="Failed to load alert details.")


class BulkAlertAction(BaseModel):
    alert_ids: List[str] = Field(..., min_length=1, max_length=100)
    action: str = Field(..., pattern=r"^(CLOSE_SAR|CLOSE_FALSE_POSITIVE|CLAIM|ASSIGN|CORRELATE_CASE)$")
    justification: str = Field(default="Batch triage action", min_length=3, max_length=2000)
    assignee_username: str | None = Field(default=None, max_length=120)

    @field_validator("justification", mode="before")
    @classmethod
    def sanitize_justification(cls, v: str) -> str:
        return sanitize_text(v) if v else "Batch triage action"


def _filter_valid_alert_transitions(rows, target_status: str) -> tuple[list, list]:
    valid_ids = []
    held_tx_ids = []
    for r in rows:
        c_st = r["status"] or "OPEN"
        try:
            validate_alert_transition(c_st, target_status)
            valid_ids.append(r["id"])
            t_id = _get_row_field(r, "transaction_id") or _get_row_field(r, "txn_id")
            if t_id:
                held_tx_ids.append(t_id)
        except HTTPException as ex_val:
            logger.warning("Skipping alert %s during bulk resolve due to illegal transition: %s", r["id"], ex_val.detail)
    return valid_ids, held_tx_ids


async def _dispatch_bulk_resolution_events(
    count: int, valid_ids: list, current_user: dict, tenant_id, payload: BulkAlertAction
):
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
            "alert_ids": [str(x) for x in valid_ids],
            "justification": payload.justification,
        },
    )

    from routers.metrics import ws_manager

    await ws_manager.broadcast(
        {
            "event": "BULK_ALERTS_RESOLVED",
            "tenant_id": str(tenant_id),
            "count": count,
            "action": payload.action,
            "resolved_by": current_user["username"],
        },
        target_tenant_id=str(tenant_id),
    )


@router.patch("")
@router.post("/bulk-action")
async def bulk_resolve_alerts(
    payload: BulkAlertAction,
    request: Request = None,
    current_user: dict = Depends(RoleChecker(["L1_ANALYST", "L2_INVESTIGATOR", "ADMIN", "ANALYST", "MLRO"])),
    _rate_limit=Depends(RateLimiter(limit=10, window=60)),
):
    """Executes atomic batch operations for up to 100 alerts simultaneously (mandatory Idempotency-Key)."""
    caller_role = str(current_user.get("role") or "").upper()
    if payload.action in ("CLOSE_SAR", "CLOSE_FALSE_POSITIVE", "ASSIGN") and caller_role == "L1_ANALYST":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Privilege Separation: L1_ANALYST cannot bulk-close or reassign alerts; escalate or claim instead.",
        )
    if payload.action == "CLOSE_SAR" and caller_role not in ("MLRO", "ADMIN", "TENANT_ADMIN", "SUPER_ADMIN"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Privilege Separation: Bulk CLOSE_SAR requires MLRO or ADMIN authorization.",
        )

    try:
        alert_uuids = [uuid.UUID(aid) for aid in payload.alert_ids]
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid UUID format in alert_ids array.")

    tenant_id = enforce_tenant_data_scope(current_user)

    async def _execute_bulk():
        try:
            if payload.action in ("CLAIM", "ASSIGN"):
                processed = await bulk_claim_or_assign_alerts_atomic(
                    tenant_id=tenant_id,
                    alert_uuids=alert_uuids,
                    action=payload.action,
                    assignee_username=payload.assignee_username,
                    current_user=current_user,
                    conn_factory=get_async_db_conn,
                )
                return {
                    "processed_count": processed,
                    "action": payload.action,
                    "status": "IN_REVIEW",
                    "message": f"Successfully processed {processed} alerts ({payload.action}).",
                }

            if payload.action == "CORRELATE_CASE":
                res = await bulk_correlate_alerts_repo(
                    tenant_id=tenant_id,
                    alert_ids=payload.alert_ids,
                    current_user=current_user,
                    conn_factory=get_async_db_conn,
                )
                return {
                    "processed_count": res["processed_alerts"],
                    "action": payload.action,
                    "status": "CORRELATED",
                    "merged_count": res["merged_count"],
                    "created_count": res["created_count"],
                    "cases": res["cases"],
                    "message": f"Correlated {res['processed_alerts']} alerts into {len(res['cases'])} entity case(s).",
                }

            next_status = "CLOSED_SAR" if payload.action == "CLOSE_SAR" else "CLOSED_FALSE_POSITIVE"
            valid_ids = await bulk_resolve_alerts_atomic(
                tenant_id=tenant_id,
                alert_uuids=alert_uuids,
                action=payload.action,
                justification=payload.justification,
                next_status=next_status,
                current_user=current_user,
                filter_transitions_fn=_filter_valid_alert_transitions,
                conn_factory=get_async_db_conn,
            )
            if not valid_ids:
                return {
                    "processed_count": 0,
                    "action": payload.action,
                    "status": next_status,
                    "message": "No eligible alerts could be transitioned.",
                }

            count = len(valid_ids)
            await _dispatch_bulk_resolution_events(count, valid_ids, current_user, tenant_id, payload)
            return {
                "processed_count": count,
                "action": payload.action,
                "status": next_status,
                "message": f"Successfully processed {count} alerts in batch transaction.",
            }
        except HTTPException:
            raise
        except Exception:
            logger.exception("Bulk alert action failed")
            raise HTTPException(status_code=500, detail="Bulk alert action failed.")

    return await run_idempotent_operation(
        request=request,
        tenant_id=str(tenant_id),
        scope="alerts:bulk_action",
        body=payload.model_dump(),
        handler=_execute_bulk,
        required=True,
    )


def sanitize_csv_cell(value: object) -> object:
    """Neutralizes CSV formula injection (CWE-1236) by escaping formula trigger characters."""
    if isinstance(value, str) and value:
        if value[0] in ("=", "+", "-", "@", "\t", "\r"):
            return f"'{value}"
    return value


@router.get("/export/csv")
async def export_alerts_csv(
    current_user: dict = Depends(RoleChecker(["ADMIN", "ANALYST", "AUDITOR"])),
    _rate_limit=Depends(RateLimiter(limit=10, window=60)),
):
    """Exports PostgreSQL compliance alerts audit ledger as streamed CSV (CWE-1236 safe)."""
    tenant_id = enforce_tenant_data_scope(current_user)

    async def stream_csv_rows():
        try:
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(
                [
                    "Alert ID",
                    "Threat Level",
                    "AI Risk Score",
                    "Rule Trigger",
                    "Status",
                    "Triggered At",
                    "Amount",
                    "Currency",
                    "Sender Account",
                    "Receiver Account",
                    "Assigned Officer",
                ]
            )
            yield output.getvalue()
            output.seek(0)
            output.truncate(0)

            async for rows in iter_alert_export_chunks_repo(
                tenant_id=tenant_id,
                chunk_size=1000,
                read_conn_factory=get_async_db_read_conn,
            ):
                for row in rows:
                    writer.writerow(
                        [
                            sanitize_csv_cell(str(row["id"])),
                            sanitize_csv_cell(row["threat_level"]),
                            f"{round(float(row['ai_risk_score'] or 0) * 100, 1)}%",
                            sanitize_csv_cell(row["rule_name"]),
                            sanitize_csv_cell(row["status"]),
                            row["created_at"].isoformat(),
                            str(row["amount"]),
                            sanitize_csv_cell(row["currency"]),
                            sanitize_csv_cell(row["sender"]),
                            sanitize_csv_cell(row["receiver"]),
                            sanitize_csv_cell(row["assignee"]),
                        ]
                    )
                yield output.getvalue()
                output.seek(0)
                output.truncate(0)
        except Exception:
            logger.exception("CSV streaming failed")
            raise

    filename = f"aml_alerts_audit_export_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv"
    return StreamingResponse(
        stream_csv_rows(),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.get("/export/pdf")
async def export_alerts_pdf(
    async_mode: bool = Query(default=False),
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    current_user: dict = Depends(RoleChecker(["ADMIN", "ANALYST", "AUDITOR"])),
    _rate_limit=Depends(RateLimiter(limit=10, window=60)),
):
    """Generates a printable audit report off the asyncio event loop, or queues asynchronously when async_mode=true."""
    tenant_id = enforce_tenant_data_scope(current_user)
    if async_mode:
        from fastapi.responses import JSONResponse
        from repositories.jobs_repo import enqueue_async_job_atomic
        from services.async_jobs import JOBS_EXPORTS_TOPIC

        job, deduplicated = await enqueue_async_job_atomic(
            tenant_id=str(tenant_id),
            job_type="ALERT_PDF_EXPORT",
            payload={"limit": 100},
            requested_by=str(current_user.get("username") or current_user.get("id") or "analyst"),
            requested_role=str(current_user.get("role") or "ANALYST"),
            topic=JOBS_EXPORTS_TOPIC,
            idempotency_key=idempotency_key,
            conn_factory=get_async_db_conn,
        )
        return JSONResponse(
            status_code=status.HTTP_202_ACCEPTED,
            content={
                "job_id": job["job_id"],
                "job_type": job["job_type"],
                "status": job["status"],
                "deduplicated": deduplicated,
                "status_url": f"/api/v1/jobs/{job['job_id']}",
            },
        )
    try:
        rows = await fetch_alerts_for_pdf_export_repo(
            tenant_id=tenant_id,
            limit=50,
            read_conn_factory=get_async_db_read_conn,
        )

        def _render_pdf_html() -> str:
            import html as _html

            table_rows_html = ""
            for r in rows:
                score = f"{round(float(r['ai_risk_score'] or 0) * 100)}%"
                safe_id = _html.escape(str(r["id"])[:8])
                safe_threat = _html.escape(str(r["threat_level"] or ""))
                safe_rule = _html.escape(str(r["rule_name"] or ""))
                safe_curr = _html.escape(str(r["currency"] or ""))
                safe_status = _html.escape(str(r["status"] or ""))
                safe_assignee = _html.escape(str(r["assignee"] or ""))
                table_rows_html += f"""
                <tr>
                    <td style="padding: 6px; border-bottom: 1px solid #ddd; font-family: monospace;">{safe_id}...</td>
                    <td style="padding: 6px; border-bottom: 1px solid #ddd;"><strong>{safe_threat}</strong></td>
                    <td style="padding: 6px; border-bottom: 1px solid #ddd;">{score}</td>
                    <td style="padding: 6px; border-bottom: 1px solid #ddd;">{safe_rule}</td>
                    <td style="padding: 6px; border-bottom: 1px solid #ddd;">${float(r['amount']):,.2f} {safe_curr}</td>
                    <td style="padding: 6px; border-bottom: 1px solid #ddd;">{safe_status}</td>
                    <td style="padding: 6px; border-bottom: 1px solid #ddd;">{safe_assignee}</td>
                </tr>
                """

            safe_officer = _html.escape(str(current_user.get("username", "")))
            safe_role = _html.escape(str(current_user.get("role", "")))
            return f"""
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
                <p><strong>Auditor / Officer:</strong> {safe_officer} ({safe_role})</p>
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

        from services.compute_executor import run_analytics_compute

        html_content = await run_analytics_compute(_render_pdf_html, timeout=10.0)
        return HTMLResponse(content=html_content)
    except HTTPException:
        raise
    except Exception:
        logger.exception("PDF/HTML report generation failed")
        raise HTTPException(status_code=500, detail="Report export failed.")


def generate_sar_xml(alert_data, justification: str) -> str:
    """Generates a regulatory FinCEN-compatible Suspicious Activity Report XML payload."""
    if len(alert_data) == 13:
        alert_id, _tx_id, rule_name, threat, score, _status, amt, curr, ts, s_acc, s_owner, r_acc, r_owner = alert_data
    else:
        alert_id, rule_name, threat, score, amt, curr, ts, s_acc, s_owner, r_acc, r_owner = alert_data

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
    ET.SubElement(transaction, "Timestamp").text = ts.isoformat() if hasattr(ts, "isoformat") else str(ts)

    sender = ET.SubElement(transaction, "Sender")
    ET.SubElement(sender, "AccountNumber").text = s_acc
    ET.SubElement(sender, "OwnerName").text = s_owner

    receiver = ET.SubElement(transaction, "Receiver")
    ET.SubElement(receiver, "AccountNumber").text = r_acc
    ET.SubElement(receiver, "OwnerName").text = r_owner

    ET.indent(root, space="  ")
    return ET.tostring(root, encoding="utf-8").decode("utf-8")
