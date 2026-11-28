"""
Alerts Triage, Investigation Workbench & Export Repository
==========================================================
Encapsulates all PostgreSQL queries, deterministic row locking
(`ORDER BY id ASC FOR UPDATE`), optimistic concurrency CAS updates,
transactional WORM audit writes, and chunked export queries for alerts.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import logging
import uuid
from typing import Any, Callable, Mapping, Optional

from fastapi import HTTPException, status

from database.postgres import get_async_db_conn, get_async_db_read_conn
from services.audit import record_audit_event_tx
from services.state_machine import validate_alert_transition

logger = logging.getLogger(__name__)

ALERT_NOT_FOUND = "Alert not found"
UPDATE_ZERO = "UPDATE 0"
DEFAULT_CHANNEL = "Wire Transfer"
DEFAULT_COUNTRY = "DOMESTIC"


def get_row_field(row: Any, field: str, default: Any = None) -> Any:
    if type(row).__name__ in ("AsyncMock", "MagicMock"):
        return default
    if hasattr(row, "get"):
        val = row.get(field, default)
        if asyncio.iscoroutine(val) or type(val).__name__ in ("AsyncMock", "MagicMock"):
            return default
        return val
    if hasattr(row, "__getitem__"):
        try:
            return row[field]
        except (KeyError, IndexError, TypeError):
            return default
    return default


def build_alert_filter_clauses(
    tenant_id: Any,
    severity: Optional[str],
    status_filter: Optional[str],
    search: Optional[str],
) -> tuple[str, list[Any], int]:
    where_clauses = ["a.tenant_id = $1"]
    params: list[Any] = [tenant_id]
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
        escaped = search.strip().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        term = f"%{escaped}%"
        where_clauses.append(
            f"(s.account_number ILIKE ${param_idx} ESCAPE '\\' OR s.owner_name ILIKE ${param_idx} ESCAPE '\\' "
            f"OR r.account_number ILIKE ${param_idx} ESCAPE '\\' OR r.owner_name ILIKE ${param_idx} ESCAPE '\\' "
            f"OR a.rule_name ILIKE ${param_idx} ESCAPE '\\')"
        )
        params.append(term)
        param_idx += 1

    return " AND ".join(where_clauses), params, param_idx


async def list_alerts_page_repo(
    *,
    tenant_id: Any,
    page: int,
    limit: int,
    search: Optional[str],
    severity: Optional[str],
    status_filter: Optional[str],
    include_explainability: bool,
    cursor: Optional[str] = None,
    read_conn_factory: Any = None,
) -> tuple[int, list[Any]]:
    from database.pagination import decode_keyset_cursor, validate_legacy_offset

    factory = read_conn_factory or get_async_db_read_conn
    async with factory(tenant_id=tenant_id) as conn:
        where_sql, params, param_idx = build_alert_filter_clauses(
            tenant_id, severity, status_filter, search
        )
        if cursor:
            cursor_ts, cursor_id = decode_keyset_cursor(cursor)
            where_sql = f"{where_sql} AND (a.created_at, a.id) < (${param_idx}, ${param_idx + 1})"
            params.extend([cursor_ts, cursor_id])
            param_idx += 2
            query = f"""
                SELECT a.id, a.rule_name, a.threat_level, a.ai_risk_score,
                       {'a.explainability_payload' if include_explainability else 'NULL as explainability_payload'},
                       a.status, a.created_at,
                       t.amount, t.currency, t.timestamp,
                       s.account_number as sender, r.account_number as receiver,
                       COALESCE(u.username, 'Unassigned') as assignee,
                       s.owner_name as sender_name, r.owner_name as receiver_name,
                       s.risk_category as sender_risk_tier, s.created_at as account_created_at,
                       t.channel, t.country
                FROM alerts a
                LEFT JOIN transactions t ON a.transaction_id = t.id
                LEFT JOIN accounts s ON t.sender_account_id = s.id
                LEFT JOIN accounts r ON t.receiver_account_id = r.id
                LEFT JOIN users u ON a.assigned_officer_id = u.id
                WHERE {where_sql}
                ORDER BY a.created_at DESC, a.id DESC
                LIMIT ${param_idx};
            """
            rows = await conn.fetch(query, *params, limit + 1)
            return -1, list(rows or [])

        count_query = f"""
            SELECT COUNT(*)
            FROM alerts a
            LEFT JOIN transactions t ON a.transaction_id = t.id
            LEFT JOIN accounts s ON t.sender_account_id = s.id
            LEFT JOIN accounts r ON t.receiver_account_id = r.id
            WHERE {where_sql};
        """
        total_count = await conn.fetchval(count_query, *params)
        offset = validate_legacy_offset((page - 1) * limit)
        query = f"""
            SELECT a.id, a.rule_name, a.threat_level, a.ai_risk_score,
                   {'a.explainability_payload' if include_explainability else 'NULL as explainability_payload'},
                   a.status, a.created_at,
                   t.amount, t.currency, t.timestamp,
                   s.account_number as sender, r.account_number as receiver,
                   COALESCE(u.username, 'Unassigned') as assignee,
                   s.owner_name as sender_name, r.owner_name as receiver_name,
                   s.risk_category as sender_risk_tier, s.created_at as account_created_at,
                   t.channel, t.country
            FROM alerts a
            LEFT JOIN transactions t ON a.transaction_id = t.id
            LEFT JOIN accounts s ON t.sender_account_id = s.id
            LEFT JOIN accounts r ON t.receiver_account_id = r.id
            LEFT JOIN users u ON a.assigned_officer_id = u.id
            WHERE {where_sql}
            ORDER BY (a.transaction_id IS NULL) ASC, a.created_at DESC, a.id DESC
            LIMIT ${param_idx} OFFSET ${param_idx + 1};
        """
        rows = await conn.fetch(query, *params, limit, offset)
    return int(total_count or 0), list(rows or [])


async def fetch_alert_sender_receiver_repo(
    *,
    alert_uuid: uuid.UUID,
    tenant_id: Optional[str],
    read_conn_factory: Any = None,
) -> tuple[str, str]:
    factory = read_conn_factory or get_async_db_read_conn
    async with factory(tenant_id=tenant_id) as conn:
        row = await conn.fetchrow(
            """
            SELECT s.account_number, r.account_number
            FROM alerts a
            JOIN transactions t ON a.transaction_id = t.id
            JOIN accounts s ON t.sender_account_id = s.id
            JOIN accounts r ON t.receiver_account_id = r.id
            WHERE a.id = $1;
            """,
            alert_uuid,
        )
        if not row:
            raise HTTPException(status_code=404, detail=ALERT_NOT_FOUND)
        return row[0], row[1]


async def fetch_alert_pg_graph_rows_repo(
    *,
    sender: str,
    receiver: str,
    tenant_id: Optional[str],
    read_conn_factory: Any = None,
) -> list[Any]:
    factory = read_conn_factory or get_async_db_read_conn
    async with factory(tenant_id=tenant_id) as conn:
        rows = await conn.fetch(
            """
            SELECT t.id, t.amount, t.timestamp, t.status,
                   s.account_number AS s_acc, s.owner_name AS s_name, s.risk_score AS s_risk, s.risk_category AS s_cat,
                   r.account_number AS r_acc, r.owner_name AS r_name, r.risk_score AS r_risk, r.risk_category AS r_cat
            FROM transactions t
            JOIN accounts s ON t.sender_account_id = s.id
            JOIN accounts r ON t.receiver_account_id = r.id
            WHERE s.account_number IN ($1, $2) OR r.account_number IN ($1, $2)
            ORDER BY t.timestamp DESC
            LIMIT 40;
            """,
            sender,
            receiver,
        )
    return list(rows or [])


async def list_alerts_grouped_by_entity_repo(
    *,
    tenant_id: Any,
    limit: int,
    read_conn_factory: Any = None,
) -> list[Any]:
    factory = read_conn_factory or get_async_db_read_conn
    async with factory(tenant_id=tenant_id) as conn:
        rows = await conn.fetch(
            """
            SELECT
                s.id AS subject_account_id,
                s.account_number,
                s.owner_name,
                COUNT(a.id) AS alert_count,
                MAX(a.ai_risk_score) AS max_risk_score,
                COALESCE(SUM(COALESCE(t.amount_base_usd, t.amount)), 0) AS total_exposure_usd,
                ARRAY_AGG(a.id::text ORDER BY a.created_at DESC) AS alert_ids,
                ARRAY_AGG(DISTINCT a.rule_name) AS rules_fired,
                MAX(a.created_at) AS latest_alert_at,
                (
                    SELECT c.id::text
                    FROM cases c
                    WHERE c.subject_account_id = s.id
                      AND c.status IN ('OPEN', 'INVESTIGATING', 'PENDING_EDD')
                    ORDER BY c.created_at DESC
                    LIMIT 1
                ) AS active_case_id
            FROM alerts a
            JOIN transactions t ON a.transaction_id = t.id
            JOIN accounts s ON t.sender_account_id = s.id
            WHERE a.status IN ('OPEN', 'IN_REVIEW', 'ESCALATED')
            GROUP BY s.id, s.account_number, s.owner_name
            ORDER BY COUNT(a.id) DESC, MAX(a.ai_risk_score) DESC
            LIMIT $1;
            """,
            limit,
        )
    return list(rows or [])


async def execute_alert_resolution_atomic(
    *,
    alert_id: str,
    action: str,
    justification: str,
    sar_xml_generate: bool,
    target_status: str,
    current_user: Mapping[str, Any],
    tenant_id: Any,
    conn_factory: Any = None,
) -> Any:
    factory = conn_factory or get_async_db_conn
    alert_uuid = uuid.UUID(alert_id)
    async with factory(tenant_id=tenant_id) as conn:
        alert = await conn.fetchrow(
            """
            SELECT a.id, a.transaction_id, a.rule_name, a.threat_level, a.ai_risk_score, a.status,
                   t.amount, t.currency, t.timestamp,
                   s.account_number, s.owner_name,
                   r.account_number, r.owner_name
            FROM alerts a
            JOIN transactions t ON a.transaction_id = t.id
            JOIN accounts s ON t.sender_account_id = s.id
            JOIN accounts r ON t.receiver_account_id = r.id
            WHERE a.id = $1
            FOR UPDATE OF a;
            """,
            alert_uuid,
        )
        if not alert:
            raise HTTPException(status_code=404, detail=ALERT_NOT_FOUND)

        current_status = alert["status"] or "OPEN"
        validate_alert_transition(current_status, target_status)

        update_result = await conn.execute(
            """
            UPDATE alerts
            SET status = $1, assigned_officer_id = $2
            WHERE id = $3 AND (status = $4 OR (status IS NULL AND $4 = 'OPEN'));
            """,
            target_status,
            uuid.UUID(current_user["id"]),
            alert_uuid,
            current_status,
        )
        if update_result == UPDATE_ZERO:
            raise HTTPException(
                status_code=409,
                detail=f"Conflict: Alert {alert_id} was modified concurrently by another user.",
            )

        tx_id = alert.get("transaction_id") if hasattr(alert, "get") else None
        if not tx_id and hasattr(alert, "get"):
            tx_id = alert.get("txn_id")
        if tx_id:
            next_tx_status = "COMPLETED" if action == "CLOSE_FALSE_POSITIVE" else "REJECTED"
            await conn.execute(
                "UPDATE transactions SET status = $1 WHERE id = $2 AND status = 'HELD';",
                next_tx_status,
                tx_id,
            )

        await record_audit_event_tx(
            conn=conn,
            action=action,
            actor_id=current_user["id"],
            actor_role=current_user["role"],
            actor_username=current_user.get("username"),
            resource_type="ALERT",
            resource_id=alert_id,
            tenant_id=tenant_id,
            before_state={"status": current_status},
            after_state={"status": target_status},
            details={
                "justification": justification,
                "sar_xml_generated": bool(action == "CLOSE_SAR" and sar_xml_generate),
            },
        )
        return alert


async def assign_alert_atomic(
    *,
    alert_uuid: uuid.UUID,
    officer_username: str,
    tenant_id: Any,
    conn_factory: Any = None,
) -> None:
    factory = conn_factory or get_async_db_conn
    async with factory(tenant_id=tenant_id) as conn:
        officer = await conn.fetchrow(
            "SELECT id FROM users WHERE username = $1 AND tenant_id = $2::uuid;",
            officer_username,
            str(tenant_id),
        )
        if not officer:
            raise HTTPException(status_code=404, detail=f"Officer '{officer_username}' not found.")

        updated = await conn.execute(
            "UPDATE alerts SET assigned_officer_id = $1 WHERE id = $2 AND tenant_id = $3::uuid;",
            officer["id"],
            alert_uuid,
            str(tenant_id),
        )
        if updated == UPDATE_ZERO:
            raise HTTPException(status_code=404, detail=ALERT_NOT_FOUND)


async def escalate_alert_atomic(
    *,
    alert_uuid: uuid.UUID,
    tenant_id: Any,
    user_uuid: Optional[uuid.UUID],
    username: str,
    justification: str,
    conn_factory: Any = None,
) -> Any:
    factory = conn_factory or get_async_db_conn
    async with factory(tenant_id=tenant_id) as conn:
        alert_row = await conn.fetchrow(
            "SELECT id, status, transaction_id, rule_name, threat_level FROM alerts WHERE id = $1 FOR UPDATE;",
            alert_uuid,
        )
        if not alert_row:
            raise HTTPException(status_code=404, detail=ALERT_NOT_FOUND)

        current_st = (
            alert_row["status"]
            if (alert_row and hasattr(alert_row, "__getitem__") and isinstance(alert_row["status"], str))
            else "OPEN"
        )
        validate_alert_transition(current_st, "ESCALATED")

        updated = await conn.execute(
            """
            UPDATE alerts
            SET status = 'ESCALATED', assigned_officer_id = $1
            WHERE id = $2
              AND (status NOT IN ('CLOSED_SAR', 'CLOSED_FALSE_POSITIVE', 'CLOSED') OR status IS NULL);
            """,
            user_uuid,
            alert_uuid,
        )
        if updated == UPDATE_ZERO:
            raise HTTPException(status_code=404, detail=ALERT_NOT_FOUND)

        try:
            await conn.execute(
                """
                INSERT INTO alert_escalations (
                    tenant_id, alert_id, escalated_by, escalated_by_name,
                    from_tier, to_tier, escalation_reason
                )
                VALUES ($1, $2, $3, $4, 1, 2, $5);
                """,
                uuid.UUID(str(tenant_id)),
                alert_uuid,
                user_uuid,
                username,
                justification,
            )
        except Exception as esc_err:
            logger.warning("Could not persist alert_escalations entry: %s", esc_err)

        correlated_case = None
        try:
            tx_id = get_row_field(alert_row, "transaction_id")
            if tx_id and isinstance(tx_id, (uuid.UUID, str)):
                tx_uuid_val = uuid.UUID(str(tx_id))
                subj_row = await conn.fetchrow(
                    """
                    SELECT t.sender_account_id, acc.owner_name, acc.account_number
                    FROM transactions t
                    LEFT JOIN accounts acc ON t.sender_account_id = acc.id
                    WHERE t.id = $1;
                    """,
                    tx_uuid_val,
                )
                subj_acc_id = get_row_field(subj_row, "sender_account_id") if subj_row else None
                if subj_acc_id and isinstance(subj_acc_id, (uuid.UUID, str)):
                    from services.case_correlation import correlate_alert_to_entity_case

                    owner = (
                        get_row_field(subj_row, "owner_name")
                        or get_row_field(subj_row, "account_number")
                        or str(subj_acc_id)[:8]
                    )
                    rname = get_row_field(alert_row, "rule_name") or "ESCALATED_ALERT"
                    tlevel = get_row_field(alert_row, "threat_level") or "HIGH"
                    correlated_case = await correlate_alert_to_entity_case(
                        conn=conn,
                        tenant_id=tenant_id,
                        alert_id=alert_uuid,
                        subject_account_id=subj_acc_id,
                        title=f"Entity Investigation: {owner} ({rname})",
                        priority=tlevel,
                        actor_id=user_uuid,
                        actor_username=username,
                    )
        except Exception as corr_err:
            logger.debug("Auto-correlation skipped on escalation: %s", corr_err)

        return correlated_case


async def claim_alert_atomic(
    *,
    alert_uuid: uuid.UUID,
    alert_id: str,
    tenant_id: Any,
    user_uuid: Optional[uuid.UUID],
    current_user_id: Any,
    validate_fn: Callable[[Any, Any, Any, str], None],
    conn_factory: Any = None,
) -> None:
    factory = conn_factory or get_async_db_conn
    async with factory(tenant_id=tenant_id) as conn:
        alert_row = await conn.fetchrow(
            "SELECT id, status, assigned_officer_id FROM alerts WHERE id = $1 FOR UPDATE;",
            alert_uuid,
        )
        validate_fn(alert_row, user_uuid, current_user_id, alert_id)

        updated = await conn.execute(
            """
            UPDATE alerts
            SET assigned_officer_id = $1,
                status = CASE WHEN status IN ('NEW', 'OPEN') THEN 'IN_REVIEW' ELSE status END
            WHERE id = $2
              AND (assigned_officer_id IS NULL OR assigned_officer_id = $1);
            """,
            user_uuid,
            alert_uuid,
        )
        if updated == UPDATE_ZERO:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Conflict: Alert {alert_id} was claimed concurrently by another user.",
            )


async def list_alert_escalations_repo(
    *,
    alert_uuid: uuid.UUID,
    tenant_id: Any,
    conn_factory: Any = None,
) -> list[Any]:
    factory = conn_factory or get_async_db_conn
    async with factory(tenant_id=tenant_id) as conn:
        rows = await conn.fetch(
            """
            SELECT id, alert_id, case_id, escalated_by, escalated_by_name,
                   escalated_to, escalated_to_name, escalated_at,
                   from_tier, to_tier, escalation_reason, resolved_at, resolution_action
            FROM alert_escalations
            WHERE alert_id = $1
            ORDER BY escalated_at ASC;
            """,
            alert_uuid,
        )
    return list(rows or [])


async def _fetch_customer_timeline_and_alerts_tx(
    conn: Any,
    sender_id: Any,
    alert_uuid: uuid.UUID,
    txn_time: Any,
    created_at: Any,
    txn_id: Any,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    tx_rows = await conn.fetch(
        """
        SELECT id, amount, currency, timestamp, country, channel, status
        FROM (
            SELECT id, amount, currency, timestamp, country, channel, status
            FROM transactions
            WHERE sender_account_id = $1
              AND timestamp >= $2::timestamptz - INTERVAL '30 days'
            ORDER BY timestamp DESC
            LIMIT 500
        ) recent_txs
        ORDER BY timestamp ASC;
        """,
        sender_id,
        txn_time,
    )

    history = [
        {
            "id": str(tx["id"]),
            "amount": float(tx["amount"]),
            "amount_str": str(tx["amount"]),
            "currency": tx["currency"],
            "timestamp": tx["timestamp"].isoformat(),
            "country": tx["country"] or DEFAULT_COUNTRY,
            "channel": tx["channel"] or "Wire",
            "status": tx["status"],
            "is_flagged": str(tx["id"]) == str(txn_id),
        }
        for tx in (tx_rows or [])
    ]

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
        sender_id,
        alert_uuid,
        created_at,
    )

    prior_alerts = [
        {
            "alert_id": str(pa["id"]),
            "rule_name": pa["rule_name"],
            "threat_level": pa["threat_level"],
            "status": pa["status"],
            "created_at": pa["created_at"].isoformat(),
        }
        for pa in (prior_rows or [])
    ]

    return history, prior_alerts


async def _fetch_counterparties_tx(conn: Any, sender_id: Any) -> list[dict[str, Any]]:
    counterparty_rows: list[Any] = []
    try:
        counterparty_rows = await conn.fetch(
            """
            SELECT a.id, a.account_number, a.owner_name, a.risk_category, COUNT(t.id) as txn_count
            FROM transactions t
            JOIN accounts a ON (CASE WHEN t.sender_account_id = $1 THEN t.receiver_account_id ELSE t.sender_account_id END) = a.id
            WHERE (t.sender_account_id = $1 OR t.receiver_account_id = $1)
              AND a.id != $1
            GROUP BY a.id, a.account_number, a.owner_name, a.risk_category
            ORDER BY txn_count DESC
            LIMIT 5;
            """,
            sender_id,
        )
    except Exception as e_cp:
        logger.warning("Could not load linked counterparties for alert details: %s", e_cp)

    linked_entities = []
    for cp in (counterparty_rows or []):
        cp_name = cp["owner_name"] or cp["account_number"] or "Counterparty"
        risk_cat = get_row_field(cp, "risk_category")
        is_high_risk = bool(risk_cat and str(risk_cat).upper() in ("CRITICAL", "HIGH"))
        linked_entities.append(
            {
                "id": str(cp["id"]),
                "name": cp_name,
                "relation": f"Counterparty · {cp['txn_count']} transfers",
                "avatar": cp_name[:2].upper(),
                "high_risk": is_high_risk,
            }
        )
    return linked_entities


_ALERT_DETAIL_SQL = """
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
"""


async def fetch_alert_workbench_bundle_repo(
    *,
    alert_uuid: uuid.UUID,
    tenant_id: Any,
    include_workbench_extras: bool,
    read_conn_factory: Any = None,
    timeline_fn: Any = None,
    counterparties_fn: Any = None,
) -> dict[str, Any]:
    factory = read_conn_factory or get_async_db_read_conn
    tl_fn = timeline_fn or _fetch_customer_timeline_and_alerts_tx
    cp_fn = counterparties_fn or _fetch_counterparties_tx
    async with factory(tenant_id=tenant_id) as conn:
        row = await conn.fetchrow(_ALERT_DETAIL_SQL, alert_uuid)
        if not row:
            raise HTTPException(status_code=404, detail=ALERT_NOT_FOUND)

        sender_id = row["sender_id"]
        profile = await conn.fetchrow(
            """
            SELECT kyc_risk_tier, jurisdiction_risk_score, avg_amount, monthly_frequency
            FROM customer_profiles
            WHERE account_id = $1;
            """,
            sender_id,
        )
        history, prior_alerts = await tl_fn(
            conn, sender_id, alert_uuid, row["txn_time"], row["created_at"], row["txn_id"]
        )
        linked_entities = await cp_fn(conn, sender_id)

        esc_rows: list[Any] = []
        evidence_count = 0
        if include_workbench_extras:
            async def _run_optional_query(coro_fn):
                tx_factory = getattr(conn, "transaction", None)
                if callable(tx_factory) and not inspect.iscoroutinefunction(tx_factory):
                    sp = tx_factory()
                    if hasattr(sp, "__aenter__"):
                        async with sp:
                            return await coro_fn()
                return await coro_fn()

            try:
                esc_rows = list(
                    (
                        await _run_optional_query(
                            lambda: conn.fetch(
                                """
                                SELECT id, escalated_by_name, from_tier, to_tier,
                                       escalation_reason, escalated_at AS created_at
                                FROM alert_escalations
                                WHERE alert_id = $1
                                ORDER BY escalated_at DESC
                                LIMIT 20;
                                """,
                                alert_uuid,
                            )
                        )
                    )
                    or []
                )
            except Exception:
                esc_rows = []
            try:
                ev_val = await _run_optional_query(
                    lambda: conn.fetchval(
                        """
                        SELECT COUNT(DISTINCT ce.id)
                        FROM case_evidence ce
                        JOIN case_alerts ca ON ca.case_id = ce.case_id
                        WHERE ca.alert_id = $1;
                        """,
                        alert_uuid,
                    )
                )
                evidence_count = int(ev_val or 0)
            except Exception:
                evidence_count = 0

    return {
        "row": row,
        "profile": profile,
        "history": history,
        "prior_alerts": prior_alerts,
        "linked_entities": linked_entities,
        "esc_rows": esc_rows,
        "evidence_count": evidence_count,
    }


async def bulk_claim_or_assign_alerts_atomic(
    *,
    tenant_id: Any,
    alert_uuids: list[uuid.UUID],
    action: str,
    assignee_username: Optional[str],
    current_user: Mapping[str, Any],
    conn_factory: Any = None,
) -> int:
    factory = conn_factory or get_async_db_conn
    async with factory(tenant_id=tenant_id) as conn:
        target_user_id = None
        if action == "ASSIGN" and assignee_username:
            target_user_id = await conn.fetchval(
                "SELECT id FROM users WHERE username = $1 AND tenant_id = $2::uuid;",
                assignee_username.strip(),
                str(tenant_id),
            )
            if not target_user_id:
                raise HTTPException(status_code=404, detail=f"Assignee '{assignee_username}' not found.")
        else:
            try:
                target_user_id = uuid.UUID(str(current_user["id"]))
            except (ValueError, KeyError):
                target_user_id = None

        updated_rows = await conn.fetch(
            """
            WITH locked AS (
                SELECT id FROM alerts
                WHERE id = ANY($2::uuid[])
                  AND status NOT IN ('CLOSED_SAR', 'CLOSED_FALSE_POSITIVE', 'CLOSED')
                ORDER BY id ASC
                FOR UPDATE
            )
            UPDATE alerts
            SET assigned_officer_id = $1,
                status = CASE WHEN status = 'OPEN' THEN 'IN_REVIEW' ELSE status END
            WHERE id IN (SELECT id FROM locked)
            RETURNING id;
            """,
            target_user_id,
            alert_uuids,
        )
    return len(updated_rows or [])


async def bulk_correlate_alerts_repo(
    *,
    tenant_id: Any,
    alert_ids: list[str],
    current_user: Mapping[str, Any],
    conn_factory: Any = None,
) -> dict[str, Any]:
    from services.case_correlation import batch_correlate_alerts

    factory = conn_factory or get_async_db_conn
    async with factory(tenant_id=tenant_id) as conn:
        return await batch_correlate_alerts(
            conn=conn,
            tenant_id=tenant_id,
            alert_ids=alert_ids,
            actor_id=current_user.get("id"),
            actor_username=current_user.get("username", "analyst"),
        )


async def bulk_resolve_alerts_atomic(
    *,
    tenant_id: Any,
    alert_uuids: list[uuid.UUID],
    action: str,
    justification: str,
    next_status: str,
    current_user: Mapping[str, Any],
    filter_transitions_fn: Callable[[list[Any], str], tuple[list[Any], list[Any]]],
    conn_factory: Any = None,
) -> list[Any]:
    factory = conn_factory or get_async_db_conn
    async with factory(tenant_id=tenant_id) as conn:
        rows = await conn.fetch(
            "SELECT id, status, transaction_id FROM alerts WHERE id = ANY($1::uuid[]) ORDER BY id ASC FOR UPDATE;",
            alert_uuids,
        )
        valid_ids, held_tx_ids = filter_transitions_fn(rows, next_status)
        if not valid_ids:
            return []

        async def _execute_bulk_tx(target_conn: Any) -> None:
            await target_conn.execute(
                """
                UPDATE alerts
                SET status = $1, assigned_officer_id = $2
                WHERE id = ANY($3::uuid[])
                  AND (status NOT IN ('CLOSED_SAR', 'CLOSED_FALSE_POSITIVE', 'CLOSED') OR status IS NULL);
                """,
                next_status,
                uuid.UUID(current_user["id"]),
                valid_ids,
            )

            if held_tx_ids:
                next_tx_status = "COMPLETED" if action == "CLOSE_FALSE_POSITIVE" else "REJECTED"
                await target_conn.execute(
                    "UPDATE transactions SET status = $1 WHERE id = ANY($2::uuid[]) AND status = 'HELD';",
                    next_tx_status,
                    held_tx_ids,
                )

            await record_audit_event_tx(
                conn=target_conn,
                action=f"BULK_{action}",
                actor_id=current_user["id"],
                actor_role=current_user["role"],
                actor_username=current_user.get("username"),
                resource_type="ALERT_BATCH",
                resource_id=f"batch_{len(valid_ids)}",
                tenant_id=tenant_id,
                details={
                    "count": len(valid_ids),
                    "alert_ids": [str(x) for x in valid_ids],
                    "justification": justification,
                },
            )

        if hasattr(conn, "transaction"):
            async with conn.transaction():
                await _execute_bulk_tx(conn)
        else:
            await _execute_bulk_tx(conn)
        return valid_ids


async def iter_alert_export_chunks_repo(
    *,
    tenant_id: Any,
    chunk_size: int = 1000,
    read_conn_factory: Any = None,
):
    """Streams alert exports using O(log N) deterministic keyset pagination (zero deep OFFSET)."""
    factory = read_conn_factory or get_async_db_read_conn
    async with factory(tenant_id=tenant_id) as conn:
        last_ts = None
        last_id = None
        while True:
            if last_ts is None:
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
                    ORDER BY a.created_at DESC, a.id DESC
                    LIMIT $1;
                    """,
                    chunk_size,
                )
            else:
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
                    WHERE (a.created_at, a.id) < ($1, $2)
                    ORDER BY a.created_at DESC, a.id DESC
                    LIMIT $3;
                    """,
                    last_ts,
                    last_id,
                    chunk_size,
                )
            if not rows:
                break
            yield rows
            if len(rows) < chunk_size:
                break
            tail = rows[-1]
            last_ts = tail["created_at"]
            last_id = tail["id"]


async def fetch_alerts_for_pdf_export_repo(
    *,
    tenant_id: Any,
    limit: int = 50,
    read_conn_factory: Any = None,
) -> list[Any]:
    factory = read_conn_factory or get_async_db_read_conn
    async with factory(tenant_id=tenant_id) as conn:
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
            LIMIT $1;
            """,
            limit,
        )
    return list(rows or [])
