"""
Customer 360, Onboarding & Privacy/GDPR/Legal-Hold Repository
=============================================================
Encapsulates all PostgreSQL queries, tenant RLS scoping, `FOR UPDATE` row
locks, and compensating rollbacks for Customer 360 dossiers, individual &
corporate onboarding, DSAR exports, legal holds, and GDPR Art. 17 erasure.
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from datetime import date as _date, datetime, timedelta, timezone
from typing import Any, Mapping, Optional

from fastapi import HTTPException, status

import database.postgres as _pg

logger = logging.getLogger(__name__)


def _write_factory(conn_factory: Any = None) -> Any:
    return conn_factory or _pg.get_async_db_conn


def _read_factory(read_conn_factory: Any = None) -> Any:
    return read_conn_factory or _pg.get_async_db_read_conn


def _escape_ilike(val: str) -> str:
    return val.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


# ── Customer 360 & pKYC ───────────────────────────────────────────────────────

async def list_customers_repo(
    *,
    tenant_id: str,
    limit: int,
    offset: int,
    search: Optional[str] = None,
    risk_tier: Optional[str] = None,
    account_status: Optional[str] = None,
    cursor: Optional[str] = None,
    read_conn_factory: Any = None,
) -> tuple[int, list[Any]]:
    from database.pagination import decode_keyset_cursor, validate_legacy_offset

    conditions = ["tenant_id = $1"]
    params: list[Any] = [uuid.UUID(str(tenant_id))]
    p_idx = 2

    if search:
        safe_search = _escape_ilike(search)
        conditions.append(
            f"(owner_name ILIKE ${p_idx} ESCAPE '\\' OR account_number ILIKE ${p_idx} ESCAPE '\\' OR swift_bic ILIKE ${p_idx} ESCAPE '\\')"
        )
        params.append(f"%{safe_search}%")
        p_idx += 1

    if risk_tier:
        conditions.append(f"risk_category = ${p_idx}")
        params.append(risk_tier.upper())
        p_idx += 1

    if account_status:
        conditions.append(f"status = ${p_idx}")
        params.append(account_status.upper())
        p_idx += 1

    factory = _read_factory(read_conn_factory)
    async with factory(tenant_id=tenant_id) as conn:
        if cursor:
            c_ts, c_id = decode_keyset_cursor(cursor)
            conditions.append(f"(created_at, id) < (${p_idx}, ${p_idx + 1})")
            params.extend([c_ts, c_id])
            p_idx += 2
            where_clause = " AND ".join(conditions)
            query = f"""
                SELECT id, account_number, swift_bic, owner_name, status,
                       risk_score, risk_category, created_at, frozen_reason
                FROM accounts
                WHERE {where_clause}
                ORDER BY created_at DESC, id DESC
                LIMIT ${p_idx};
            """
            rows = await conn.fetch(query, *params, limit + 1)
            return -1, list(rows or [])

        safe_offset = validate_legacy_offset(offset)
        where_clause = " AND ".join(conditions)
        total = await conn.fetchval(f"SELECT COUNT(*) FROM accounts WHERE {where_clause};", *params)
        query = f"""
            SELECT id, account_number, swift_bic, owner_name, status,
                   risk_score, risk_category, created_at, frozen_reason
            FROM accounts
            WHERE {where_clause}
            ORDER BY risk_score DESC, created_at DESC, id DESC
            LIMIT ${p_idx} OFFSET ${p_idx + 1};
        """
        rows = await conn.fetch(query, *params, limit, safe_offset)
    return int(total or 0), list(rows or [])


async def trigger_pkyc_delta_rescreen_repo(
    *,
    tenant_id: str,
    triggered_by: str,
    limit: int,
    es_client: Any,
    conn_factory: Any = None,
) -> Any:
    from services.pkyc_and_qa import run_pkyc_delta_rescreen

    factory = _write_factory(conn_factory)
    async with factory(tenant_id=tenant_id) as conn:
        return await run_pkyc_delta_rescreen(
            conn=conn,
            tenant_id=tenant_id,
            triggered_by=triggered_by,
            limit=limit,
            es_client=es_client,
        )


async def list_pkyc_rescreen_runs_repo(
    *,
    tenant_id: str,
    limit: int,
    read_conn_factory: Any = None,
) -> list[Any]:
    factory = _read_factory(read_conn_factory)
    async with factory(tenant_id=tenant_id) as conn:
        rows = await conn.fetch(
            """
            SELECT id, triggered_by, accounts_scanned, material_changes_found,
                   alerts_generated, started_at, completed_at
            FROM pkyc_rescreen_runs
            ORDER BY started_at DESC
            LIMIT $1;
            """,
            limit,
        )
    return list(rows or [])


async def fetch_customer_activity_tx(conn: Any, acc_num: str, acc_uuid: uuid.UUID):
    tx_rows = await conn.fetch(
        """
        SELECT id, amount, currency, timestamp,
               sender_account_id, receiver_account_id
        FROM transactions
        WHERE sender_account_id = $1 OR receiver_account_id = $1
        ORDER BY timestamp DESC
        LIMIT 30;
        """,
        acc_uuid,
    )
    recent_txs = [
        {
            "id": str(r["id"]),
            "amount": float(r["amount"]),
            "amount_str": str(r["amount"]),
            "currency": r["currency"],
            "timestamp": r["timestamp"].isoformat() if r["timestamp"] else "",
            "type": "OUTBOUND" if str(r["sender_account_id"]) in (str(acc_uuid), str(acc_num)) else "INBOUND",
            "counterparty": str(
                r["receiver_account_id"]
                if str(r["sender_account_id"]) in (str(acc_uuid), str(acc_num))
                else r["sender_account_id"]
            ),
        }
        for r in (tx_rows or [])
    ]

    monthly_rows = await conn.fetch(
        """
        SELECT TO_CHAR(timestamp, 'YYYY-MM') as month,
               COUNT(*) as tx_count,
               SUM(amount) as total_volume
        FROM transactions
        WHERE (sender_account_id = $1 OR receiver_account_id = $1)
          AND timestamp >= NOW() - INTERVAL '12 months'
        GROUP BY TO_CHAR(timestamp, 'YYYY-MM')
        ORDER BY month ASC;
        """,
        acc_uuid,
    )
    monthly_trend = [
        {"month": r["month"], "tx_count": int(r["tx_count"]), "volume": float(r["total_volume"] or 0.0)}
        for r in (monthly_rows or [])
    ]

    alert_rows = await conn.fetch(
        """
        SELECT a.id, a.rule_name, a.threat_level, a.ai_risk_score, a.status, a.created_at
        FROM alerts a
        JOIN transactions t ON a.transaction_id = t.id
        WHERE t.sender_account_id = $1 OR t.receiver_account_id = $1
        ORDER BY a.created_at DESC
        LIMIT 15;
        """,
        acc_uuid,
    )
    alerts = [
        {
            "id": str(r["id"]),
            "rule_name": r["rule_name"],
            "threat_level": r["threat_level"],
            "score": float(r["ai_risk_score"] or 0.0),
            "status": r["status"],
            "created_at": r["created_at"].isoformat() if r["created_at"] else "",
        }
        for r in (alert_rows or [])
    ]

    edd_rows = await conn.fetch(
        """
        SELECT id, trigger_reason, status, mlro_decision, created_at
        FROM edd_requests
        WHERE account_id = $1
        ORDER BY created_at DESC;
        """,
        acc_uuid,
    )
    edd_records = [
        {
            "id": str(r["id"]),
            "trigger_reason": r["trigger_reason"],
            "status": r["status"],
            "decision": r["mlro_decision"],
            "created_at": r["created_at"].isoformat() if r["created_at"] else "",
        }
        for r in (edd_rows or [])
    ]
    return recent_txs, monthly_trend, alerts, edd_records


async def fetch_customer_dossier_db_repo(
    *,
    acc_uuid: uuid.UUID,
    tenant_id: str,
    read_conn_factory: Any = None,
) -> dict[str, Any]:
    factory = _read_factory(read_conn_factory)
    async with factory(tenant_id=tenant_id) as conn:
        acc = await conn.fetchrow(
            """
            SELECT id, account_number, swift_bic, owner_name, status,
                   risk_score, risk_category, created_at, frozen_reason,
                   freezing_order_ref, frozen_at, last_rescreened_at
            FROM accounts
            WHERE id = $1 AND tenant_id = $2;
            """,
            acc_uuid,
            uuid.UUID(str(tenant_id)),
        )
        if not acc:
            raise HTTPException(status_code=404, detail="Customer account not found.")

        acc_num = acc["account_number"]
        owner_name = acc["owner_name"]
        recent_txs, monthly_trend, alerts, edd_records = await fetch_customer_activity_tx(
            conn, acc_num, acc_uuid
        )
        pep_match_count = 0
        try:
            if owner_name and hasattr(conn, "fetchval"):
                raw_pep = await conn.fetchval(
                    "SELECT COUNT(*) FROM pep_entities WHERE name ILIKE $1;",
                    f"%{owner_name.strip()}%",
                )
                if isinstance(raw_pep, (int, float)):
                    pep_match_count = int(raw_pep)
        except Exception:
            pep_match_count = 0

    return {
        "acc": acc,
        "recent_txs": recent_txs,
        "monthly_trend": monthly_trend,
        "alerts": alerts,
        "edd_records": edd_records,
        "pep_match_count": pep_match_count,
    }


# ── Onboarding ────────────────────────────────────────────────────────────────

async def onboard_individual_account_repo(
    *,
    authorized_tenant_id: Any,
    account_number: str,
    swift_bic: Optional[str],
    owner_name: str,
    risk_score: float,
    dob_val: Optional[_date],
    conn_factory: Any = None,
) -> Any:
    factory = _write_factory(conn_factory)
    async with factory(tenant_id=authorized_tenant_id) as conn:
        tenant = await conn.fetchrow("SELECT id FROM tenants WHERE id = $1;", authorized_tenant_id)
        if not tenant:
            raise HTTPException(status_code=400, detail="Invalid tenant_id")

        return await conn.fetchval(
            """
            INSERT INTO accounts (tenant_id, account_number, swift_bic, owner_name, risk_score, date_of_birth)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id;
            """,
            authorized_tenant_id,
            account_number,
            swift_bic,
            owner_name,
            risk_score,
            dob_val,
        )


async def onboard_corporate_account_repo(
    *,
    authorized_tenant_id: Any,
    account_number: str,
    swift_bic: Optional[str],
    company_name: str,
    corp_risk_score: float,
    conn_factory: Any = None,
) -> Any:
    factory = _write_factory(conn_factory)
    async with factory(tenant_id=authorized_tenant_id) as conn:
        tenant = await conn.fetchrow("SELECT id FROM tenants WHERE id = $1;", authorized_tenant_id)
        if not tenant:
            raise HTTPException(status_code=400, detail="Invalid tenant_id")

        return await conn.fetchval(
            """
            INSERT INTO accounts (tenant_id, account_number, swift_bic, owner_name, risk_score)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id;
            """,
            authorized_tenant_id,
            account_number,
            swift_bic,
            company_name,
            corp_risk_score,
        )


async def compensating_delete_account_repo(
    *,
    authorized_tenant_id: Any,
    account_id: Any,
    conn_factory: Any = None,
) -> None:
    factory = _write_factory(conn_factory)
    async with factory(tenant_id=authorized_tenant_id) as conn:
        await conn.execute("DELETE FROM accounts WHERE id = $1;", account_id)


async def get_onboarded_account_by_id_repo(
    *,
    acc_uuid: uuid.UUID,
    tenant_id: Any,
    conn_factory: Any = None,
) -> Any:
    factory = _write_factory(conn_factory)
    async with factory(tenant_id=tenant_id) as conn:
        return await conn.fetchrow(
            """
            SELECT id, account_number, swift_bic, owner_name, risk_score, risk_category, date_of_birth, created_at
            FROM accounts
            WHERE id = $1 AND tenant_id = $2;
            """,
            acc_uuid,
            tenant_id,
        )


async def list_onboarded_accounts_repo(
    *,
    tenant_id: Any,
    limit: int,
    offset: int,
    cursor: Optional[str] = None,
    conn_factory: Any = None,
) -> tuple[int, list[Any]]:
    from database.pagination import decode_keyset_cursor, validate_legacy_offset

    factory = _write_factory(conn_factory)
    async with factory(tenant_id=tenant_id) as conn:
        if cursor:
            c_ts, c_id = decode_keyset_cursor(cursor)
            rows = await conn.fetch(
                """
                SELECT id, account_number, swift_bic, owner_name, risk_score, risk_category, created_at
                FROM accounts
                WHERE tenant_id = $1 AND (created_at, id) < ($2, $3)
                ORDER BY created_at DESC, id DESC
                LIMIT $4;
                """,
                tenant_id,
                c_ts,
                c_id,
                limit + 1,
            )
            return -1, list(rows or [])

        safe_offset = validate_legacy_offset(offset)
        total_count = await conn.fetchval(
            "SELECT COUNT(*) FROM accounts WHERE tenant_id = $1;",
            tenant_id,
        )
        rows = await conn.fetch(
            """
            SELECT id, account_number, swift_bic, owner_name, risk_score, risk_category, created_at
            FROM accounts
            WHERE tenant_id = $1
            ORDER BY created_at DESC, id DESC
            LIMIT $2 OFFSET $3;
            """,
            tenant_id,
            limit,
            safe_offset,
        )
    return int(total_count or 0), list(rows or [])


# ── Privacy, DSAR, Legal Holds & GDPR Art. 17 Erasure ─────────────────────────

async def fetch_dsar_export_repo(
    *,
    account_number: str,
    tenant_id: str,
    page_limit: int,
    offset: int,
    cursor: Optional[str] = None,
    read_conn_factory: Any = None,
) -> dict[str, Any]:
    from database.pagination import decode_keyset_cursor, validate_legacy_offset

    factory = _read_factory(read_conn_factory)
    async with factory(tenant_id=tenant_id) as conn:
        acc = await conn.fetchrow(
            """
            SELECT id, account_number, owner_name, swift_bic, status, created_at
            FROM accounts
            WHERE account_number = $1 AND tenant_id = $2;
            """,
            account_number,
            uuid.UUID(str(tenant_id)),
        )
        if not acc:
            raise HTTPException(status_code=404, detail="Account not found.")

        acc_id = acc["id"]
        if cursor:
            c_ts, c_id = decode_keyset_cursor(cursor)
            txs = await conn.fetch(
                """
                SELECT id, amount, currency, status, timestamp, country, channel
                FROM transactions
                WHERE (sender_account_id = $1 OR receiver_account_id = $1)
                  AND (timestamp, id) < ($2, $3)
                ORDER BY timestamp DESC, id DESC
                LIMIT $4;
                """,
                acc_id,
                c_ts,
                c_id,
                page_limit + 1,
            )
            return {"acc": acc, "total_tx": -1, "txs": list(txs or [])}

        safe_offset = validate_legacy_offset(offset)
        total_tx = await conn.fetchval(
            """
            SELECT COUNT(*)
            FROM transactions
            WHERE sender_account_id = $1 OR receiver_account_id = $1;
            """,
            acc_id,
        )
        txs = await conn.fetch(
            """
            SELECT id, amount, currency, status, timestamp, country, channel
            FROM transactions
            WHERE (sender_account_id = $1 OR receiver_account_id = $1)
            ORDER BY timestamp DESC, id DESC
            LIMIT $2 OFFSET $3;
            """,
            acc_id,
            page_limit,
            safe_offset,
        )
    return {"acc": acc, "total_tx": int(total_tx or 0), "txs": list(txs or [])}


async def list_legal_holds_repo(
    *,
    tenant_id: str,
    acc_uuid: Optional[uuid.UUID],
    active_only: bool,
    read_conn_factory: Any = None,
) -> list[Any]:
    factory = _read_factory(read_conn_factory)
    tenant_uuid = uuid.UUID(str(tenant_id))
    async with factory(tenant_id=tenant_id) as conn:
        if acc_uuid is not None:
            rows = await conn.fetch(
                """
                SELECT id, account_id, case_id, reference_number, reason, is_active, created_by_username, created_at
                FROM legal_holds
                WHERE tenant_id = $1 AND account_id = $2 AND ($3 = FALSE OR is_active = TRUE)
                ORDER BY created_at DESC;
                """,
                tenant_uuid,
                acc_uuid,
                active_only,
            )
        else:
            rows = await conn.fetch(
                """
                SELECT id, account_id, case_id, reference_number, reason, is_active, created_by_username, created_at
                FROM legal_holds
                WHERE tenant_id = $1 AND ($2 = FALSE OR is_active = TRUE)
                ORDER BY created_at DESC
                LIMIT 200;
                """,
                tenant_uuid,
                active_only,
            )
    return list(rows or [])


async def create_legal_hold_repo(
    *,
    tenant_id: str,
    acc_uuid: uuid.UUID,
    case_uuid: Optional[uuid.UUID],
    reference_number: str,
    reason: str,
    username: str,
    conn_factory: Any = None,
) -> uuid.UUID:
    factory = _write_factory(conn_factory)
    async with factory(tenant_id=tenant_id) as conn:
        return await conn.fetchval(
            """
            INSERT INTO legal_holds (
                tenant_id, account_id, case_id, reference_number, reason,
                is_active, created_by_username
            ) VALUES ($1, $2, $3, $4, $5, true, $6)
            RETURNING id;
            """,
            uuid.UUID(str(tenant_id)),
            acc_uuid,
            case_uuid,
            reference_number,
            reason,
            username,
        )


async def release_legal_hold_repo(
    *,
    hold_uuid: uuid.UUID,
    tenant_id: str,
    conn_factory: Any = None,
) -> bool:
    factory = _write_factory(conn_factory)
    async with factory(tenant_id=tenant_id) as conn:
        result = await conn.execute(
            """
            UPDATE legal_holds
            SET is_active = false, released_at = NOW()
            WHERE id = $1 AND tenant_id = $2;
            """,
            hold_uuid,
            uuid.UUID(str(tenant_id)),
        )
        return result != "UPDATE 0"


async def execute_gdpr_erasure_atomic(
    *,
    account_number: str,
    safe_reason: str,
    tenant_id: str,
    conn_factory: Any = None,
) -> dict[str, Any]:
    five_years_ago = datetime.now(timezone.utc) - timedelta(days=365 * 5)
    tenant_uuid = uuid.UUID(str(tenant_id))
    factory = _write_factory(conn_factory)

    async with factory(tenant_id=tenant_id) as conn:
        acc = await conn.fetchrow(
            """
            SELECT id, account_number, owner_name, created_at, erased_at
            FROM accounts
            WHERE account_number = $1 AND tenant_id = $2
            FOR UPDATE;
            """,
            account_number,
            tenant_uuid,
        )
        if not acc:
            raise HTTPException(status_code=404, detail="Account not found.")
        if acc.get("erased_at") is not None:
            return {
                "already_erased": True,
                "account_number": account_number,
                "erased_at": acc["erased_at"].isoformat(),
            }

        acc_id = acc["id"]
        active_holds = await conn.fetchval(
            "SELECT COUNT(*) FROM legal_holds WHERE tenant_id = $1 AND account_id = $2 AND is_active = TRUE;",
            tenant_uuid,
            acc_id,
        )
        if int(active_holds or 0) > 0:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Erasure blocked: active regulatory/legal hold prevents PII deletion.",
            )

        latest_retention_ts = await conn.fetchval(
            """
            SELECT GREATEST(
                (SELECT MAX(timestamp) FROM transactions WHERE sender_account_id = $1 OR receiver_account_id = $1),
                (SELECT MAX(a.fincen_submitted_at)
                 FROM alerts a
                 JOIN transactions t ON a.transaction_id = t.id
                 WHERE (t.sender_account_id = $1 OR t.receiver_account_id = $1)
                   AND a.fincen_submitted_at IS NOT NULL)
            );
            """,
            acc_id,
        )
        anchor_ts = latest_retention_ts or acc["created_at"]
        if anchor_ts is not None:
            if anchor_ts.tzinfo is None:
                anchor_ts = anchor_ts.replace(tzinfo=timezone.utc)
            if anchor_ts > five_years_ago:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Erasure deferred under 31 CFR § 1010.430: mandatory 5-year BSA statutory retention period has not elapsed.",
                )

        pseudonym = "ERASED-" + hashlib.sha256(f"{tenant_id}:{acc_id}".encode("utf-8")).hexdigest()[:10].upper()
        await conn.execute(
            """
            UPDATE accounts
            SET owner_name = $1,
                erased_at = NOW(),
                erasure_reason = $2
            WHERE id = $3;
            """,
            pseudonym,
            safe_reason,
            acc_id,
        )
    return {
        "already_erased": False,
        "acc_id": str(acc_id),
        "pseudonym": pseudonym,
    }
