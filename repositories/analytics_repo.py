"""
Analytics, Network Graph, Compliance Reporting, ML & Global Search Repository
=============================================================================
Encapsulates all PostgreSQL read/write queries for dashboard KPIs, executive
analytics, recursive graph fallback, corporate UBO edges, compliance reports,
ML feedback/explainability, and Cmd+K global search.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Optional

import database.postgres as _pg

logger = logging.getLogger(__name__)


def _write_factory(conn_factory: Any = None) -> Any:
    return conn_factory or _pg.get_async_db_conn


def _read_factory(read_conn_factory: Any = None) -> Any:
    return read_conn_factory or _pg.get_async_db_read_conn


# ── Dashboard & Executive Metrics ─────────────────────────────────────────────

async def fetch_dashboard_metrics_repo(
    *,
    tenant_id: Any,
    determine_risk_tier_fn: Callable[[int], str],
    read_conn_factory: Any = None,
) -> dict[str, Any]:
    factory = _read_factory(read_conn_factory)
    async with factory(tenant_id=tenant_id) as conn:
        active_cases = await conn.fetchval("SELECT COUNT(*) FROM alerts WHERE status = 'OPEN';")
        critical_cases = await conn.fetchval(
            "SELECT COUNT(*) FROM alerts WHERE status = 'OPEN' AND threat_level = 'CRITICAL';"
        )

        trend_rows = await conn.fetch(
            """
            SELECT DATE(created_at) as day, COUNT(*) as count
            FROM alerts
            WHERE created_at >= NOW() - INTERVAL '7 days'
            GROUP BY DATE(created_at)
            ORDER BY day ASC;
            """
        )
        days_map = {
            (datetime.now(timezone.utc) - timedelta(days=i)).strftime("%a"): 0 for i in reversed(range(7))
        }
        for row in (trend_rows or []):
            day_name = row["day"].strftime("%a")
            if day_name in days_map:
                days_map[day_name] = int(row["count"])

        cat_rows = await conn.fetch(
            """
            SELECT rule_name, COUNT(*) as count
            FROM alerts
            GROUP BY rule_name
            ORDER BY count DESC;
            """
        )
        categories = [{"category": row["rule_name"], "count": int(row["count"])} for row in (cat_rows or [])]

        leaderboard_rows = await conn.fetch(
            """
            SELECT u.username,
                   COUNT(a.id) FILTER (WHERE a.status = 'OPEN') as active_cases,
                   COUNT(a.id) FILTER (WHERE a.status LIKE 'CLOSED%') as resolved_cases,
                   COUNT(a.id) as total_cases
            FROM users u
            LEFT JOIN alerts a ON u.id = a.assigned_officer_id
            GROUP BY u.username
            ORDER BY active_cases DESC;
            """
        )
        analysts = []
        for row in (leaderboard_rows or []):
            active = int(row["active_cases"])
            resolved = int(row["resolved_cases"])
            total = int(row["total_cases"])
            res_rate = round((resolved / total * 100), 1) if total > 0 else 100.0
            analysts.append(
                {
                    "username": row["username"],
                    "active_cases": active,
                    "resolution_rate": f"{res_rate}%",
                    "risk_tier": determine_risk_tier_fn(active),
                }
            )

        avg_res_hours = 0.0
        escalation_rate = 0.0
        try:
            raw_avg = await conn.fetchval(
                """
                SELECT AVG(EXTRACT(EPOCH FROM (closed_at - created_at)) / 3600.0)
                FROM cases
                WHERE status = 'CLOSED' AND closed_at IS NOT NULL AND created_at IS NOT NULL AND closed_at >= created_at;
                """
            )
            if isinstance(raw_avg, (int, float)):
                avg_res_hours = round(float(raw_avg), 1)
            total_alerts_all = await conn.fetchval("SELECT COUNT(*) FROM alerts;")
            escalated_alerts = await conn.fetchval(
                "SELECT COUNT(*) FROM alerts WHERE status IN ('ESCALATED', 'CLOSED_SAR');"
            )
            if (
                isinstance(total_alerts_all, (int, float))
                and total_alerts_all > 0
                and isinstance(escalated_alerts, (int, float))
            ):
                escalation_rate = round((float(escalated_alerts) / float(total_alerts_all)) * 100.0, 1)
        except Exception:
            pass

    return {
        "active_cases": active_cases or 0,
        "critical_cases": critical_cases or 0,
        "avg_resolution_hours": avg_res_hours,
        "escalation_rate": escalation_rate,
        "daily_trend": {"labels": list(days_map.keys()), "data": list(days_map.values())},
        "category_distribution": categories,
        "analyst_leaderboard": analysts,
    }


async def fetch_executive_counts_tx(conn: Any) -> dict[str, Any]:
    alerts_24h = await conn.fetchval(
        "SELECT COUNT(*) FROM alerts WHERE created_at >= NOW() - INTERVAL '24 hours';"
    )
    open_alerts = await conn.fetchval(
        "SELECT COUNT(*) FROM alerts WHERE status IN ('NEW', 'IN_REVIEW', 'ESCALATED', 'OPEN');"
    )
    open_cases = await conn.fetchval(
        "SELECT COUNT(*) FROM cases WHERE status IN ('OPEN', 'INVESTIGATING', 'PENDING_EDD', 'PENDING_SAR');"
    )
    sars_mtd = await conn.fetchval(
        """
        SELECT COUNT(*) FROM sar_drafts
        WHERE status IN ('APPROVED', 'FILED')
          AND created_at >= DATE_TRUNC('month', NOW());
        """
    )
    total_closed = await conn.fetchval("SELECT COUNT(*) FROM alerts WHERE status LIKE 'CLOSED%';")
    fps_closed = await conn.fetchval("SELECT COUNT(*) FROM alerts WHERE status = 'CLOSED_FALSE_POSITIVE';")
    median_triage = await conn.fetchval(
        """
        SELECT PERCENTILE_CONT(0.5) WITHIN GROUP (
            ORDER BY EXTRACT(EPOCH FROM (COALESCE(res.resolved_at, a.fincen_submitted_at) - a.created_at)) / 3600.0
        )
        FROM alerts a
        LEFT JOIN LATERAL (
            SELECT MAX(al.occurred_at) AS resolved_at
            FROM audit_log al
            WHERE al.resource_id = a.id::text
              AND al.action IN ('CLOSE_FALSE_POSITIVE', 'RESOLVE_ALERT', 'FINCEN_SAR_FILED', 'UPDATE_ALERT')
        ) res ON TRUE
        WHERE a.status LIKE 'CLOSED%'
          AND a.created_at IS NOT NULL
          AND COALESCE(res.resolved_at, a.fincen_submitted_at) IS NOT NULL
          AND COALESCE(res.resolved_at, a.fincen_submitted_at) >= a.created_at;
        """
    )

    t_closed = int(total_closed or 0)
    f_closed = int(fps_closed or 0)
    fp_rate = round((f_closed / t_closed * 100), 1) if t_closed > 0 else 0.0
    median_hours = round(float(median_triage), 1) if median_triage is not None else 0.0

    return {
        "alerts_24h": int(alerts_24h or 0),
        "open_alerts": int(open_alerts or 0),
        "open_cases": int(open_cases or 0),
        "sars_filed_mtd": int(sars_mtd or 0),
        "false_positive_rate": f"{fp_rate}%",
        "median_triage_hours": median_hours,
    }


async def fetch_executive_sla_breaches_tx(conn: Any) -> dict[str, Any]:
    breach_24h = await conn.fetchval(
        """
        SELECT COUNT(*) FROM alerts
        WHERE status IN ('NEW', 'IN_REVIEW', 'ESCALATED', 'OPEN')
          AND created_at <= NOW() - INTERVAL '24 hours';
        """
    )
    breach_48h = await conn.fetchval(
        """
        SELECT COUNT(*) FROM alerts
        WHERE status IN ('NEW', 'IN_REVIEW', 'ESCALATED', 'OPEN')
          AND created_at <= NOW() - INTERVAL '48 hours';
        """
    )
    breach_72h = await conn.fetchval(
        """
        SELECT COUNT(*) FROM alerts
        WHERE status IN ('NEW', 'IN_REVIEW', 'ESCALATED', 'OPEN')
          AND created_at <= NOW() - INTERVAL '72 hours';
        """
    )

    breach_rows = await conn.fetch(
        """
        SELECT a.id, a.rule_name, a.threat_level, a.created_at,
               ROUND(EXTRACT(EPOCH FROM (NOW() - a.created_at)) / 3600.0, 1) as age_hours,
               COALESCE(u.username, 'UNASSIGNED') as assignee
        FROM alerts a
        LEFT JOIN users u ON a.assigned_officer_id = u.id
        WHERE a.status IN ('NEW', 'IN_REVIEW', 'ESCALATED', 'OPEN')
          AND a.created_at <= NOW() - INTERVAL '24 hours'
        ORDER BY a.created_at ASC
        LIMIT 10;
        """
    )
    breach_items = [
        {
            "alert_id": str(r["id"]),
            "rule_name": r["rule_name"],
            "threat_level": r["threat_level"],
            "age_hours": float(r["age_hours"]),
            "assignee": r["assignee"],
        }
        for r in (breach_rows or [])
    ]

    return {
        "breach_24h": int(breach_24h or 0),
        "breach_48h": int(breach_48h or 0),
        "breach_72h": int(breach_72h or 0),
        "items": breach_items,
    }


async def fetch_executive_analytics_tx(conn: Any) -> tuple[list[dict[str, Any]], dict[str, int], list[dict[str, Any]]]:
    cat_rows = await conn.fetch(
        "SELECT rule_name, COUNT(*) as count FROM alerts GROUP BY rule_name ORDER BY count DESC LIMIT 8;"
    )
    typologies = [{"rule_name": r["rule_name"], "count": int(r["count"])} for r in (cat_rows or [])]

    trend_rows = await conn.fetch(
        """
        SELECT DATE(created_at) as day, COUNT(*) as count
        FROM alerts
        WHERE created_at >= NOW() - INTERVAL '7 days'
        GROUP BY DATE(created_at)
        ORDER BY day ASC;
        """
    )
    days_map = {
        (datetime.now(timezone.utc) - timedelta(days=i)).strftime("%a"): 0 for i in reversed(range(7))
    }
    for row in (trend_rows or []):
        day_name = row["day"].strftime("%a")
        if day_name in days_map:
            days_map[day_name] = int(row["count"])

    leaderboard_rows = await conn.fetch(
        """
        SELECT u.username,
               COUNT(a.id) FILTER (WHERE a.status IN ('OPEN', 'IN_REVIEW', 'ESCALATED')) as active_cases,
               COUNT(a.id) FILTER (WHERE a.status LIKE 'CLOSED%') as resolved_cases,
               COUNT(a.id) as total_cases
        FROM users u
        LEFT JOIN alerts a ON u.id = a.assigned_officer_id
        GROUP BY u.username
        ORDER BY resolved_cases DESC
        LIMIT 10;
        """
    )
    analysts = []
    for row in (leaderboard_rows or []):
        active = int(row["active_cases"])
        resolved = int(row["resolved_cases"])
        total = int(row["total_cases"])
        res_rate = round((resolved / total * 100), 1) if total > 0 else 100.0
        analysts.append(
            {
                "username": row["username"],
                "active_cases": active,
                "resolved_cases": resolved,
                "resolution_rate": f"{res_rate}%",
            }
        )

    return typologies, days_map, analysts


async def fetch_executive_metrics_repo(
    *,
    tenant_id: Any,
    counts_fn: Any = None,
    sla_fn: Any = None,
    analytics_fn: Any = None,
    read_conn_factory: Any = None,
) -> dict[str, Any]:
    factory = _read_factory(read_conn_factory)
    c_fn = counts_fn or fetch_executive_counts_tx
    s_fn = sla_fn or fetch_executive_sla_breaches_tx
    a_fn = analytics_fn or fetch_executive_analytics_tx

    async with factory(tenant_id=tenant_id) as conn:
        kpis = await c_fn(conn)
        sla_breaches = await s_fn(conn)
        typologies, days_map, analysts = await a_fn(conn)

    return {
        "kpis": kpis,
        "sla_breaches": sla_breaches,
        "typologies": typologies,
        "daily_trend": {"labels": list(days_map.keys()), "data": list(days_map.values())},
        "leaderboard": analysts,
    }


# ── Network Graph Expansion, UBO Edges & Cross-Entity MDM ─────────────────────

async def expand_network_pg_fallback_repo(
    *,
    entity_id: str,
    tenant_id: Optional[str],
    hops: int,
    read_conn_factory: Any = None,
) -> tuple[Optional[str], list[Any]]:
    safe_hops = max(1, min(int(hops), 3))
    target_entity = str(entity_id or "").strip()
    factory = _read_factory(read_conn_factory)
    async with factory(tenant_id=tenant_id) as conn:
        if target_entity.lower() in ("", "auto", "default"):
            seed_row = await conn.fetchrow(
                """
                SELECT a.account_number
                FROM accounts a
                JOIN transactions t
                  ON t.sender_account_id = a.id OR t.receiver_account_id = a.id
                WHERE ($1::text IS NULL OR t.tenant_id = $1::uuid)
                GROUP BY a.id, a.account_number, a.risk_score
                ORDER BY count(t.id) DESC, a.risk_score DESC NULLS LAST
                LIMIT 1
                """,
                str(tenant_id) if tenant_id else None,
            )
            if not seed_row:
                return None, []
            target_entity = seed_row["account_number"]

        escaped_entity = target_entity.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        rows = await conn.fetch(
            """
            WITH RECURSIVE visited_accounts(acc_id, depth) AS (
                SELECT id, 0
                FROM accounts
                WHERE (
                    id::text = $1
                    OR account_number ILIKE $4 ESCAPE '\\'
                    OR owner_name ILIKE $4 ESCAPE '\\'
                )
                  AND ($2::text IS NULL OR tenant_id = $2::uuid)
                UNION
                SELECT CASE
                           WHEN t.sender_account_id = v.acc_id THEN t.receiver_account_id
                           ELSE t.sender_account_id
                       END,
                       v.depth + 1
                FROM visited_accounts v
                JOIN transactions t
                  ON t.sender_account_id = v.acc_id OR t.receiver_account_id = v.acc_id
                WHERE v.depth < $3
                  AND ($2::text IS NULL OR t.tenant_id = $2::uuid)
            )
            SELECT DISTINCT
                t.id as tx_id,
                t.amount,
                t.timestamp,
                s.id as sender_id,
                s.account_number as sender_acc,
                s.owner_name as sender_name,
                s.risk_score as sender_risk,
                s.status as sender_status,
                r.id as receiver_id,
                r.account_number as receiver_acc,
                r.owner_name as receiver_name,
                r.risk_score as receiver_risk,
                r.status as receiver_status
            FROM transactions t
            JOIN accounts s ON t.sender_account_id = s.id
            JOIN accounts r ON t.receiver_account_id = r.id
            WHERE (t.sender_account_id IN (SELECT acc_id FROM visited_accounts)
               AND t.receiver_account_id IN (SELECT acc_id FROM visited_accounts))
              AND ($2::text IS NULL OR t.tenant_id = $2::uuid)
            ORDER BY t.timestamp DESC
            LIMIT 75;
            """,
            target_entity,
            str(tenant_id) if tenant_id else None,
            safe_hops,
            escaped_entity,
        )
    return target_entity, list(rows or [])


async def create_ubo_edge_repo(
    *,
    tenant_id: str,
    safe_parent: str,
    parent_entity_type: str,
    safe_child: str,
    ownership_pct: float,
    jurisdiction: str,
    tax_id: Optional[str],
    verified_source: str,
    conn_factory: Any = None,
) -> uuid.UUID:
    factory = _write_factory(conn_factory)
    async with factory(tenant_id=tenant_id) as conn:
        return await conn.fetchval(
            """
            INSERT INTO corporate_ownership_edges (
                tenant_id, parent_entity_name, parent_entity_type, child_company_name,
                ownership_pct, jurisdiction, tax_id, verified_source
            )
            VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8)
            RETURNING id;
            """,
            str(tenant_id),
            safe_parent,
            parent_entity_type,
            safe_child,
            ownership_pct,
            jurisdiction,
            tax_id,
            verified_source,
        )


async def list_corporate_ownership_edges_repo(
    *,
    tenant_id: str,
    read_conn_factory: Any = None,
) -> list[dict[str, Any]]:
    factory = _read_factory(read_conn_factory)
    async with factory(tenant_id=tenant_id) as conn:
        rows = await conn.fetch(
            """
            SELECT parent_entity_name, parent_entity_type, child_company_name,
                   ownership_pct, jurisdiction, tax_id
            FROM corporate_ownership_edges
            WHERE tenant_id = $1::uuid
            LIMIT 2000;
            """,
            str(tenant_id),
        )
    return [dict(r) for r in (rows or [])]


async def find_cross_entity_mdm_links_repo(
    *,
    tenant_id: str,
    account_number: str,
    read_conn_factory: Any = None,
) -> Any:
    from services.ubo_resolver import find_cross_entity_mdm_links

    factory = _read_factory(read_conn_factory)
    async with factory(tenant_id=tenant_id) as conn:
        return await find_cross_entity_mdm_links(conn=conn, account_number=account_number)


# ── Regulatory Compliance Reporting ───────────────────────────────────────────

async def fetch_sar_summary_repo(*, tenant_id: str, read_conn_factory: Any = None) -> Any:
    factory = _read_factory(read_conn_factory)
    async with factory(tenant_id=tenant_id) as conn:
        return await conn.fetchrow(
            """
            SELECT
                COUNT(*) AS total_drafts,
                COUNT(*) FILTER (WHERE status = 'APPROVED') AS approved_drafts,
                COUNT(*) FILTER (WHERE status = 'FILED') AS submitted_drafts,
                COUNT(*) FILTER (WHERE status = 'REJECTED') AS rejected_drafts
            FROM sar_drafts
            WHERE tenant_id = $1;
            """,
            uuid.UUID(str(tenant_id)),
        )


async def fetch_ctr_summary_repo(*, tenant_id: str, read_conn_factory: Any = None) -> Any:
    factory = _read_factory(read_conn_factory)
    async with factory(tenant_id=tenant_id) as conn:
        return await conn.fetchrow(
            """
            SELECT
                COUNT(*) AS total_ctrs,
                COUNT(*) FILTER (WHERE status = 'FILED') AS filed_ctrs,
                COUNT(*) FILTER (WHERE status = 'PENDING') AS pending_ctrs,
                COALESCE(SUM(amount), 0.0) AS total_cash_volume
            FROM ctr_filings
            WHERE tenant_id = $1;
            """,
            uuid.UUID(str(tenant_id)),
        )


async def fetch_conversion_counts_repo(*, tenant_id: str, read_conn_factory: Any = None) -> tuple[int, int, int]:
    factory = _read_factory(read_conn_factory)
    t_uuid = uuid.UUID(str(tenant_id))
    async with factory(tenant_id=tenant_id) as conn:
        total_alerts = await conn.fetchval("SELECT COUNT(*) FROM alerts WHERE tenant_id = $1;", t_uuid) or 0
        total_cases = await conn.fetchval("SELECT COUNT(*) FROM cases WHERE tenant_id = $1;", t_uuid) or 0
        filed_sars = (
            await conn.fetchval(
                "SELECT COUNT(*) FROM sar_drafts WHERE tenant_id = $1 AND status = 'FILED';", t_uuid
            )
            or 0
        )
    return int(total_alerts), int(total_cases), int(filed_sars)


async def fetch_kyc_status_repo(*, tenant_id: str, read_conn_factory: Any = None) -> Any:
    factory = _read_factory(read_conn_factory)
    async with factory(tenant_id=tenant_id) as conn:
        return await conn.fetchrow(
            """
            SELECT
                COUNT(*) AS total_scheduled,
                COUNT(*) FILTER (WHERE status = 'OVERDUE' OR due_date < NOW()) AS overdue_reviews,
                COUNT(*) FILTER (WHERE status = 'COMPLETED') AS completed_reviews
            FROM kyc_reviews
            WHERE tenant_id = $1;
            """,
            uuid.UUID(str(tenant_id)),
        )


# ── ML Feedback & Explainability ──────────────────────────────────────────────

async def fetch_ml_feedback_stats_repo(*, tenant_id: str, conn_factory: Any = None) -> tuple[int, int, int]:
    factory = _write_factory(conn_factory)
    async with factory(tenant_id=tenant_id) as conn:
        total_samples = await conn.fetchval(
            "SELECT COUNT(*) FROM ml_feedback_samples WHERE tenant_id = $1::uuid;",
            str(tenant_id),
        )
        fp_count = await conn.fetchval(
            "SELECT COUNT(*) FROM ml_feedback_samples WHERE tenant_id = $1::uuid AND label = 0;",
            str(tenant_id),
        )
        sar_count = await conn.fetchval(
            "SELECT COUNT(*) FROM ml_feedback_samples WHERE tenant_id = $1::uuid AND label = 1;",
            str(tenant_id),
        )
    return int(total_samples or 0), int(fp_count or 0), int(sar_count or 0)


async def fetch_alert_explainability_row_repo(
    *,
    a_uuid: uuid.UUID,
    tenant_id: str,
    conn_factory: Any = None,
) -> Any:
    factory = _write_factory(conn_factory)
    async with factory(tenant_id=tenant_id) as conn:
        return await conn.fetchrow(
            """
            SELECT a.id, a.rule_name, a.threat_level, a.ai_risk_score,
                   a.explainability_payload, t.amount, t.currency
            FROM alerts a
            LEFT JOIN transactions t ON a.transaction_id = t.id
            WHERE a.id = $1 AND a.tenant_id = $2::uuid;
            """,
            a_uuid,
            str(tenant_id),
        )


# ── Unified Global Search ─────────────────────────────────────────────────────

async def search_accounts_global_repo(*, tenant_id: str, pattern: str, limit: int, read_conn_factory: Any = None):
    factory = _read_factory(read_conn_factory)
    async with factory(tenant_id=tenant_id) as conn:
        return list(
            await conn.fetch(
                """
                SELECT id, account_number, owner_name, swift_bic, status, risk_score
                FROM accounts
                WHERE account_number ILIKE $1 OR owner_name ILIKE $1 OR swift_bic ILIKE $1
                ORDER BY risk_score DESC NULLS LAST
                LIMIT $2;
                """,
                pattern,
                limit,
            )
            or []
        )


async def search_cases_global_repo(*, tenant_id: str, pattern: str, limit: int, read_conn_factory: Any = None):
    factory = _read_factory(read_conn_factory)
    async with factory(tenant_id=tenant_id) as conn:
        return list(
            await conn.fetch(
                """
                SELECT id, case_number, title, status, priority
                FROM cases
                WHERE case_number ILIKE $1 OR title ILIKE $1
                ORDER BY created_at DESC
                LIMIT $2;
                """,
                pattern,
                limit,
            )
            or []
        )


async def search_alerts_global_repo(*, tenant_id: str, pattern: str, limit: int, read_conn_factory: Any = None):
    factory = _read_factory(read_conn_factory)
    async with factory(tenant_id=tenant_id) as conn:
        return list(
            await conn.fetch(
                """
                SELECT id, rule_name, threat_level, status, ai_risk_score
                FROM alerts
                WHERE rule_name ILIKE $1 OR id::text ILIKE $1
                ORDER BY created_at DESC
                LIMIT $2;
                """,
                pattern,
                limit,
            )
            or []
        )


async def search_sars_global_repo(*, tenant_id: str, pattern: str, limit: int, read_conn_factory: Any = None):
    factory = _read_factory(read_conn_factory)
    async with factory(tenant_id=tenant_id) as conn:
        return list(
            await conn.fetch(
                """
                SELECT id, status, drafted_by_username, fincen_tracking_id
                FROM sar_drafts
                WHERE id::text ILIKE $1
                   OR narrative ILIKE $1
                   OR COALESCE(fincen_tracking_id, '') ILIKE $1
                ORDER BY created_at DESC
                LIMIT $2;
                """,
                pattern,
                limit,
            )
            or []
        )
