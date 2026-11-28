"""
Entity-Centric Case Auto-Correlation Engine (P1-1)
===================================================
Reduces analyst alert fatigue by automatically merging related alerts for the same
subject account/entity within a configurable time window (default 7 days) into a
single unified investigation case, dynamically upgrading case priority when a higher-
severity alert correlates into the case.
"""

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("aml.case_correlation")

PRIORITY_RANK: Dict[str, int] = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def compute_entity_correlation_key(subject_account_id: str | uuid.UUID | None) -> Optional[str]:
    """Produces a deterministic entity correlation key scoped to a subject account."""
    if not subject_account_id:
        return None
    return f"entity:{str(subject_account_id).strip().lower()}"


def higher_priority(current_priority: str | None, incoming_priority: str | None) -> str:
    cur = (current_priority or "MEDIUM").upper().strip()
    inc = (incoming_priority or "").upper().strip()
    cur_valid = cur if cur in PRIORITY_RANK else "MEDIUM"
    if inc not in PRIORITY_RANK:
        return cur_valid
    if PRIORITY_RANK[inc] > PRIORITY_RANK[cur_valid]:
        return inc
    return cur_valid


async def correlate_alert_to_entity_case(
    conn: Any,
    tenant_id: str | uuid.UUID,
    alert_id: str | uuid.UUID,
    subject_account_id: str | uuid.UUID | None,
    title: str,
    priority: str = "HIGH",
    actor_id: str | uuid.UUID | None = None,
    actor_username: str = "system",
    window_days: int = 7,
    narrative: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Links an alert into an existing open/investigating entity case within `window_days`,
    or creates a new entity-correlated case if none exists.
    Must be called with an active tenant-RLS `asyncpg` connection.
    """
    tenant_uuid = uuid.UUID(str(tenant_id))
    alert_uuid = uuid.UUID(str(alert_id))
    subj_uuid = uuid.UUID(str(subject_account_id)) if subject_account_id else None
    actor_uuid = None
    if actor_id:
        try:
            actor_uuid = uuid.UUID(str(actor_id))
        except ValueError:
            actor_uuid = None

    corr_key = compute_entity_correlation_key(subj_uuid)
    norm_priority = priority.upper() if (priority and priority.upper() in PRIORITY_RANK) else "HIGH"

    existing_case = None
    if corr_key:
        existing_case = await conn.fetchrow(
            """
            SELECT id, case_number, priority, status
            FROM cases
            WHERE tenant_id = $1
              AND correlation_key = $2
              AND status IN ('OPEN', 'IN_REVIEW', 'INVESTIGATING', 'PENDING_EDD', 'PENDING_SAR')
              AND created_at >= NOW() - ($3::int * INTERVAL '1 day')
            ORDER BY created_at DESC
            LIMIT 1;
            """,
            tenant_uuid,
            corr_key,
            max(1, min(int(window_days), 90)),
        )

    if existing_case:
        case_id = existing_case["id"]
        case_number = existing_case["case_number"]
        new_priority = higher_priority(existing_case["priority"], norm_priority)

        await conn.execute(
            """
            INSERT INTO case_alerts (case_id, alert_id)
            VALUES ($1, $2)
            ON CONFLICT (case_id, alert_id) DO NOTHING;
            """,
            case_id,
            alert_uuid,
        )

        if new_priority != existing_case["priority"]:
            await conn.execute(
                "UPDATE cases SET priority = $1, updated_at = NOW() WHERE id = $2;",
                new_priority,
                case_id,
            )
        else:
            await conn.execute(
                "UPDATE cases SET updated_at = NOW() WHERE id = $1;",
                case_id,
            )

        await conn.execute(
            """
            INSERT INTO case_notes (case_id, author_id, author_username, note)
            VALUES ($1, $2, $3, $4);
            """,
            case_id,
            actor_uuid,
            actor_username,
            f"Auto-correlated alert {str(alert_uuid)[:8]} into entity case {case_number} (priority: {new_priority}).",
        )

        linked_count = await conn.fetchval(
            "SELECT COUNT(*) FROM case_alerts WHERE case_id = $1;",
            case_id,
        )
        return {
            "case_id": str(case_id),
            "case_number": case_number,
            "priority": new_priority,
            "correlated": True,
            "correlation_key": corr_key,
            "linked_alert_count": int(linked_count or 1),
        }

    # No active entity case found -> create a new entity-correlated case
    case_number = f"CASE-{datetime.now(timezone.utc).year}-{uuid.uuid4().hex[:6].upper()}"
    case_id = await conn.fetchval(
        """
        INSERT INTO cases (
            tenant_id, case_number, title, priority, assigned_to, assigned_username,
            subject_account_id, narrative, status, correlation_key
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'OPEN', $9)
        RETURNING id;
        """,
        tenant_uuid,
        case_number,
        title[:200],
        norm_priority,
        actor_uuid,
        actor_username,
        subj_uuid,
        narrative or f"Entity-correlated investigation initiated from alert {alert_uuid}.",
        corr_key,
    )

    await conn.execute(
        """
        INSERT INTO case_alerts (case_id, alert_id)
        VALUES ($1, $2)
        ON CONFLICT (case_id, alert_id) DO NOTHING;
        """,
        case_id,
        alert_uuid,
    )

    return {
        "case_id": str(case_id),
        "case_number": case_number,
        "priority": norm_priority,
        "correlated": False,
        "correlation_key": corr_key,
        "linked_alert_count": 1,
    }


async def batch_correlate_alerts(
    conn: Any,
    tenant_id: str | uuid.UUID,
    alert_ids: List[str],
    actor_id: str | uuid.UUID | None = None,
    actor_username: str = "analyst",
    window_days: int = 7,
) -> Dict[str, Any]:
    """Correlates a batch of alert IDs into unified entity cases grouped by sender account."""
    if not alert_ids:
        return {"processed_alerts": 0, "cases": [], "merged_count": 0, "created_count": 0}

    uuids = [uuid.UUID(str(a)) for a in alert_ids]
    rows = await conn.fetch(
        """
        SELECT a.id AS alert_id,
               a.rule_name,
               a.threat_level,
               t.sender_account_id,
               acc.account_number,
               acc.owner_name
        FROM alerts a
        LEFT JOIN transactions t ON a.transaction_id = t.id
        LEFT JOIN accounts acc ON t.sender_account_id = acc.id
        WHERE a.id = ANY($1::uuid[])
        ORDER BY a.created_at ASC;
        """,
        uuids,
    )

    cases_by_id: Dict[str, Dict[str, Any]] = {}
    merged_count = 0
    created_count = 0

    for row in rows:
        subj = row["sender_account_id"]
        label = row["owner_name"] or row["account_number"] or str(subj or row["alert_id"])[:8]
        title = f"Entity Investigation: {label} ({row['rule_name'] or 'AML_ALERT'})"
        raw_threat = str(row["threat_level"] or "HIGH").upper().strip()
        mapped_priority = "LOW" if raw_threat == "NONE" else (raw_threat if raw_threat in PRIORITY_RANK else "HIGH")
        res = await correlate_alert_to_entity_case(
            conn=conn,
            tenant_id=tenant_id,
            alert_id=row["alert_id"],
            subject_account_id=subj,
            title=title,
            priority=mapped_priority,
            actor_id=actor_id,
            actor_username=actor_username,
            window_days=window_days,
        )
        if res["correlated"]:
            merged_count += 1
        else:
            created_count += 1
        cases_by_id[res["case_id"]] = res

    return {
        "processed_alerts": len(rows),
        "merged_count": merged_count,
        "created_count": created_count,
        "cases": list(cases_by_id.values()),
    }
