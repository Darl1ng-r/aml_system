"""
Automated Notification & SLA Escalation Engine (P1-4)
======================================================
Persists tenant-scoped in-app notifications, sweeps for breached Alert SLAs
and approaching 30-day BSA SAR statutory deadlines with 12-hour deduplication,
and forwards SLA escalation events into the durable transactional outbox so
configured Slack/Teams/Email webhook bridges receive signed escalations.
"""

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from services.webhooks import enqueue_webhook_event_tx

logger = logging.getLogger("aml.notifications")

# Enterprise SLA windows (hours)
SLA_HOURS_BY_THREAT = {
    "CRITICAL": 24,
    "HIGH": 72,
    "MEDIUM": 168,
}
DEDUP_WINDOW_HOURS = 12


async def create_notification(
    conn: Any,
    tenant_id: str | uuid.UUID,
    category: str,
    title: str,
    body: str,
    severity: str = "INFO",
    recipient_user_id: str | uuid.UUID | None = None,
    recipient_role: Optional[str] = None,
    link_url: str = "",
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    dedup_hours: int = DEDUP_WINDOW_HOURS,
) -> Optional[str]:
    """
    Inserts a tenant-scoped notification if no identical (category, resource_id)
    notification was already emitted within `dedup_hours`.
    """
    tenant_uuid = uuid.UUID(str(tenant_id))
    rec_uuid = uuid.UUID(str(recipient_user_id)) if recipient_user_id else None

    if resource_id and dedup_hours > 0:
        exists = await conn.fetchval(
            """
            SELECT 1
            FROM notifications
            WHERE tenant_id = $1
              AND category = $2
              AND resource_id = $3
              AND created_at >= NOW() - ($4::int * INTERVAL '1 hour')
            LIMIT 1;
            """,
            tenant_uuid,
            category,
            str(resource_id),
            int(dedup_hours),
        )
        if exists:
            return None

    notif_id = await conn.fetchval(
        """
        INSERT INTO notifications (
            tenant_id, recipient_user_id, recipient_role, category, severity,
            title, body, link_url, resource_type, resource_id
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        RETURNING id;
        """,
        tenant_uuid,
        rec_uuid,
        recipient_role.upper() if recipient_role else None,
        category.upper(),
        severity.upper(),
        title[:240],
        body,
        link_url[:300],
        resource_type,
        str(resource_id) if resource_id else None,
    )
    return str(notif_id)


async def run_sla_escalation_sweep(
    conn: Any,
    tenant_id: str | uuid.UUID,
) -> Dict[str, Any]:
    """
    Scans open alerts and pending SAR drafts under tenant RLS for SLA / statutory
    breaches, persists deduplicated notifications, and emits signed `SLA_ESCALATION`
    outbox webhook events for external Slack/Teams/Email bridges.
    """
    tenant_uuid = uuid.UUID(str(tenant_id))
    alert_escalations = 0
    sar_escalations = 0
    created_ids: List[str] = []

    # 1. Breached Open Alert SLAs (CRITICAL > 24h, HIGH > 72h)
    breached_alerts = await conn.fetch(
        """
        SELECT id, rule_name, threat_level, status, created_at
        FROM alerts
        WHERE status IN ('OPEN', 'IN_REVIEW', 'ESCALATED')
          AND (
              (threat_level = 'CRITICAL' AND created_at < NOW() - INTERVAL '24 hours')
              OR (threat_level = 'HIGH' AND created_at < NOW() - INTERVAL '72 hours')
          )
        ORDER BY created_at ASC
        LIMIT 50;
        """
    )

    for a in (breached_alerts or []):
        aid = str(a["id"])
        threat = a["threat_level"] or "HIGH"
        rule = a["rule_name"] or "AML_ALERT"
        nid = await create_notification(
            conn=conn,
            tenant_id=tenant_uuid,
            category="SLA_BREACH",
            severity="CRITICAL" if threat == "CRITICAL" else "WARNING",
            recipient_role="MLRO",
            title=f"SLA Breach: {threat} Alert ({rule})",
            body=f"Alert {aid[:8]} has exceeded the {SLA_HOURS_BY_THREAT.get(threat, 72)}h SLA window in state {a['status']}.",
            link_url=f"/alerts/triage?search={aid[:8]}",
            resource_type="ALERT",
            resource_id=aid,
        )
        if nid:
            alert_escalations += 1
            created_ids.append(nid)
            await enqueue_webhook_event_tx(
                conn=conn,
                tenant_id=str(tenant_uuid),
                event_type="SLA_ESCALATION",
                aggregate_id=aid,
                payload={
                    "category": "SLA_BREACH",
                    "alert_id": aid,
                    "threat_level": threat,
                    "rule_name": rule,
                    "status": a["status"],
                },
            )

    # 2. Approaching / Overdue 30-Day BSA SAR Statutory Deadlines (<= 5 days)
    urgent_sars = await conn.fetch(
        """
        SELECT id, alert_id, status, statutory_deadline_at
        FROM sar_drafts
        WHERE status IN ('DRAFT', 'PENDING_MLRO_REVIEW', 'APPROVED')
          AND statutory_deadline_at IS NOT NULL
          AND statutory_deadline_at <= NOW() + INTERVAL '5 days'
        ORDER BY statutory_deadline_at ASC
        LIMIT 50;
        """
    )
    now_utc = datetime.now(timezone.utc)
    for s in (urgent_sars or []):
        sid = str(s["id"])
        dl = s["statutory_deadline_at"]
        if dl.tzinfo is None:
            dl = dl.replace(tzinfo=timezone.utc)
        days_left = int((dl - now_utc).total_seconds() // 86400)
        is_overdue = days_left < 0
        title = (
            f"OVERDUE BSA SAR Filing ({abs(days_left)}d past deadline)"
            if is_overdue
            else f"BSA 30-Day SAR Deadline in {days_left}d"
        )
        nid = await create_notification(
            conn=conn,
            tenant_id=tenant_uuid,
            category="SAR_DEADLINE_WARNING",
            severity="CRITICAL" if is_overdue or days_left <= 2 else "WARNING",
            recipient_role="MLRO",
            title=title,
            body=f"SAR Draft {sid[:8]} (status: {s['status']}) requires immediate MLRO review and FinCEN transmission.",
            link_url=f"/sar/editor?draft_id={sid}",
            resource_type="SAR_DRAFT",
            resource_id=sid,
        )
        if nid:
            sar_escalations += 1
            created_ids.append(nid)
            await enqueue_webhook_event_tx(
                conn=conn,
                tenant_id=str(tenant_uuid),
                event_type="SLA_ESCALATION",
                aggregate_id=sid,
                payload={
                    "category": "SAR_DEADLINE_WARNING",
                    "sar_draft_id": sid,
                    "days_until_deadline": days_left,
                    "is_overdue": is_overdue,
                },
            )

    return {
        "checked_at": now_utc.isoformat(),
        "alert_sla_escalations": alert_escalations,
        "sar_deadline_escalations": sar_escalations,
        "total_notifications_created": len(created_ids),
        "notification_ids": created_ids,
    }
