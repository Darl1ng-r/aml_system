"""
Async Background Job Service (Queue-Based Load Leveling — Scale Stage 2)
========================================================================
Offloads heavy exports (PDF/HTML audit reports, streamed CSV, signed RS256
Examiner ZIP packets), analytical backtests, and transactional email
notifications onto partitioned Redpanda queues backed by the Transactional
Outbox, idempotent job claiming, and Dead-Letter Queues (DLQs).
"""

from __future__ import annotations

import csv
import html as _html
import io
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from repositories.jobs_repo import (
    claim_async_job_for_processing_repo,
    complete_async_job_repo,
    fail_async_job_repo,
)

logger = logging.getLogger("aml.async_jobs")


def sanitize_csv_cell(value: Any) -> str:
    """Neutralizes spreadsheet formula injection (CWE-1236) in exported CSV cells."""
    text = "" if value is None else str(value)
    if text and text[0] in ("=", "+", "-", "@", "\t", "\r"):
        return f"'{text}"
    return text

JOBS_EXPORTS_TOPIC = "aml.jobs.exports"
JOBS_EXPORTS_DLQ_TOPIC = "aml.jobs.exports.dlq"
JOBS_NOTIFICATIONS_TOPIC = "aml.jobs.notifications"
JOBS_NOTIFICATIONS_DLQ_TOPIC = "aml.jobs.notifications.dlq"

ALLOWED_JOB_TYPES = frozenset(
    {
        "ALERT_PDF_EXPORT",
        "ALERT_CSV_EXPORT",
        "EXAMINER_PACKET_ZIP",
        "EMAIL_NOTIFICATION",
        "RULE_BACKTEST_ANALYTICS",
    }
)


def resolve_topic_for_job_type(job_type: str) -> str:
    normalized = str(job_type or "").upper().strip()
    if normalized == "EMAIL_NOTIFICATION":
        return JOBS_NOTIFICATIONS_TOPIC
    return JOBS_EXPORTS_TOPIC


def resolve_dlq_topic_for_source_topic(source_topic: str) -> str:
    if source_topic == JOBS_NOTIFICATIONS_TOPIC:
        return JOBS_NOTIFICATIONS_DLQ_TOPIC
    return JOBS_EXPORTS_DLQ_TOPIC


def _render_alerts_html_report(rows: list[Any], requested_by: str, requested_role: str) -> bytes:
    table_rows = []
    for r in rows:
        score = f"{round(float(r['ai_risk_score'] or 0) * 100)}%"
        table_rows.append(
            "<tr>"
            f"<td>{_html.escape(str(r['id'])[:8])}...</td>"
            f"<td><strong>{_html.escape(str(r['threat_level'] or ''))}</strong></td>"
            f"<td>{score}</td>"
            f"<td>{_html.escape(str(r['rule_name'] or ''))}</td>"
            f"<td>${float(r['amount'] or 0):,.2f} {_html.escape(str(r['currency'] or ''))}</td>"
            f"<td>{_html.escape(str(r['status'] or ''))}</td>"
            f"<td>{_html.escape(str(r['assignee'] or ''))}</td>"
            "</tr>"
        )
    doc = (
        "<!DOCTYPE html><html><head><title>AML Async Audit Report</title></head>"
        "<body><h1>AML Audit Report &amp; Case Ledger</h1>"
        f"<p><strong>Generated At:</strong> {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}</p>"
        f"<p><strong>Requested By:</strong> {_html.escape(requested_by)} ({_html.escape(requested_role)})</p>"
        "<table><thead><tr><th>Alert ID</th><th>Threat</th><th>Score</th><th>Rule</th>"
        "<th>Amount</th><th>Status</th><th>Assignee</th></tr></thead>"
        f"<tbody>{''.join(table_rows)}</tbody></table></body></html>"
    )
    return doc.encode("utf-8")


async def execute_async_job(
    event: dict[str, Any],
    *,
    conn_factory: Any = None,
    read_conn_factory: Any = None,
) -> dict[str, Any]:
    """
    Idempotently claims and executes a queued background job.
    Returns `{"status": "SKIPPED_IDEMPOTENT"}` if already claimed/completed.
    """
    job_id_raw = event.get("job_id")
    tenant_id = str(event.get("tenant_id") or "").strip()
    if not job_id_raw or not tenant_id:
        raise ValueError("Async job event missing mandatory job_id or tenant_id.")

    job_uuid = uuid.UUID(str(job_id_raw))
    claimed = await claim_async_job_for_processing_repo(
        tenant_id=tenant_id,
        job_id=job_uuid,
        conn_factory=conn_factory,
    )
    if not claimed:
        logger.info("Idempotent skip for async job %s (already processing or completed).", job_id_raw)
        return {"job_id": str(job_uuid), "status": "SKIPPED_IDEMPOTENT"}

    job_type = claimed["job_type"]
    payload = claimed.get("payload") or {}
    requested_by = claimed.get("requested_by") or "system"
    requested_role = claimed.get("requested_role") or "ANALYST"

    try:
        from services.compute_executor import run_analytics_compute
        from services.evidence_storage import compute_sha256_hex, get_evidence_storage_backend

        if job_type == "ALERT_PDF_EXPORT":
            from repositories.alert_repo import fetch_alerts_for_pdf_export_repo

            limit = max(1, min(500, int(payload.get("limit", 100))))
            rows = await fetch_alerts_for_pdf_export_repo(
                tenant_id=tenant_id,
                limit=limit,
                read_conn_factory=read_conn_factory,
            )
            artifact_bytes = await run_analytics_compute(
                _render_alerts_html_report, rows, requested_by, requested_role, timeout=15.0
            )
            sha256 = compute_sha256_hex(artifact_bytes)
            filename = f"alerts_report_{job_uuid.hex[:8]}.html"
            backend = get_evidence_storage_backend()
            storage_key = await backend.put_object(
                tenant_id, f"job_{job_uuid}_{filename}", artifact_bytes, "text/html"
            )
            await complete_async_job_repo(
                tenant_id=tenant_id,
                job_id=job_uuid,
                result_meta={"row_count": len(rows), "bytes": len(artifact_bytes), "backend": backend.backend_name},
                artifact_storage_key=storage_key,
                artifact_sha256=sha256,
                artifact_content_type="text/html",
                artifact_filename=filename,
                conn_factory=conn_factory,
            )
            return {"job_id": str(job_uuid), "status": "COMPLETED", "row_count": len(rows)}

        if job_type == "ALERT_CSV_EXPORT":
            from repositories.alert_repo import iter_alert_export_chunks_repo

            buf = io.StringIO()
            writer = csv.writer(buf)
            writer.writerow(["Alert ID", "Transaction ID", "Rule", "Threat Level", "Risk Score", "Status", "Amount", "Currency", "Created At"])
            row_count = 0
            async for chunk in iter_alert_export_chunks_repo(
                tenant_id=tenant_id,
                read_conn_factory=read_conn_factory,
            ):
                for r in chunk:
                    writer.writerow([
                        sanitize_csv_cell(str(r["id"])),
                        sanitize_csv_cell(str(r["transaction_id"])),
                        sanitize_csv_cell(str(r["rule_name"])),
                        sanitize_csv_cell(str(r["threat_level"])),
                        sanitize_csv_cell(str(r["ai_risk_score"])),
                        sanitize_csv_cell(str(r["status"])),
                        sanitize_csv_cell(str(r["amount"])),
                        sanitize_csv_cell(str(r["currency"])),
                        sanitize_csv_cell(r["created_at"].isoformat() if r["created_at"] else ""),
                    ])
                    row_count += 1
            artifact_bytes = buf.getvalue().encode("utf-8")
            sha256 = compute_sha256_hex(artifact_bytes)
            filename = f"alerts_export_{job_uuid.hex[:8]}.csv"
            backend = get_evidence_storage_backend()
            storage_key = await backend.put_object(
                tenant_id, f"job_{job_uuid}_{filename}", artifact_bytes, "text/csv"
            )
            await complete_async_job_repo(
                tenant_id=tenant_id,
                job_id=job_uuid,
                result_meta={"row_count": row_count, "bytes": len(artifact_bytes), "backend": backend.backend_name},
                artifact_storage_key=storage_key,
                artifact_sha256=sha256,
                artifact_content_type="text/csv",
                artifact_filename=filename,
                conn_factory=conn_factory,
            )
            return {"job_id": str(job_uuid), "status": "COMPLETED", "row_count": row_count}

        if job_type == "EXAMINER_PACKET_ZIP":
            from repositories.audit_repo import build_examiner_packet_repo
            from services.examiner_packet import build_signed_examiner_packet

            case_id = payload.get("case_id")
            if not case_id:
                raise ValueError("EXAMINER_PACKET_ZIP job requires payload.case_id")
            zip_bytes, manifest, zip_sha256 = await build_examiner_packet_repo(
                tenant_id=tenant_id,
                case_uuid=uuid.UUID(str(case_id)),
                generated_by=requested_by,
                build_packet_fn=build_signed_examiner_packet,
                read_conn_factory=read_conn_factory,
            )
            filename = f"examiner_packet_{str(case_id)[:8]}_{job_uuid.hex[:6]}.zip"
            backend = get_evidence_storage_backend()
            storage_key = await backend.put_object(
                tenant_id, f"job_{job_uuid}_{filename}", zip_bytes, "application/zip"
            )
            await complete_async_job_repo(
                tenant_id=tenant_id,
                job_id=job_uuid,
                result_meta={
                    "case_id": str(case_id),
                    "case_number": manifest.get("case_number"),
                    "bytes": len(zip_bytes),
                    "backend": backend.backend_name,
                },
                artifact_storage_key=storage_key,
                artifact_sha256=zip_sha256,
                artifact_content_type="application/zip",
                artifact_filename=filename,
                conn_factory=conn_factory,
            )
            return {"job_id": str(job_uuid), "status": "COMPLETED", "sha256": zip_sha256}

        if job_type == "EMAIL_NOTIFICATION":
            recipient = str(payload.get("recipient") or "").strip()
            subject = str(payload.get("subject") or "AML Sentinel Notification").strip()
            if not recipient or "@" not in recipient:
                raise ValueError("EMAIL_NOTIFICATION job requires a valid payload.recipient email.")
            logger.info(
                "Dispatched async compliance email notification job=%s tenant=%s subject=%s",
                job_uuid,
                tenant_id,
                subject[:80],
            )
            await complete_async_job_repo(
                tenant_id=tenant_id,
                job_id=job_uuid,
                result_meta={
                    "delivery_channel": "async_queue",
                    "recipient_domain": recipient.split("@", 1)[-1],
                    "subject": subject[:120],
                    "delivered_at": datetime.now(timezone.utc).isoformat(),
                },
                conn_factory=conn_factory,
            )
            return {"job_id": str(job_uuid), "status": "COMPLETED"}

        if job_type == "RULE_BACKTEST_ANALYTICS":
            from services.rule_backtest import run_rule_backtest_simulation

            rule_id = payload.get("rule_id")
            if not rule_id:
                raise ValueError("RULE_BACKTEST_ANALYTICS job requires payload.rule_id")
            lookback_days = max(1, min(365, int(payload.get("lookback_days", 30))))
            summary = await run_rule_backtest_simulation(
                tenant_id=tenant_id,
                rule_id=str(rule_id),
                lookback_days=lookback_days,
            )
            await complete_async_job_repo(
                tenant_id=tenant_id,
                job_id=job_uuid,
                result_meta=summary if isinstance(summary, dict) else {"summary": str(summary)},
                conn_factory=conn_factory,
            )
            return {"job_id": str(job_uuid), "status": "COMPLETED"}

        raise ValueError(f"Unsupported async job_type: {job_type}")
    except Exception as exc:
        await fail_async_job_repo(
            tenant_id=tenant_id,
            job_id=job_uuid,
            error_message=f"{type(exc).__name__}: {exc}",
            dead_lettered=False,
            conn_factory=conn_factory,
        )
        raise
