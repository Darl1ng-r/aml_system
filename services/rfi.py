"""
External Customer / RM Request-for-Information (RFI) Portal Service (P2-1)
===========================================================================
Enables investigators to send time-boxed, cryptographically hashed upload links
to Customers or Relationship Managers without granting workspace credentials:
  - Token format: `rfi_<tenant_hex>.<random_secret>` -> resolves tenant RLS strictly
    while storing only SHA-256(`token`) in `rfi_requests.token_hash`.
  - Automatically pauses the case SLA clock (`PENDING_EDD` + `sla_paused_at = NOW()`).
  - External portal exposes ZERO internal AML rules, risk scores, or SAR metadata
    (strict anti-tipping-off hygiene under 31 U.S.C. § 5318(g)(2)).
  - Uploaded documents pass through P0-3 ClamAV/EICAR malware scanning + SHA-256
    WORM Evidence Storage, resume the case SLA clock, and notify the investigator.
"""

import hashlib
import logging
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("aml.rfi")


def generate_rfi_token(tenant_id: str | uuid.UUID) -> Tuple[str, str]:
    """Generates `(raw_token, sha256_token_hash)` embedding tenant UUID hex for strict RLS lookup."""
    tenant_hex = uuid.UUID(str(tenant_id)).hex
    secret_part = secrets.token_urlsafe(24)
    raw_token = f"rfi_{tenant_hex}.{secret_part}"
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    return raw_token, token_hash


def parse_rfi_token(raw_token: str) -> Tuple[Optional[str], str]:
    """Extracts `(tenant_id_str, sha256_token_hash)` from an external RFI token."""
    if not raw_token or not raw_token.startswith("rfi_") or "." not in raw_token:
        return None, ""
    prefix = raw_token[4:].split(".", 1)[0]
    try:
        tenant_id = str(uuid.UUID(hex=prefix))
    except ValueError:
        return None, ""
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    return tenant_id, token_hash


def compute_sla_pause_delta_seconds(sla_paused_at: Optional[datetime], now_utc: Optional[datetime] = None) -> int:
    """Computes elapsed seconds a case SLA clock was paused while awaiting RFI response."""
    if sla_paused_at is None:
        return 0
    now = now_utc or datetime.now(timezone.utc)
    if sla_paused_at.tzinfo is None:
        sla_paused_at = sla_paused_at.replace(tzinfo=timezone.utc)
    return max(0, int((now - sla_paused_at).total_seconds()))


def serialize_public_rfi_safe(row: Any) -> Dict[str, Any]:
    """
    Strictly customer-safe projection for the unauthenticated external RFI portal.
    NEVER exposes case_id, internal case titles, rule names, risk scores, or SAR indicators.
    """
    expires = row["expires_at"]
    return {
        "status": row["status"],
        "recipient_role": row["recipient_role"],
        "prompt_message": row["prompt_message"],
        "requested_docs": list(row["requested_docs"] or []),
        "expires_at": expires.isoformat() if expires else None,
        "submitted_at": row["submitted_at"].isoformat() if row.get("submitted_at") else None,
    }


async def pause_case_sla_for_rfi(conn: Any, case_uuid: uuid.UUID) -> None:
    """Moves an active case to PENDING_EDD and starts the SLA pause clock if not already paused."""
    await conn.execute(
        """
        UPDATE cases
        SET status = CASE WHEN status IN ('OPEN', 'INVESTIGATING') THEN 'PENDING_EDD' ELSE status END,
            sla_paused_at = COALESCE(sla_paused_at, NOW()),
            updated_at = NOW()
        WHERE id = $1 AND status <> 'CLOSED';
        """,
        case_uuid,
    )


async def resume_case_sla_after_rfi(conn: Any, case_uuid: uuid.UUID) -> int:
    """Resumes the case SLA clock and accumulates total paused seconds."""
    row = await conn.fetchrow(
        "SELECT sla_paused_at, sla_paused_seconds, status FROM cases WHERE id = $1;",
        case_uuid,
    )
    if not row:
        return 0
    delta_secs = compute_sla_pause_delta_seconds(row["sla_paused_at"])
    total_paused = int(row["sla_paused_seconds"] or 0) + delta_secs
    await conn.execute(
        """
        UPDATE cases
        SET status = CASE WHEN status = 'PENDING_EDD' THEN 'INVESTIGATING' ELSE status END,
            sla_paused_at = NULL,
            sla_paused_seconds = $1,
            updated_at = NOW()
        WHERE id = $2;
        """,
        total_paused,
        case_uuid,
    )
    return delta_secs
