"""
Keyset (Cursor) Pagination & Legacy Offset Guardrails
=====================================================
Provides deterministic O(log N) keyset pagination using composite `(timestamp, id)`
opaque URL-safe Base64 cursors, paired with a strict `MAX_LEGACY_OFFSET` cap to
prevent deep `OFFSET` sequential scan denial-of-service on backward-compatible
`?page=` / `?offset=` routes.
"""

from __future__ import annotations

import base64
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence

from fastapi import HTTPException

MAX_LEGACY_OFFSET: int = 10_000


def validate_legacy_offset(offset: int, *, max_offset: int = MAX_LEGACY_OFFSET) -> int:
    """Clamps/validates legacy OFFSET parameters and blocks deep-OFFSET scans."""
    if offset < 0:
        raise HTTPException(status_code=400, detail="offset must be >= 0")
    if offset > max_offset:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Legacy offset pagination is capped at {max_offset} rows to protect database performance. "
                "Use opaque keyset pagination via the `cursor` query parameter (`next_cursor`) instead."
            ),
        )
    return int(offset)


def encode_keyset_cursor(sort_ts: datetime | str, row_id: str | uuid.UUID) -> str:
    """Encodes a `(timestamp, uuid)` tuple into an opaque URL-safe Base64 cursor."""
    if isinstance(sort_ts, datetime):
        ts_dt = sort_ts if sort_ts.tzinfo is not None else sort_ts.replace(tzinfo=timezone.utc)
        ts_str = ts_dt.astimezone(timezone.utc).isoformat()
    else:
        ts_str = str(sort_ts)
    payload = {"t": ts_str, "i": str(row_id)}
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def decode_keyset_cursor(
    cursor: str, *, require_uuid: bool = True
) -> tuple[datetime, uuid.UUID | str]:
    """Decodes and strictly validates an opaque keyset cursor, raising HTTP 400 if malformed."""
    if not cursor or not isinstance(cursor, str) or len(cursor) > 512:
        raise HTTPException(status_code=400, detail="Malformed pagination cursor.")
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
        data = json.loads(raw.decode("utf-8"))
        if not isinstance(data, dict) or "t" not in data or "i" not in data:
            raise ValueError("Missing cursor keys")
        ts_raw = str(data["t"])
        if ts_raw.endswith("Z"):
            ts_raw = ts_raw[:-1] + "+00:00"
        sort_ts = datetime.fromisoformat(ts_raw)
        if sort_ts.tzinfo is None:
            sort_ts = sort_ts.replace(tzinfo=timezone.utc)
        raw_id = str(data["i"]).strip()
        if not raw_id:
            raise ValueError("Empty cursor id")
        row_id: uuid.UUID | str = uuid.UUID(raw_id) if require_uuid else raw_id
        return sort_ts, row_id
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid or corrupted pagination cursor.")


def extract_next_cursor(
    items: Sequence[Mapping[str, Any]],
    *,
    has_more: bool,
    ts_field: str = "created_at",
    id_field: str = "id",
) -> str | None:
    """Computes `next_cursor` from the final item in a page when `has_more` is True."""
    if not has_more or not items:
        return None
    last = items[-1]
    ts_val = last.get(ts_field)
    id_val = last.get(id_field)
    if ts_val is None or id_val is None:
        return None
    return encode_keyset_cursor(ts_val, str(id_val))
