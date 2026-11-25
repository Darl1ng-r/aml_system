"""
Enterprise HTTP Caching, Conditional Revalidation (ETag/304) & Optimistic Concurrency (If-Match)
=================================================================================================
Provides RFC 9110 compliant conditional request helpers for AML Sentinel APIs:
  - Strong SHA-256 ETag computation over canonical JSON payloads.
  - `If-None-Match` → `304 Not Modified` while strictly preserving `Cache-Control: no-store`
    and `Vary: Origin, Cookie` on sensitive API responses (zero PII written to browser/proxy disk).
  - `If-Match` optimistic concurrency enforcement (`412 Precondition Failed`) to prevent
    silent lost updates when multiple compliance officers edit the same rule, case, or SAR draft.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, Optional

from fastapi import HTTPException, Request, Response, status
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse


def compute_etag(payload: Any) -> str:
    """Computes a deterministic RFC 9110 strong ETag over a JSON-serializable payload."""
    encoded = jsonable_encoder(payload)
    canonical = json.dumps(encoded, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    digest = hashlib.sha256(canonical).hexdigest()[:24]
    return f'"{digest}"'


def build_version_etag(prefix: str, version: Any) -> str:
    """Builds a deterministic version-based strong ETag (e.g., `"rule-v3"`)."""
    clean = str(version if version is not None else 0).strip().replace('"', "")
    return f'"{prefix}-v{clean}"'


def build_entity_etag(prefix: str, entity_id: Any, updated_at: Any, state: Any = "") -> str:
    """Builds a deterministic entity-state strong ETag for optimistic concurrency."""
    ts = updated_at.isoformat() if hasattr(updated_at, "isoformat") else str(updated_at or "")
    raw = f"{prefix}:{entity_id}:{ts}:{state}".encode("utf-8")
    digest = hashlib.sha256(raw).hexdigest()[:20]
    return f'"{prefix}-{digest}"'


def _strip_weak_prefix(tag: str) -> str:
    t = tag.strip()
    if t.startswith("W/") or t.startswith("w/"):
        t = t[2:].strip()
    return t


def etag_matches(header_value: Optional[str], current_etag: str) -> bool:
    """Checks whether an `If-None-Match` or `If-Match` header matches `current_etag` (RFC 9110 §13.1)."""
    if not header_value:
        return False
    target = _strip_weak_prefix(current_etag)
    for part in header_value.split(","):
        candidate = part.strip()
        if not candidate:
            continue
        if candidate == "*":
            return True
        if _strip_weak_prefix(candidate) == target:
            return True
    return False


def build_conditional_json_response(
    request: Optional[Request],
    payload: Any,
    *,
    etag: Optional[str] = None,
    status_code: int = status.HTTP_200_OK,
    extra_headers: Optional[Dict[str, str]] = None,
) -> Response:
    """
    Returns `304 Not Modified` if `request`'s `If-None-Match` matches the payload's strong ETag;
    otherwise returns `JSONResponse` with `ETag`, `Cache-Control: no-store`, and `Vary: Origin, Cookie`.
    If `request` is None (e.g., direct Python unit-test invocation), returns `payload` unchanged.
    """
    if request is None:
        return payload  # type: ignore[return-value]

    encoded = jsonable_encoder(payload)
    computed_etag = etag or compute_etag(encoded)
    headers: Dict[str, str] = {
        "ETag": computed_etag,
        "Cache-Control": "no-store",
        "Pragma": "no-cache",
        "Vary": "Origin, Cookie",
    }
    if extra_headers:
        headers.update(extra_headers)

    if_none_match = request.headers.get("if-none-match")
    if if_none_match and etag_matches(if_none_match, computed_etag):
        return Response(status_code=status.HTTP_304_NOT_MODIFIED, headers=headers)

    return JSONResponse(content=encoded, status_code=status_code, headers=headers)


def check_if_match(
    request: Optional[Request],
    current_etag: str,
    *,
    resource_label: str = "resource",
) -> None:
    """
    Enforces optimistic concurrency when the caller supplies an `If-Match` header.
    Raises HTTP 412 Precondition Failed if the resource was modified since the client fetched it.
    """
    if request is None:
        return
    if_match = request.headers.get("if-match")
    if not if_match:
        return
    if not etag_matches(if_match, current_etag):
        raise HTTPException(
            status_code=status.HTTP_412_PRECONDITION_FAILED,
            detail=(
                f"Precondition Failed: {resource_label} was modified by another user or process. "
                "Reload the latest version and re-apply your changes."
            ),
            headers={"ETag": current_etag},
        )
