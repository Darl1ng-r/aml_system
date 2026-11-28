"""
Pure-ASGI Request Body Size Limit & Pre-Spool Guard Middleware
==============================================================
Protects FastAPI / Starlette from memory-exhaustion & chunked-transfer body DoS
before JSON, form-urlencoded, or multipart/form-data parsers buffer the payload:
  - Enforces strict Content-Length AND streaming byte-count caps (handles chunked encoding)
  - Default API body cap: 2 MiB (covers large SAR XMLs while blocking abuse)
  - Evidence & RFI upload endpoints: 26 MiB (25 MiB file + multipart metadata overhead)
  - Pre-validates unauthenticated `/api/v1/rfi/public/{token}/submit` token format
    BEFORE python-multipart spools uploaded bytes to RAM/tmpfs (fixes P1-02 & P1-03).
"""

from __future__ import annotations

import json
import re
from typing import Iterable, Tuple

from starlette.types import ASGIApp, Message, Receive, Scope, Send

DEFAULT_MAX_BODY_BYTES = 2 * 1024 * 1024       # 2 MiB for JSON / form payloads
UPLOAD_MAX_BODY_BYTES = 26 * 1024 * 1024       # 26 MiB for 25 MiB evidence/RFI uploads

_UPLOAD_PATH_PATTERNS: Tuple[re.Pattern[str], ...] = (
    re.compile(r"^/api/v1/cases/[^/]+/evidence/?$"),
    re.compile(r"^/api/v1/rfi/public/[^/]+/submit/?$"),
)
_RFI_SUBMIT_PATTERN = re.compile(r"^/api/v1/rfi/public/([^/]+)/submit/?$")


class _PayloadTooLargeError(Exception):
    pass


async def _send_json_error(send: Send, status_code: int, detail: str) -> None:
    from observability.middleware import correlation_id_var, get_current_trace_id

    payload = {
        "detail": detail,
        "correlation_id": correlation_id_var.get("") or None,
        "trace_id": get_current_trace_id(),
    }
    body = json.dumps(payload).encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": status_code,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("ascii")),
                (b"cache-control", b"no-store"),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body, "more_body": False})


class RequestBodySizeLimitMiddleware:
    """Pure ASGI middleware enforcing hard Content-Length and streaming body limits."""

    def __init__(
        self,
        app: ASGIApp,
        default_max_bytes: int = DEFAULT_MAX_BODY_BYTES,
        upload_max_bytes: int = UPLOAD_MAX_BODY_BYTES,
        upload_patterns: Iterable[re.Pattern[str]] = _UPLOAD_PATH_PATTERNS,
    ) -> None:
        self.app = app
        self.default_max_bytes = int(default_max_bytes)
        self.upload_max_bytes = int(upload_max_bytes)
        self.upload_patterns = tuple(upload_patterns)

    def _limit_for_path(self, path: str) -> int:
        for pat in self.upload_patterns:
            if pat.match(path):
                return self.upload_max_bytes
        return self.default_max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        method = str(scope.get("method", "GET")).upper()
        if method in {"GET", "HEAD", "OPTIONS"}:
            await self.app(scope, receive, send)
            return

        path = str(scope.get("path", ""))

        # P1-03: Reject malformed unauthenticated RFI tokens BEFORE multipart spooling
        rfi_match = _RFI_SUBMIT_PATTERN.match(path)
        if rfi_match:
            raw_token = rfi_match.group(1)
            try:
                from services.rfi import parse_rfi_token
                tenant_id, _ = parse_rfi_token(raw_token)
            except Exception:
                tenant_id = None
            if not tenant_id:
                await _send_json_error(send, 404, "Invalid documentation request link.")
                return

        max_bytes = self._limit_for_path(path)

        # Fast-path Content-Length header check
        headers = scope.get("headers") or []
        for name, value in headers:
            if name.lower() == b"content-length":
                try:
                    content_length = int(value.decode("ascii").strip())
                except (ValueError, UnicodeDecodeError):
                    await _send_json_error(send, 400, "Invalid Content-Length header.")
                    return
                if content_length < 0:
                    await _send_json_error(send, 400, "Invalid Content-Length header.")
                    return
                if content_length > max_bytes:
                    await _send_json_error(
                        send,
                        413,
                        f"Request payload too large (limit: {max_bytes // (1024 * 1024)} MB).",
                    )
                    return
                break

        # Streaming byte-counter wrapper to defeat chunked Transfer-Encoding bypasses
        bytes_received = 0
        response_started = False

        async def bounded_receive() -> Message:
            nonlocal bytes_received
            message = await receive()
            if message.get("type") == "http.request":
                chunk = message.get("body") or b""
                bytes_received += len(chunk)
                if bytes_received > max_bytes:
                    raise _PayloadTooLargeError()
            return message

        async def tracking_send(message: Message) -> None:
            nonlocal response_started
            if message.get("type") == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, bounded_receive, tracking_send)
        except _PayloadTooLargeError:
            if not response_started:
                await _send_json_error(
                    send,
                    413,
                    f"Request payload too large (limit: {max_bytes // (1024 * 1024)} MB).",
                )
