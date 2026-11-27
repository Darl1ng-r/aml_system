"""
Pure-ASGI Correlation-ID, Telemetry & Request-Deadline Middleware
=================================================================
1. `CorrelationIdMiddleware`: Pure ASGI middleware (eliminates Starlette
   `BaseHTTPMiddleware` streaming buffer overhead while keeping a `.dispatch()`
   compatibility helper for unit tests). Extracts/generates `X-Correlation-ID`,
   resets `tenant_id_var` and `user_id_var` fail-closed, echoes the header, and
   records normalized Prometheus HTTP metrics.
2. `RequestTimeoutMiddleware`: Pure ASGI request-deadline guard that bounds
   runaway HTTP handlers (default 20s; 60s for export/packet/backtest/network
   endpoints), returning structured HTTP 504 Gateway Timeout with correlation ID.
"""

from __future__ import annotations

import asyncio
import contextvars
import json
import re
import time
import uuid
from typing import Callable, Awaitable

from starlette.datastructures import MutableHeaders
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

# ContextVar accessible from logging filters, services, etc.
correlation_id_var: contextvars.ContextVar[str] = contextvars.ContextVar(
    "correlation_id", default=""
)
tenant_id_var: contextvars.ContextVar[str] = contextvars.ContextVar(
    "tenant_id", default=""
)
user_id_var: contextvars.ContextVar[str] = contextvars.ContextVar(
    "user_id", default=""
)

_UUID_REGEX = re.compile(r"/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
_NUMERIC_ID_REGEX = re.compile(r"/\d+")
_CORRELATION_ID_RE = re.compile(r"^[A-Za-z0-9._-]{8,64}$")

_EXTENDED_TIMEOUT_MARKERS = (
    "/export/",
    "/examiner-packet",
    "/backtest",
    "/network",
    "/watchlist/sync",
)


def sanitize_correlation_id(raw: str | None) -> str:
    """Validates inbound X-Correlation-ID against strict charset & length (fixes P3-03)."""
    if raw and _CORRELATION_ID_RE.fullmatch(raw.strip()):
        return raw.strip()
    return str(uuid.uuid4())


def get_current_trace_id() -> str:
    """Returns the active OpenTelemetry 32-hex trace_id if a valid span is active, else empty string."""
    try:
        from opentelemetry import trace

        span = trace.get_current_span()
        if span is not None:
            ctx = span.get_span_context()
            if ctx is not None and getattr(ctx, "is_valid", False) and ctx.trace_id:
                return f"{ctx.trace_id:032x}"
    except Exception:
        pass
    return ""


def _normalize_scope_path(scope: Scope) -> str:
    route = scope.get("route")
    if route and hasattr(route, "path"):
        return getattr(route, "path")
    path = scope.get("path") or ""
    path = _UUID_REGEX.sub("/{id}", path)
    path = _NUMERIC_ID_REGEX.sub("/{id}", path)
    return path


def normalize_metric_path(request: Request) -> str:
    """Normalizes URL paths to prevent Prometheus metric label cardinality explosion."""
    return _normalize_scope_path(request.scope)


def _extract_header_from_scope(scope: Scope, target_name: bytes) -> str | None:
    for k, v in scope.get("headers") or ():
        if k.lower() == target_name:
            try:
                return v.decode("latin-1")
            except Exception:
                return None
    return None


class CorrelationIdMiddleware:
    """
    Pure-ASGI FastAPI / Starlette middleware that:
    1. Reads ``X-Correlation-ID`` from the request (or generates a UUID4).
    2. Stores ``correlation_id_var``, ``tenant_id_var``, and ``user_id_var`` in contextvars.
    3. Echoes ``X-Correlation-ID`` back in response headers without buffering streams.
    4. Records Prometheus HTTP request counts and latency metrics.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        raw_cid = _extract_header_from_scope(scope, b"x-correlation-id")
        cid = sanitize_correlation_id(raw_cid)

        # Security: Never trust raw unauthenticated X-Tenant-ID headers in log context.
        tok_cid = correlation_id_var.set(cid)
        tok_tid = tenant_id_var.set("")
        tok_uid = user_id_var.set("")

        t0 = time.monotonic()
        status_code = 500

        async def send_wrapper(message: Message) -> None:
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = int(message.get("status", 200))
                headers = MutableHeaders(scope=message)
                headers["X-Correlation-ID"] = cid
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            duration = time.monotonic() - t0
            endpoint = _normalize_scope_path(scope)
            method = scope.get("method", "GET")
            try:
                from observability.prometheus import record_http_request
                record_http_request(method, endpoint, status_code, duration)
            except Exception:
                pass
            correlation_id_var.reset(tok_cid)
            tenant_id_var.reset(tok_tid)
            user_id_var.reset(tok_uid)

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        """Backward-compatible helper for unit tests invoking `.dispatch()` directly."""
        cid = sanitize_correlation_id(request.headers.get("x-correlation-id"))
        correlation_id_var.set(cid)
        tenant_id_var.set("")
        user_id_var.set("")

        t0 = time.monotonic()
        try:
            response = await call_next(request)
            duration = time.monotonic() - t0
            endpoint = normalize_metric_path(request)
            response.headers["X-Correlation-ID"] = cid
            try:
                from observability.prometheus import record_http_request
                record_http_request(request.method, endpoint, response.status_code, duration)
            except Exception:
                pass
            return response
        except Exception as exc:
            duration = time.monotonic() - t0
            endpoint = normalize_metric_path(request)
            try:
                from observability.prometheus import record_http_request
                record_http_request(request.method, endpoint, 500, duration)
            except Exception:
                pass
            raise exc


class RequestTimeoutMiddleware:
    """
    Pure-ASGI request deadline guard preventing runaway computations from tying up
    worker slots indefinitely. Skips WebSockets and already-started streaming responses.
    """

    def __init__(
        self,
        app: ASGIApp,
        default_timeout_seconds: float = 20.0,
        extended_timeout_seconds: float = 60.0,
    ) -> None:
        self.app = app
        self.default_timeout_seconds = max(1.0, float(default_timeout_seconds))
        self.extended_timeout_seconds = max(self.default_timeout_seconds, float(extended_timeout_seconds))

    def _deadline_for_path(self, path: str) -> float:
        lower = (path or "").lower()
        for marker in _EXTENDED_TIMEOUT_MARKERS:
            if marker in lower:
                return self.extended_timeout_seconds
        return self.default_timeout_seconds

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        deadline = self._deadline_for_path(path)
        response_started = False

        async def tracking_send(message: Message) -> None:
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await asyncio.wait_for(self.app(scope, receive, tracking_send), timeout=deadline)
        except asyncio.TimeoutError:
            if response_started:
                return
            cid = correlation_id_var.get("") or str(uuid.uuid4())
            tid = get_current_trace_id()
            payload = json.dumps(
                {
                    "detail": f"Request exceeded server deadline ({deadline:.0f}s).",
                    "correlation_id": cid,
                    "trace_id": tid,
                }
            ).encode("utf-8")
            resp_headers = [
                (b"content-type", b"application/json"),
                (b"x-correlation-id", cid.encode("latin-1")),
                (b"content-length", str(len(payload)).encode("ascii")),
            ]
            if tid:
                resp_headers.append((b"x-trace-id", tid.encode("latin-1")))
            await send(
                {
                    "type": "http.response.start",
                    "status": 504,
                    "headers": resp_headers,
                }
            )
            await send({"type": "http.response.body", "body": payload})


class ReadAfterWriteStickinessMiddleware:
    """
    Pure-ASGI middleware enforcing Read-Your-Own-Writes consistency when read
    replicas are active:
      - On GET/HEAD requests, checks `X-Read-Consistency: strong` or an active
        5-second State Redis stickiness marker for the caller and sets
        `force_primary_read_var = True`.
      - On successful (2xx) mutating requests (`POST`, `PUT`, `PATCH`, `DELETE`),
        records the caller's stickiness marker and emits `X-Read-Consistency-Window`.
    """

    _MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        from config import settings
        from database.read_after_write import (
            compute_caller_stickiness_id,
            force_primary_read_var,
            has_active_write_stickiness,
            mark_write_stickiness,
            read_routing_reason_var,
        )

        method = str(scope.get("method", "GET")).upper()
        auth_hdr = _extract_header_from_scope(scope, b"authorization")
        cookie_hdr = _extract_header_from_scope(scope, b"cookie")
        consistency_hdr = (_extract_header_from_scope(scope, b"x-read-consistency") or "").strip().lower()
        caller_fp = compute_caller_stickiness_id(
            authorization_header=auth_hdr,
            cookie_header=cookie_hdr,
        )

        force_primary = False
        reason = "replica"
        if consistency_hdr == "strong":
            force_primary = True
            reason = "primary_header_strong"
        elif method in ("GET", "HEAD") and caller_fp:
            if await has_active_write_stickiness(caller_fp):
                force_primary = True
                reason = "primary_raw_stickiness"

        tok_force = force_primary_read_var.set(force_primary)
        tok_reason = read_routing_reason_var.set(reason)
        window_seconds = max(1, int(getattr(settings, "read_after_write_window_seconds", 5)))
        status_code = 500

        async def send_wrapper(message: Message) -> None:
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = int(message.get("status", 200))
                if method in self._MUTATING_METHODS and 200 <= status_code < 300:
                    headers = MutableHeaders(scope=message)
                    headers["X-Read-Consistency-Window"] = str(window_seconds)
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
            if method in self._MUTATING_METHODS and 200 <= status_code < 300:
                effective_fp = caller_fp or compute_caller_stickiness_id(
                    tenant_id=tenant_id_var.get(""),
                    user_id=user_id_var.get(""),
                )
                if effective_fp:
                    await mark_write_stickiness(effective_fp, ttl_seconds=window_seconds)
        finally:
            force_primary_read_var.reset(tok_force)
            read_routing_reason_var.reset(tok_reason)
