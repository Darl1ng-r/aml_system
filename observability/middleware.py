"""
Correlation-ID Middleware
==========================
Generates (or extracts from the incoming ``X-Correlation-ID`` header) a unique
correlation ID and stores it in a ``contextvars.ContextVar`` so that every log
line emitted during the request lifetime carries the same ID.

The ID is also returned to the client via the ``X-Correlation-ID`` response
header, making end-to-end request tracing trivial.
"""

import contextvars
import uuid

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

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


import time
import re

_UUID_REGEX = re.compile(r"/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
_NUMERIC_ID_REGEX = re.compile(r"/\d+")
_CORRELATION_ID_RE = re.compile(r"^[A-Za-z0-9._-]{8,64}$")


def sanitize_correlation_id(raw: str | None) -> str:
    """Validates inbound X-Correlation-ID against strict charset & length (fixes P3-03)."""
    if raw and _CORRELATION_ID_RE.fullmatch(raw.strip()):
        return raw.strip()
    return str(uuid.uuid4())


def normalize_metric_path(request: Request) -> str:
    """Normalizes URL paths to prevent Prometheus metric label cardinality explosion."""
    route = request.scope.get("route")
    if route and hasattr(route, "path"):
        return getattr(route, "path")
    path = request.scope.get("path") or (request.url.path if hasattr(request, "url") else "")
    path = _UUID_REGEX.sub("/{id}", path)
    path = _NUMERIC_ID_REGEX.sub("/{id}", path)
    return path


class CorrelationIdMiddleware(BaseHTTPMiddleware):
    """
    FastAPI / Starlette middleware that:
    1. Reads ``X-Correlation-ID`` from the request (or generates a UUID4).
    2. Stores ``correlation_id_var``, ``tenant_id_var``, and ``user_id_var`` in contextvars.
    3. Echoes ``X-Correlation-ID`` back in the response headers.
    4. Records Prometheus HTTP request counts and latency metrics.
    """

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        cid = sanitize_correlation_id(request.headers.get("x-correlation-id"))

        # Security: Never trust raw unauthenticated X-Tenant-ID headers in log context.
        # tenant_id_var & user_id_var are populated strictly after JWT/gateway verification.
        correlation_id_var.set(cid)
        tenant_id_var.set("")
        user_id_var.set("")

        t0 = time.monotonic()
        try:
            response = await call_next(request)
            duration = time.monotonic() - t0
            # Normalize AFTER call_next() so request.scope["route"] is populated
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
