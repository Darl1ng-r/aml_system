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
        cid = request.headers.get("x-correlation-id", str(uuid.uuid4()))
        tenant_id = request.headers.get("x-tenant-id", "")

        correlation_id_var.set(cid)
        if tenant_id:
            tenant_id_var.set(tenant_id)
        user_id_var.set("")

        t0 = time.monotonic()
        try:
            response = await call_next(request)
            duration = time.monotonic() - t0
            response.headers["X-Correlation-ID"] = cid
            try:
                from observability.prometheus import record_http_request
                record_http_request(request.method, request.url.path, response.status_code, duration)
            except Exception:
                pass
            return response
        except Exception as exc:
            duration = time.monotonic() - t0
            try:
                from observability.prometheus import record_http_request
                record_http_request(request.method, request.url.path, 500, duration)
            except Exception:
                pass
            raise exc
