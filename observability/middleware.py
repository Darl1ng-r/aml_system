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


class CorrelationIdMiddleware(BaseHTTPMiddleware):
    """
    FastAPI / Starlette middleware that:
    1. Reads ``X-Correlation-ID`` from the request (or generates a UUID4).
    2. Stores it in ``correlation_id_var`` for the duration of the request.
    3. Echoes it back in the response headers.
    """

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        cid = request.headers.get("x-correlation-id", str(uuid.uuid4()))
        correlation_id_var.set(cid)

        response = await call_next(request)
        response.headers["X-Correlation-ID"] = cid
        return response
