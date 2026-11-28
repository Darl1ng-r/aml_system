"""
Pure-ASGI Anti-CSRF Custom Header & Login-CSRF Origin Protection Middleware
===========================================================================
1. Defends cookie-authenticated state-changing requests (POST, PUT, PATCH, DELETE)
   by requiring `X-CSRF-Protection: 1` (custom headers trigger CORS preflight).
2. Normalizes trailing slashes on exempt paths (fixes P2-08).
3. Enforces Origin / Sec-Fetch-Site same-origin validation on exempt browser
   auth POSTs (`/api/v1/auth/login`, `/api/v1/auth/mfa/verify`, etc.) whenever
   an Origin or cross-site Sec-Fetch-Site header is present, neutralizing Login CSRF.
4. Pure ASGI implementation (zero BaseHTTPMiddleware body-buffering overhead)
   with canonical error envelopes including `correlation_id` and `trace_id`.
"""

from __future__ import annotations

import json
from urllib.parse import urlparse

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from config import settings
from observability.middleware import correlation_id_var, get_current_trace_id


def _csrf_error_payload(detail: str) -> dict:
    return {
        "detail": detail,
        "correlation_id": correlation_id_var.get("") or None,
        "trace_id": get_current_trace_id(),
    }


async def _send_csrf_json_error(send: Send, detail: str) -> None:
    body = json.dumps(_csrf_error_payload(detail)).encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": 403,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("ascii")),
                (b"cache-control", b"no-store"),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body, "more_body": False})


class CSRFProtectionMiddleware:
    STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
    EXEMPT_PATHS = {
        "/api/v1/auth/login",
        "/api/v1/auth/token",
        "/api/v1/auth/signup",
        "/api/v1/auth/register",
        "/api/v1/auth/mfa/verify",
    }

    def __init__(self, app: ASGIApp, exempt_paths: set[str] | None = None):
        self.app = app
        raw_exempt = exempt_paths or self.EXEMPT_PATHS
        self.exempt_paths = {p.rstrip("/") or "/" for p in raw_exempt}

    @staticmethod
    def _allowed_origins(request: Request) -> set[str]:
        origins = {o.strip().rstrip("/").lower() for o in settings.allowed_origins.split(",") if o.strip()}
        pub = (getattr(settings, "public_base_url", "") or "").strip().rstrip("/").lower()
        if pub:
            origins.add(pub)
        # Same-origin with the serving host itself
        host = request.headers.get("host", "").strip().lower()
        scheme = request.url.scheme.lower()
        if host:
            origins.add(f"{scheme}://{host}")
            origins.add(f"https://{host}")
        return origins

    def _is_cross_site_browser_auth_attempt(self, request: Request) -> bool:
        sec_fetch_site = (request.headers.get("sec-fetch-site") or "").strip().lower()
        if sec_fetch_site == "cross-site":
            return True

        origin = (request.headers.get("origin") or "").strip().rstrip("/").lower()
        if origin and origin != "null":
            if origin not in self._allowed_origins(request):
                return True
            return False

        referer = (request.headers.get("referer") or "").strip()
        if referer and getattr(settings, "is_hardened", settings.is_production):
            parsed = urlparse(referer)
            ref_origin = f"{parsed.scheme}://{parsed.netloc}".lower()
            if ref_origin not in self._allowed_origins(request):
                return True

        return False

    def _evaluate_csrf_rejection(self, request: Request) -> str | None:
        if request.method not in self.STATE_CHANGING_METHODS:
            return None

        normalized_path = request.url.path.rstrip("/") or "/"

        # Login-CSRF protection on exempt auth endpoints (P2-08)
        if normalized_path in self.exempt_paths:
            if self._is_cross_site_browser_auth_attempt(request):
                return "CSRF validation failed: cross-site Origin rejected on authentication endpoint."
            return None

        has_session_cookie = bool(
            request.cookies.get("access_token") or request.cookies.get("refresh_token")
        )
        if has_session_cookie:
            csrf_header = request.headers.get("x-csrf-protection")
            if csrf_header != "1":
                return "CSRF protection error. Missing required 'X-CSRF-Protection: 1' header."

        return None

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope)
        rejection_detail = self._evaluate_csrf_rejection(request)
        if rejection_detail is not None:
            await _send_csrf_json_error(send, rejection_detail)
            return

        await self.app(scope, receive, send)

    async def dispatch(self, request: Request, call_next):
        """Backwards-compatible helper for direct unit tests invoking dispatch()."""
        rejection_detail = self._evaluate_csrf_rejection(request)
        if rejection_detail is not None:
            return JSONResponse(status_code=403, content=_csrf_error_payload(rejection_detail))
        return await call_next(request)
