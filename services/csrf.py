"""
Anti-CSRF Custom Header & Login-CSRF Origin Protection Middleware
=================================================================
1. Defends cookie-authenticated state-changing requests (POST, PUT, PATCH, DELETE)
   by requiring `X-CSRF-Protection: 1` (custom headers trigger CORS preflight).
2. Normalizes trailing slashes on exempt paths (fixes P2-08).
3. Enforces Origin / Sec-Fetch-Site same-origin validation on exempt browser
   auth POSTs (`/api/v1/auth/login`, `/api/v1/auth/mfa/verify`, etc.) whenever
   an Origin or cross-site Sec-Fetch-Site header is present, neutralizing Login CSRF.
"""

from urllib.parse import urlparse
from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from config import settings


class CSRFProtectionMiddleware(BaseHTTPMiddleware):
    STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
    EXEMPT_PATHS = {
        "/api/v1/auth/login",
        "/api/v1/auth/token",
        "/api/v1/auth/signup",
        "/api/v1/auth/register",
        "/api/v1/auth/mfa/verify",
    }

    def __init__(self, app: ASGIApp, exempt_paths: set[str] | None = None):
        super().__init__(app)
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

    async def dispatch(self, request: Request, call_next):
        if request.method in self.STATE_CHANGING_METHODS:
            normalized_path = request.url.path.rstrip("/") or "/"

            # Login-CSRF protection on exempt auth endpoints (P2-08)
            if normalized_path in self.exempt_paths:
                if self._is_cross_site_browser_auth_attempt(request):
                    return JSONResponse(
                        status_code=403,
                        content={"detail": "CSRF validation failed: cross-site Origin rejected on authentication endpoint."},
                    )
                return await call_next(request)

            has_session_cookie = bool(
                request.cookies.get("access_token") or request.cookies.get("refresh_token")
            )
            if has_session_cookie:
                csrf_header = request.headers.get("x-csrf-protection")
                if csrf_header != "1":
                    return JSONResponse(
                        status_code=403,
                        content={"detail": "CSRF protection error. Missing required 'X-CSRF-Protection: 1' header."}
                    )

        return await call_next(request)
