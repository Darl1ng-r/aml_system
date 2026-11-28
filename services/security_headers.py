"""
Security Headers Middleware
===========================
Injects standard browser hardening headers on all HTTP responses:
  - Content-Security-Policy (CSP; WSS-only connect-src in hardened environments)
  - X-Frame-Options: DENY
  - X-Content-Type-Options: nosniff
  - Referrer-Policy (no-referrer on token-gated RFI/audit routes)
  - Strict-Transport-Security (single canonical source; Ingress snippet removed)
  - Cross-Origin-Opener-Policy / Cross-Origin-Resource-Policy / Permissions-Policy
  - Default `Cache-Control: no-store` & `Pragma: no-cache` on all `/api/*` endpoints (P1-15)
  - Attaches `X-RateLimit-*` response headers computed by RateLimiter when present
"""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
from starlette.requests import Request
from starlette.responses import Response

from config import settings

DEFAULT_CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://unpkg.com; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://unpkg.com; "
    "font-src 'self' https://fonts.gstatic.com; "
    "connect-src 'self' ws: wss:; "
    "img-src 'self' data: blob:; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "form-action 'self'; "
    "frame-ancestors 'none'; "
    "upgrade-insecure-requests;"
)

HARDENED_CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://unpkg.com; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://unpkg.com; "
    "font-src 'self' https://fonts.gstatic.com; "
    "connect-src 'self' wss:; "
    "img-src 'self' data: blob:; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "form-action 'self'; "
    "frame-ancestors 'none'; "
    "upgrade-insecure-requests;"
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp, csp: str | None = None):
        super().__init__(app)
        self._explicit_csp = csp

    def _effective_csp(self) -> str:
        if self._explicit_csp is not None:
            return self._explicit_csp
        if getattr(settings, "is_hardened", settings.is_production):
            return HARDENED_CSP
        return DEFAULT_CSP

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        path = request.url.path

        response.headers["Content-Security-Policy"] = self._effective_csp()
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"

        if path.startswith(("/rfi/", "/api/v1/rfi/public/", "/api/v1/audit/rooms/")):
            response.headers["Referrer-Policy"] = "no-referrer"
            response.headers["Cache-Control"] = "no-store"
            response.headers["CDN-Cache-Control"] = "no-store"
            response.headers["Pragma"] = "no-cache"
        else:
            response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")

        # P1-15 / Scale Stage 2: Prevent browser & CDN/edge proxy caching of ALL sensitive /api/*
        # responses via both Cache-Control and RFC 9213 CDN-Cache-Control defense-in-depth.
        if path.startswith("/api/"):
            if "cache-control" not in response.headers:
                response.headers["Cache-Control"] = "no-store"
                response.headers["Pragma"] = "no-cache"
            if "cdn-cache-control" not in response.headers:
                cc_val = response.headers.get("Cache-Control", "").lower()
                if "no-store" in cc_val or "private" in cc_val or "no-cache" in cc_val:
                    response.headers["CDN-Cache-Control"] = "no-store"
            existing_vary = response.headers.get("Vary", "")
            vary_tokens = {v.strip() for v in existing_vary.split(",") if v.strip()}
            vary_tokens.update({"Origin", "Cookie"})
            response.headers["Vary"] = ", ".join(sorted(vary_tokens))
        elif "cdn-cache-control" not in response.headers:
            cc_val = response.headers.get("Cache-Control", "").lower()
            if "no-store" in cc_val or "private" in cc_val:
                response.headers["CDN-Cache-Control"] = "no-store"

        # Single canonical HSTS header (duplicate Ingress snippet removed in ingress-tls.yaml)
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers["Permissions-Policy"] = (
            "geolocation=(), camera=(), microphone=(), payment=(), usb=(), "
            "display-capture=(), accelerometer=()"
        )

        # Attach X-RateLimit-* headers recorded by RateLimiter dependency if present
        rl_headers = getattr(request.state, "rate_limit_headers", None)
        if isinstance(rl_headers, dict):
            for k, v in rl_headers.items():
                response.headers.setdefault(k, v)

        return response
