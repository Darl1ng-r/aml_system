"""
Security Headers Middleware
===========================
Injects standard browser hardening headers on all HTTP responses (Findings #22, #23):
- Content-Security-Policy (CSP)
- X-Frame-Options: DENY
- X-Content-Type-Options: nosniff
- Referrer-Policy: strict-origin-when-cross-origin
- Permissions-Policy
"""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
from starlette.requests import Request
from starlette.responses import Response

DEFAULT_CSP = (
    "default-src 'self'; "
    "script-src 'self' cdn.jsdelivr.net unpkg.com; "
    "style-src 'self' 'unsafe-inline' fonts.googleapis.com unpkg.com; "
    "font-src 'self' fonts.gstatic.com; "
    "connect-src 'self' ws: wss:; "
    "img-src 'self' data: https:; "
    "frame-ancestors 'none'; "
    "upgrade-insecure-requests;"
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp, csp: str = DEFAULT_CSP):
        super().__init__(app)
        self.csp = csp

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = self.csp
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers["Permissions-Policy"] = (
            "geolocation=(), camera=(), microphone=(), payment=(), usb=(), "
            "display-capture=(), accelerometer=()"
        )
        return response
