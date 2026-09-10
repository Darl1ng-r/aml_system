"""
Anti-CSRF Header Verification Middleware
=========================================
Guards state-changing endpoints (POST, PUT, DELETE, PATCH) against Cross-Site
Request Forgery (CSRF) when using cookie-based session authentication.
Requires the presence of custom header 'X-CSRF-Protection: 1'.
"""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
from fastapi import Request
from fastapi.responses import JSONResponse

EXEMPT_PATHS = {
    "/api/v1/auth/login",
    "/api/v1/auth/signup",
    "/api/v1/auth/mfa/verify",
    "/docs",
    "/openapi.json",
}


class CSRFProtectionMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp, exempt_paths: set[str] | None = None):
        super().__init__(app)
        self.exempt_paths = exempt_paths or EXEMPT_PATHS

    async def dispatch(self, request: Request, call_next):
        if request.method in {"POST", "PUT", "DELETE", "PATCH"}:
            if request.url.path not in self.exempt_paths:
                csrf_header = request.headers.get("x-csrf-protection")
                has_cookie_session = bool(
                    request.cookies.get("access_token") or request.cookies.get("refresh_token")
                )
                
                # Enforce X-CSRF-Protection: 1 when using cookie-based session authentication
                if has_cookie_session and csrf_header != "1":
                    return JSONResponse(
                        status_code=403,
                        content={"detail": "CSRF protection error: missing or invalid 'X-CSRF-Protection: 1' header"}
                    )

        return await call_next(request)
