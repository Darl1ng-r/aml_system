"""
Pure-ASGI Security Headers Middleware
=====================================
Injects standard browser hardening headers on all HTTP responses without
Starlette `BaseHTTPMiddleware` stream-buffering overhead:
  - Strict zero-`unsafe-inline`, zero-CDN `API_CSP` on `/api/*`, `/health*`,
    `/.well-known/*`, and `/metrics`
  - Version-pinned SRI CDN paths + per-request cryptographic CSP nonces
    (`script-src-elem 'self' 'nonce-...'`) on server-rendered HTML pages
  - X-Frame-Options: DENY
  - X-Content-Type-Options: nosniff
  - Referrer-Policy (no-referrer on token-gated RFI/audit routes)
  - Strict-Transport-Security (single canonical source; Ingress snippet removed)
  - Cross-Origin-Opener-Policy / Cross-Origin-Resource-Policy / Permissions-Policy
  - Default `Cache-Control: no-store`, `CDN-Cache-Control: no-store`, & `Pragma: no-cache`
    on all `/api/*` endpoints (P1-15 / Scale Stage 2)
  - Attaches `X-RateLimit-*` response headers computed by RateLimiter when present
"""

from __future__ import annotations

import secrets
from starlette.datastructures import MutableHeaders
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from config import settings

# Exact SRI-pinned external CDN assets used by static/index.html & static/network.html
_PINNED_SCRIPT_CDNS = (
    "https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js "
    "https://unpkg.com/vis-network@10.1.2/standalone/umd/vis-network.min.js"
)
_PINNED_STYLE_CDNS = (
    "https://fonts.googleapis.com "
    "https://unpkg.com/vis-network@10.1.2/styles/vis-network.min.css"
)

# Locked-down machine/API CSP: zero 'unsafe-inline', zero third-party CDNs
API_CSP = (
    "default-src 'none'; "
    "frame-ancestors 'none'; "
    "base-uri 'none'; "
    "form-action 'none'; "
    "upgrade-insecure-requests;"
)

DEFAULT_CSP = (
    "default-src 'self'; "
    f"script-src 'self' 'unsafe-inline' {_PINNED_SCRIPT_CDNS}; "
    f"style-src 'self' 'unsafe-inline' {_PINNED_STYLE_CDNS}; "
    "font-src 'self' https://fonts.gstatic.com; "
    "connect-src 'self' ws: wss:; "
    "img-src 'self' data: blob:; "
    "worker-src 'self' blob:; "
    "child-src 'none'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "form-action 'self'; "
    "frame-ancestors 'none'; "
    "upgrade-insecure-requests;"
)

HARDENED_CSP = (
    "default-src 'self'; "
    f"script-src 'self' 'unsafe-inline' {_PINNED_SCRIPT_CDNS}; "
    f"style-src 'self' 'unsafe-inline' {_PINNED_STYLE_CDNS}; "
    "font-src 'self' https://fonts.gstatic.com; "
    "connect-src 'self' wss:; "
    "img-src 'self' data: blob:; "
    "worker-src 'self' blob:; "
    "child-src 'none'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "form-action 'self'; "
    "frame-ancestors 'none'; "
    "upgrade-insecure-requests;"
)

_API_CSP_PREFIXES = ("/api/", "/health", "/.well-known/", "/metrics")


def _is_api_or_machine_path(path: str) -> bool:
    return path == "/health" or path == "/metrics" or path.startswith(_API_CSP_PREFIXES)


def build_nonce_enforced_csp(base_csp: str, nonce: str) -> str:
    """
    Upgrades an HTML CSP with a per-request cryptographic nonce via `script-src-elem`
    so injected `<script>` tags are strictly blocked without breaking legacy inline
    event attributes (`script-src-attr`).
    """
    return (
        f"{base_csp} "
        f"script-src-elem 'self' 'nonce-{nonce}' {_PINNED_SCRIPT_CDNS};"
    )


class SecurityHeadersMiddleware:
    """Pure-ASGI security headers middleware with strict API CSP & per-request HTML nonces."""

    def __init__(self, app: ASGIApp, csp: str | None = None):
        self.app = app
        self._explicit_csp = csp

    def _effective_csp(
        self,
        path: str = "",
        *,
        csp_nonce: str | None = None,
        nonce_applied: bool = False,
    ) -> str:
        if self._explicit_csp is not None:
            return self._explicit_csp
        if path and _is_api_or_machine_path(path):
            return API_CSP
        base_csp = (
            HARDENED_CSP
            if getattr(settings, "is_hardened", settings.is_production)
            else DEFAULT_CSP
        )
        if nonce_applied and csp_nonce:
            return build_nonce_enforced_csp(base_csp, csp_nonce)
        return base_csp

    def _apply_headers(
        self,
        headers: MutableHeaders,
        path: str,
        state: dict,
    ) -> None:
        csp_nonce = state.get("csp_nonce")
        nonce_applied = bool(state.get("csp_nonce_applied", False))

        headers["Content-Security-Policy"] = self._effective_csp(
            path,
            csp_nonce=csp_nonce,
            nonce_applied=nonce_applied,
        )
        headers["X-Frame-Options"] = "DENY"
        headers["X-Content-Type-Options"] = "nosniff"

        if path.startswith(("/rfi/", "/api/v1/rfi/public/", "/api/v1/audit/rooms/")):
            headers["Referrer-Policy"] = "no-referrer"
            headers["Cache-Control"] = "no-store"
            headers["CDN-Cache-Control"] = "no-store"
            headers["Pragma"] = "no-cache"
        else:
            headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")

        # P1-15 / Scale Stage 2: Prevent browser & CDN/edge proxy caching of ALL sensitive /api/*
        # responses via both Cache-Control and RFC 9213 CDN-Cache-Control defense-in-depth.
        if path.startswith("/api/"):
            if "cache-control" not in headers:
                headers["Cache-Control"] = "no-store"
                headers["Pragma"] = "no-cache"
            if "cdn-cache-control" not in headers:
                cc_val = headers.get("Cache-Control", "").lower()
                if "no-store" in cc_val or "private" in cc_val or "no-cache" in cc_val:
                    headers["CDN-Cache-Control"] = "no-store"
            existing_vary = headers.get("Vary", "")
            vary_tokens = {v.strip() for v in existing_vary.split(",") if v.strip()}
            vary_tokens.update({"Origin", "Cookie"})
            headers["Vary"] = ", ".join(sorted(vary_tokens))
        elif "cdn-cache-control" not in headers:
            cc_val = headers.get("Cache-Control", "").lower()
            if "no-store" in cc_val or "private" in cc_val:
                headers["CDN-Cache-Control"] = "no-store"

        # Single canonical HSTS header (duplicate Ingress snippet removed in ingress-tls.yaml)
        headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
        headers["Cross-Origin-Opener-Policy"] = "same-origin"
        headers["Cross-Origin-Resource-Policy"] = "same-origin"
        headers["Permissions-Policy"] = (
            "geolocation=(), camera=(), microphone=(), payment=(), usb=(), "
            "display-capture=(), accelerometer=()"
        )

        # Attach X-RateLimit-* headers recorded by RateLimiter dependency if present
        rl_headers = state.get("rate_limit_headers")
        if isinstance(rl_headers, dict):
            for k, v in rl_headers.items():
                headers.setdefault(k, v)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        path = str(scope.get("path", ""))
        state = scope.setdefault("state", {})
        if not _is_api_or_machine_path(path):
            state.setdefault("csp_nonce", secrets.token_urlsafe(16))

        async def send_with_security_headers(message: Message) -> None:
            if message.get("type") == "http.response.start":
                headers = MutableHeaders(scope=message)
                self._apply_headers(headers, path, state)
            await send(message)

        await self.app(scope, receive, send_with_security_headers)

    async def dispatch(self, request: Request, call_next) -> Response:
        """Backwards-compatible helper for direct unit tests invoking dispatch()."""
        path = request.url.path
        if not _is_api_or_machine_path(path) and not getattr(request.state, "csp_nonce", None):
            request.state.csp_nonce = secrets.token_urlsafe(16)
        response = await call_next(request)
        state_dict = getattr(request.state, "_state", {})
        self._apply_headers(response.headers, path, state_dict)
        return response
