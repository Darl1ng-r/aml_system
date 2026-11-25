"""
HashiCorp Vault HTTP API Client
================================
Thin async wrapper around the Vault HTTP API v1 with:
  - HTTPS enforcement in hardened environments (prod / staging)
  - Custom TLS CA / mTLS SSLContext integration
  - Persistent pooled httpx.AsyncClient reuse (no per-secret TCP+TLS churn)
  - Full-jitter exponential backoff retries on transient errors
  - Automatic AppRole re-authentication when token max-TTL renewal returns 403
"""

import asyncio
import logging
from typing import Any, Dict, Optional

try:
    import httpx
    _HTTPX_AVAILABLE = True
except ImportError:  # pragma: no cover
    _HTTPX_AVAILABLE = False

from services.http_client import full_jitter_backoff

logger = logging.getLogger(__name__)


class VaultAuthError(RuntimeError):
    """Raised when Vault authentication fails."""


class VaultSecretError(RuntimeError):
    """Raised when a Vault KV-v2 read fails."""


class VaultClient:
    """Async HashiCorp Vault client with pooled connections, TLS, and AppRole re-auth."""

    def __init__(self, addr: str, mount: str = "secret", timeout: float = 10.0) -> None:
        if not _HTTPX_AVAILABLE:  # pragma: no cover
            raise RuntimeError("httpx is required for VaultClient. Install it via pip.")
        from config import settings

        cleaned_addr = addr.rstrip("/")
        if getattr(settings, "is_hardened", settings.is_production) and not cleaned_addr.lower().startswith("https://"):
            raise VaultAuthError(
                f"CRITICAL: Plaintext Vault address '{cleaned_addr}' is forbidden in hardened environments. Use https://."
            )

        self.addr = cleaned_addr
        self.mount = mount
        self.timeout = timeout
        self._token: Optional[str] = None
        self._role_id: Optional[str] = None
        self._secret_id: Optional[str] = None
        self._client: Optional[httpx.AsyncClient] = None

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            verify: Any = True
            try:
                from services.tls_manager import get_ssl_context
                ssl_ctx = get_ssl_context()
                if ssl_ctx is not None:
                    verify = ssl_ctx
            except Exception as exc:
                logger.warning("VaultClient: could not load custom TLS context (%s); using system trust store.", exc)

            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(connect=min(3.0, self.timeout), read=self.timeout, write=self.timeout, pool=2.0),
                limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
                follow_redirects=False,
                verify=verify,
            )
        return self._client

    async def aclose(self) -> None:
        if self._client is not None and not self._client.is_closed:
            try:
                await self._client.aclose()
            except Exception:
                pass
        self._client = None

    async def _request_with_retry(self, method: str, url: str, *, retries: int = 2, **kwargs: Any) -> httpx.Response:
        client = self._get_client()
        last_exc: Optional[Exception] = None
        for attempt in range(retries + 1):
            try:
                resp = await client.request(method, url, **kwargs)
                if resp.status_code in (429, 500, 502, 503, 504) and attempt < retries:
                    await asyncio.sleep(full_jitter_backoff(0.3, attempt, cap=3.0))
                    continue
                return resp
            except httpx.RequestError as exc:
                last_exc = exc
                if attempt < retries:
                    await asyncio.sleep(full_jitter_backoff(0.3, attempt, cap=3.0))
                    continue
                raise
        assert last_exc is not None
        raise last_exc

    # ── Authentication ────────────────────────────────────────────────────

    async def authenticate_token(self, token: str) -> None:
        """Use a static Vault token (dev mode only — never use in production)."""
        await asyncio.sleep(0)
        self._token = token
        logger.info("VaultClient: authenticated via static token (dev mode).")

    async def authenticate_approle(self, role_id: str, secret_id: str) -> None:
        """Perform AppRole login and store credentials for transparent max-TTL re-auth."""
        url = f"{self.addr}/v1/auth/approle/login"
        payload = {"role_id": role_id, "secret_id": secret_id}
        self._role_id = role_id
        self._secret_id = secret_id

        try:
            resp = await self._request_with_retry("POST", url, json=payload)
        except httpx.RequestError as exc:
            raise VaultAuthError(f"VaultClient: network error during AppRole login: {exc}") from exc

        if resp.status_code != 200:
            raise VaultAuthError(f"VaultClient: AppRole login failed — HTTP {resp.status_code}: {resp.text}")

        body = resp.json()
        self._token = body["auth"]["client_token"]
        ttl = body["auth"].get("lease_duration", "unknown")
        logger.info("VaultClient: AppRole login successful (token TTL: %ss).", ttl)

    # ── KV-v2 Secret Read ─────────────────────────────────────────────────

    async def read_secret(self, path: str) -> Dict[str, Any]:
        """Read a KV-v2 secret and return its data.data dict."""
        if not self._token:
            raise VaultAuthError("VaultClient: not authenticated — call authenticate_* first.")

        url = f"{self.addr}/v1/{self.mount}/data/{path}"
        headers = {"X-Vault-Token": self._token}

        try:
            resp = await self._request_with_retry("GET", url, headers=headers)
        except httpx.RequestError as exc:
            raise VaultSecretError(f"VaultClient: network error reading secret '{path}': {exc}") from exc

        # Transparent AppRole re-authentication if token expired
        if resp.status_code == 403 and self._role_id and self._secret_id:
            logger.warning("VaultClient: received 403 reading '%s'; re-authenticating via AppRole...", path)
            await self.authenticate_approle(self._role_id, self._secret_id)
            headers = {"X-Vault-Token": self._token or ""}
            try:
                resp = await self._request_with_retry("GET", url, headers=headers, retries=1)
            except httpx.RequestError as exc:
                raise VaultSecretError(f"VaultClient: network error re-reading secret '{path}': {exc}") from exc

        if resp.status_code == 404:
            raise VaultSecretError(f"VaultClient: secret path '{path}' not found in mount '{self.mount}'.")
        if resp.status_code != 200:
            raise VaultSecretError(f"VaultClient: failed to read '{path}' — HTTP {resp.status_code}: {resp.text}")

        body = resp.json()
        secret_data: Dict[str, Any] = body.get("data", {}).get("data", {})
        logger.debug("VaultClient: read secret '%s' (%d keys).", path, len(secret_data))
        return secret_data

    # ── Token Renewal ─────────────────────────────────────────────────────

    async def renew_token(self) -> None:
        """Renew current client token; automatically re-authenticate via AppRole on 403."""
        if not self._token:
            return

        url = f"{self.addr}/v1/auth/token/renew-self"
        headers = {"X-Vault-Token": self._token}

        try:
            resp = await self._request_with_retry("POST", url, headers=headers, retries=1)
        except httpx.RequestError as exc:
            logger.warning("VaultClient: token renewal network error: %s", exc)
            return

        if resp.status_code == 200:
            ttl = resp.json().get("auth", {}).get("lease_duration", "?")
            logger.info("VaultClient: token renewed successfully (new TTL: %ss).", ttl)
        elif resp.status_code == 403 and self._role_id and self._secret_id:
            logger.warning("VaultClient: token max-TTL reached (HTTP 403); re-authenticating via AppRole...")
            await self.authenticate_approle(self._role_id, self._secret_id)
        else:
            logger.warning(
                "VaultClient: token renewal returned HTTP %s (token may be non-renewable — safe to ignore in dev).",
                resp.status_code,
            )
