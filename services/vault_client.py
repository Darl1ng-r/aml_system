"""
HashiCorp Vault HTTP API Client
================================
Thin async wrapper around the Vault HTTP API v1.

Supports:
  - AppRole authentication  (role_id + secret_id)
  - Dev-token authentication (VAULT_DEV_TOKEN env var — local dev only)
  - KV-v2 secret reads       (GET /v1/{mount}/data/{path})
  - Token renewal             (POST /v1/auth/token/renew-self)

Design decisions:
  - Uses httpx.AsyncClient directly rather than hvac so we stay fully async
    and avoid adding a second Vault SDK dependency.
  - The client is stateless except for the cached Vault token; callers are
    responsible for calling authenticate() before read_secret().
  - Raises VaultAuthError / VaultSecretError on failures so the caller can
    decide whether to hard-fail or fall back to env vars.
"""

import logging
from typing import Any, Dict, Optional

try:
    import httpx
    _HTTPX_AVAILABLE = True
except ImportError:  # pragma: no cover
    _HTTPX_AVAILABLE = False

logger = logging.getLogger(__name__)


class VaultAuthError(RuntimeError):
    """Raised when Vault authentication fails."""


class VaultSecretError(RuntimeError):
    """Raised when a Vault KV-v2 read fails."""


class VaultClient:
    """
    Async HashiCorp Vault client.

    Usage::

        client = VaultClient(addr="http://127.0.0.1:8200", mount="secret")
        await client.authenticate_approle(role_id="...", secret_id="...")
        data = await client.read_secret("aml/postgres")
        password = data["password"]
    """

    def __init__(self, addr: str, mount: str = "secret", timeout: float = 10.0) -> None:
        if not _HTTPX_AVAILABLE:  # pragma: no cover
            raise RuntimeError("httpx is required for VaultClient. Install it via pip.")
        self.addr = addr.rstrip("/")
        self.mount = mount
        self.timeout = timeout
        self._token: Optional[str] = None

    # ── Authentication ────────────────────────────────────────────────────

    async def authenticate_token(self, token: str) -> None:
        """Use a static Vault token (dev mode only — never use in production)."""
        self._token = token
        logger.info("VaultClient: authenticated via static token (dev mode).")

    async def authenticate_approle(self, role_id: str, secret_id: str) -> None:
        """
        Perform AppRole login and store the resulting client token.

        POST /v1/auth/approle/login
        """
        url = f"{self.addr}/v1/auth/approle/login"
        payload = {"role_id": role_id, "secret_id": secret_id}

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                resp = await client.post(url, json=payload)
            except httpx.RequestError as exc:
                raise VaultAuthError(
                    f"VaultClient: network error during AppRole login: {exc}"
                ) from exc

        if resp.status_code != 200:
            raise VaultAuthError(
                f"VaultClient: AppRole login failed — HTTP {resp.status_code}: {resp.text}"
            )

        body = resp.json()
        self._token = body["auth"]["client_token"]
        ttl = body["auth"].get("lease_duration", "unknown")
        logger.info(f"VaultClient: AppRole login successful (token TTL: {ttl}s).")

    # ── KV-v2 Secret Read ─────────────────────────────────────────────────

    async def read_secret(self, path: str) -> Dict[str, Any]:
        """
        Read a KV-v2 secret and return its data dict.

        GET /v1/{mount}/data/{path}

        Returns the ``data.data`` sub-key from the KV-v2 response envelope,
        i.e. the actual key/value pairs stored at that path.
        """
        if not self._token:
            raise VaultAuthError("VaultClient: not authenticated — call authenticate_* first.")

        url = f"{self.addr}/v1/{self.mount}/data/{path}"
        headers = {"X-Vault-Token": self._token}

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                resp = await client.get(url, headers=headers)
            except httpx.RequestError as exc:
                raise VaultSecretError(
                    f"VaultClient: network error reading secret '{path}': {exc}"
                ) from exc

        if resp.status_code == 404:
            raise VaultSecretError(
                f"VaultClient: secret path '{path}' not found in mount '{self.mount}'."
            )
        if resp.status_code != 200:
            raise VaultSecretError(
                f"VaultClient: failed to read '{path}' — HTTP {resp.status_code}: {resp.text}"
            )

        body = resp.json()
        # KV-v2 wraps the payload: { data: { data: { key: val, ... }, metadata: {...} } }
        secret_data: Dict[str, Any] = body.get("data", {}).get("data", {})
        logger.debug(f"VaultClient: read secret '{path}' ({len(secret_data)} keys).")
        return secret_data

    # ── Token Renewal ─────────────────────────────────────────────────────

    async def renew_token(self) -> None:
        """
        Renew the current client token.

        POST /v1/auth/token/renew-self
        Safe to call on a non-renewable token — just logs a warning.
        """
        if not self._token:
            return

        url = f"{self.addr}/v1/auth/token/renew-self"
        headers = {"X-Vault-Token": self._token}

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                resp = await client.post(url, headers=headers)
            except httpx.RequestError as exc:
                logger.warning(f"VaultClient: token renewal network error: {exc}")
                return

        if resp.status_code == 200:
            ttl = resp.json().get("auth", {}).get("lease_duration", "?")
            logger.info(f"VaultClient: token renewed successfully (new TTL: {ttl}s).")
        else:
            logger.warning(
                f"VaultClient: token renewal returned HTTP {resp.status_code} "
                f"(token may be non-renewable — safe to ignore in dev)."
            )
