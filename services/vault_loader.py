"""
Vault Secrets Loader & SecretStore
====================================
Application-level bootstrap that fetches all required secrets from
HashiCorp Vault KV-v2 at startup, caches them in an in-memory
``SecretStore``, and schedules a background renewal task so long-running
workers automatically pick up rotated credentials.

Fallback behaviour
------------------
When ``VAULT_ADDR`` is **not** set (i.e. local development), ``bootstrap()``
logs a notice and returns immediately.  Every ``SecretStore.get()`` call
then falls back to environment variables, preserving the existing local-dev
workflow with no Vault installation required.

Secret layout (KV-v2 mount: ``secret``)
-----------------------------------------
  secret/data/aml/postgres       → password, user, host, port, db
  secret/data/aml/neo4j          → password, user, uri
  secret/data/aml/elasticsearch  → password, user
  secret/data/aml/jwt            → secret_keys  (comma-separated rotation list)
  secret/data/aml/fincen         → api_key, file_password, transmitter_tin, efiling_url
  secret/data/aml/watchlists     → worldcheck_api_key, worldcheck_api_secret, dowjones_api_key
  secret/data/aml/supabase       → key, url
"""

import asyncio
import logging
import os
from typing import Any, Dict, Optional

from services.vault_client import VaultAuthError, VaultClient, VaultSecretError

logger = logging.getLogger(__name__)

# ── Vault connection config ──────────────────────────────────────────────
_VAULT_MOUNT = os.getenv("VAULT_MOUNT", "secret")

# How often the background task re-fetches secrets (seconds).
# Set to half the token TTL to ensure we never expire between renewals.
_RENEWAL_INTERVAL = int(os.getenv("VAULT_LEASE_RENEWAL_SECONDS", "3600"))

# All KV-v2 paths relative to the mount that we must fetch at startup.
_SECRET_PATHS = [
    "aml/postgres",
    "aml/neo4j",
    "aml/elasticsearch",
    "aml/jwt",
    "aml/fincen",
    "aml/watchlists",
    "aml/supabase",
]


# ── SecretStore ───────────────────────────────────────────────────────────

class _SecretStore:
    """
    In-memory cache of flattened secrets fetched from Vault.

    Keys are ``{path_segment}.{field}``, e.g. ``postgres.password``.
    Values are always strings.

    Thread-safe for reads; writes only occur during startup and the
    periodic background renewal (asyncio event loop — no concurrent writes).
    """

    def __init__(self) -> None:
        self._store: Dict[str, str] = {}
        self._loaded: bool = False

    def _populate(self, path: str, data: Dict[str, Any]) -> None:
        """Store all fields from a secret path under a namespaced key."""
        segment = path.split("/")[-1]  # "aml/postgres" → "postgres"
        for field, value in data.items():
            key = f"{segment}.{field}"
            self._store[key] = str(value)
        logger.debug(f"SecretStore: populated '{path}' ({len(data)} fields).")

    def get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """
        Return the secret value for ``key``.

        Key format: ``{secret_name}.{field}`` (e.g. ``postgres.password``).
        Returns ``default`` if the key is not present (Vault not loaded or
        path not found).
        """
        return self._store.get(key, default)

    def require(self, key: str) -> str:
        """Like ``get()`` but raises ``KeyError`` if the key is missing."""
        value = self._store.get(key)
        if value is None:
            raise KeyError(
                f"SecretStore: required secret '{key}' is not set. "
                "Ensure Vault is reachable and the secret path is seeded."
            )
        return value

    @property
    def is_loaded(self) -> bool:
        return self._loaded

    def mark_loaded(self) -> None:
        self._loaded = True

    def clear_and_repopulate(self, path: str, data: Dict[str, Any]) -> None:
        """Used by the renewal task to update individual paths atomically."""
        segment = path.split("/")[-1]
        # Remove old keys for this path, then re-insert fresh values
        old_keys = [k for k in self._store if k.startswith(f"{segment}.")]
        for k in old_keys:
            del self._store[k]
        self._populate(path, data)


# Module-level singleton — imported by all callers
SecretStore = _SecretStore()


# ── Loader ────────────────────────────────────────────────────────────────

class VaultSecretsLoader:
    """
    Bootstraps secret loading from Vault at application startup.

    Typical usage in FastAPI lifespan::

        await VaultSecretsLoader.bootstrap()
    """

    _client: Optional[VaultClient] = None

    @classmethod
    async def bootstrap(cls) -> None:
        """
        Authenticate to Vault, fetch all required secrets, and schedule
        the background renewal task.

        If ``VAULT_ADDR`` is not set, silently returns — callers fall back
        to environment variables (dev mode).

        Raises ``RuntimeError`` if Vault is configured but unreachable or
        authentication fails.
        """
        vault_addr = os.getenv("VAULT_ADDR", "").strip()

        if not vault_addr:
            logger.info(
                "VaultSecretsLoader: VAULT_ADDR not set — running in env-var fallback mode. "
                "Set VAULT_ADDR, VAULT_ROLE_ID, VAULT_SECRET_ID for production."
            )
            return

        logger.info(f"VaultSecretsLoader: connecting to Vault at {vault_addr} ...")
        client = VaultClient(addr=vault_addr, mount=_VAULT_MOUNT)

        # ── Authenticate ─────────────────────────────────────────────────
        dev_token = os.getenv("VAULT_DEV_TOKEN", "").strip()
        if dev_token:
            # Dev convenience — never for production
            await client.authenticate_token(dev_token)
            logger.warning(
                "VaultSecretsLoader: using VAULT_DEV_TOKEN — NOT suitable for production."
            )
        else:
            role_id = os.getenv("VAULT_ROLE_ID", "").strip()
            secret_id = os.getenv("VAULT_SECRET_ID", "").strip()
            if not role_id or not secret_id:
                raise RuntimeError(
                    "VaultSecretsLoader: VAULT_ADDR is set but VAULT_ROLE_ID / "
                    "VAULT_SECRET_ID are missing. Cannot authenticate to Vault."
                )
            try:
                await client.authenticate_approle(role_id=role_id, secret_id=secret_id)
            except VaultAuthError as exc:
                raise RuntimeError(
                    f"VaultSecretsLoader: Vault authentication failed — {exc}"
                ) from exc

        cls._client = client

        # ── Fetch all secret paths ───────────────────────────────────────
        await cls._fetch_all(client)
        SecretStore.mark_loaded()
        logger.info(
            f"VaultSecretsLoader: {len(_SECRET_PATHS)} secret paths loaded successfully."
        )

        # ── Schedule background renewal ──────────────────────────────────
        asyncio.create_task(cls._renewal_loop(), name="vault-secret-renewal")
        logger.info(
            f"VaultSecretsLoader: background renewal scheduled "
            f"(interval: {_RENEWAL_INTERVAL}s)."
        )

    @classmethod
    async def _fetch_all(cls, client: VaultClient) -> None:
        """Fetch every secret path and populate SecretStore."""
        for path in _SECRET_PATHS:
            try:
                data = await client.read_secret(path)
                SecretStore._populate(path, data)
            except VaultSecretError as exc:
                # Non-fatal: log and continue — some paths may not be seeded yet
                logger.warning(
                    f"VaultSecretsLoader: could not read '{path}' — {exc}. "
                    "Falling back to env vars for that secret group."
                )

    @classmethod
    async def _renewal_loop(cls) -> None:
        """
        Background asyncio task that periodically re-fetches all secrets
        and renews the Vault token to prevent expiry.

        Errors are non-fatal — the existing cached values remain valid
        until the next successful renewal.
        """
        while True:
            await asyncio.sleep(_RENEWAL_INTERVAL)

            if cls._client is None:
                return

            logger.info("VaultSecretsLoader: running scheduled secret renewal...")
            try:
                await cls._client.renew_token()
                await cls._fetch_all(cls._client)
                logger.info("VaultSecretsLoader: secret renewal complete.")
            except Exception as exc:  # noqa: BLE001
                logger.error(
                    f"VaultSecretsLoader: renewal failed ({exc}). "
                    "Cached values remain active until next cycle."
                )
