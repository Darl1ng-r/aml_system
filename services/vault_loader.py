"""
Vault Secrets Loader & SecretStore
====================================
Application-level bootstrap that fetches all required secrets from
HashiCorp Vault KV-v2 at startup, caches them in an in-memory ``SecretStore``,
and schedules a jittered background renewal task so long-running API pods and
workers automatically pick up rotated credentials (including RS256 hot-reload).

Canonical KV-v2 secret layout (mount: ``secret``)
-------------------------------------------------
  secret/data/aml/postgres       → password, aml_app_password, user, host, port, db
  secret/data/aml/redis          → password
  secret/data/aml/neo4j          → password, user, uri
  secret/data/aml/elasticsearch  → password, user
  secret/data/aml/jwt            → rsa_private_key, previous_public_keys, secret_keys, algorithm
  secret/data/aml/encryption     → pii_key
  secret/data/aml/observability  → metrics_secret
  secret/data/aml/gateway        → internal_secret
  secret/data/aml/fincen         → api_key, file_password, transmitter_tin, efiling_url, sftp_password
  secret/data/aml/watchlists     → worldcheck_api_key, worldcheck_api_secret, dowjones_api_key
  secret/data/aml/supabase       → key, url
"""

import asyncio
import logging
import os
import random
from typing import Any, Dict, Optional

from services.vault_client import VaultAuthError, VaultClient, VaultSecretError

logger = logging.getLogger(__name__)

_VAULT_MOUNT = os.getenv("VAULT_MOUNT", "secret")
_RENEWAL_INTERVAL = int(os.getenv("VAULT_LEASE_RENEWAL_SECONDS", "3600"))
_background_tasks: set[asyncio.Task] = set()

# Canonical KV-v2 secret schema shared with ESO manifests & bootstrap script (P1-10)
VAULT_SECRET_PATHS = (
    "aml/postgres",
    "aml/redis",
    "aml/neo4j",
    "aml/elasticsearch",
    "aml/jwt",
    "aml/encryption",
    "aml/observability",
    "aml/gateway",
    "aml/fincen",
    "aml/watchlists",
    "aml/supabase",
)
_SECRET_PATHS = list(VAULT_SECRET_PATHS)

try:
    from observability.prometheus import _get_or_create_counter

    VAULT_RENEWAL_FAILURES = _get_or_create_counter(
        "aml_vault_renewal_failures_total",
        "Total failed HashiCorp Vault secret renewal cycles",
        [],
    )
except Exception:  # pragma: no cover
    VAULT_RENEWAL_FAILURES = None


class _SecretStore:
    """In-memory cache of flattened secrets fetched from Vault."""

    def __init__(self) -> None:
        self._store: Dict[str, str] = {}
        self._loaded: bool = False

    def _populate(self, path: str, data: Dict[str, Any]) -> None:
        segment = path.split("/")[-1]
        for field, value in data.items():
            key = f"{segment}.{field}"
            self._store[key] = str(value)
        logger.debug("SecretStore: populated '%s' (%d fields).", path, len(data))

    def get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        return self._store.get(key, default)

    def require(self, key: str) -> str:
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
        segment = path.split("/")[-1]
        old_keys = [k for k in self._store if k.startswith(f"{segment}.")]
        for k in old_keys:
            del self._store[k]
        self._populate(path, data)


SecretStore = _SecretStore()


class VaultSecretsLoader:
    """Bootstraps secret loading from Vault at application/worker startup."""

    _client: Optional[VaultClient] = None
    _renewal_task: Optional[asyncio.Task] = None

    @classmethod
    async def bootstrap(cls) -> None:
        vault_addr = os.getenv("VAULT_ADDR", "").strip()
        if not vault_addr:
            logger.info(
                "VaultSecretsLoader: VAULT_ADDR not set — running in env-var fallback mode. "
                "Set VAULT_ADDR, VAULT_ROLE_ID, VAULT_SECRET_ID for production."
            )
            return

        logger.info("VaultSecretsLoader: connecting to Vault at %s ...", vault_addr)
        mount = os.getenv("VAULT_MOUNT", _VAULT_MOUNT)
        client = VaultClient(addr=vault_addr, mount=mount)

        dev_token = os.getenv("VAULT_DEV_TOKEN", "").strip()
        if dev_token:
            from config import settings
            env_val = os.getenv("ENVIRONMENT", "").strip().lower()
            if getattr(settings, "is_hardened", settings.is_production) or env_val in {"production", "prod", "staging"}:
                await client.aclose()
                raise RuntimeError(
                    "CRITICAL SECURITY VIOLATION: VAULT_DEV_TOKEN is strictly prohibited in production/staging. "
                    "Use AppRole (VAULT_ROLE_ID / VAULT_SECRET_ID) instead."
                )
            await client.authenticate_token(dev_token)
            logger.warning("VaultSecretsLoader: using VAULT_DEV_TOKEN — NOT suitable for production.")
        else:
            role_id = os.getenv("VAULT_ROLE_ID", "").strip()
            secret_id = os.getenv("VAULT_SECRET_ID", "").strip()
            if not role_id or not secret_id:
                await client.aclose()
                raise RuntimeError(
                    "VaultSecretsLoader: VAULT_ADDR is set but VAULT_ROLE_ID / "
                    "VAULT_SECRET_ID are missing. Cannot authenticate to Vault."
                )
            try:
                await client.authenticate_approle(role_id=role_id, secret_id=secret_id)
            except VaultAuthError as exc:
                await client.aclose()
                raise RuntimeError(f"VaultSecretsLoader: Vault authentication failed — {exc}") from exc

        cls._client = client
        await cls._fetch_all(client)
        SecretStore.mark_loaded()
        logger.info("VaultSecretsLoader: %d secret paths checked/loaded.", len(_SECRET_PATHS))

        task = asyncio.create_task(cls._renewal_loop(), name="vault-secret-renewal")
        _background_tasks.add(task)
        task.add_done_callback(_background_tasks.discard)
        cls._renewal_task = task
        logger.info("VaultSecretsLoader: background renewal scheduled (base interval: %ss with jitter).", _RENEWAL_INTERVAL)

    @classmethod
    async def _fetch_all(cls, client: VaultClient) -> None:
        jwt_updated = False
        for path in _SECRET_PATHS:
            try:
                data = await client.read_secret(path)
                SecretStore.clear_and_repopulate(path, data)
                if path == "aml/jwt":
                    jwt_updated = True
            except VaultSecretError as exc:
                logger.warning(
                    "VaultSecretsLoader: could not read '%s' — %s. Falling back to env vars for that group.",
                    path,
                    exc,
                )

        if jwt_updated:
            try:
                from services.secrets_manager import invalidate_rsa_key_cache
                invalidate_rsa_key_cache()
            except Exception:
                pass

    @classmethod
    async def _renewal_loop(cls) -> None:
        while True:
            # Add +/- 10% jitter to avoid synchronized renewal bursts across pod fleet (P2-04)
            jitter = random.uniform(-0.1, 0.1) * _RENEWAL_INTERVAL
            await asyncio.sleep(max(30.0, _RENEWAL_INTERVAL + jitter))

            if cls._client is None:
                return

            logger.info("VaultSecretsLoader: running scheduled secret renewal...")
            try:
                await cls._client.renew_token()
                await cls._fetch_all(cls._client)
                logger.info("VaultSecretsLoader: secret renewal complete.")
            except Exception:
                if VAULT_RENEWAL_FAILURES is not None:
                    try:
                        VAULT_RENEWAL_FAILURES.inc()
                    except Exception:
                        pass
                logger.exception("VaultSecretsLoader: renewal failed. Cached values remain active until next cycle.")

    @classmethod
    async def shutdown(cls) -> None:
        if cls._renewal_task is not None and not cls._renewal_task.done():
            cls._renewal_task.cancel()
            try:
                await cls._renewal_task
            except asyncio.CancelledError:
                pass
        if cls._client is not None:
            await cls._client.aclose()
        cls._renewal_task = None
        cls._client = None
