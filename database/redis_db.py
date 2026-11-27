"""
Redis Connection Manager (Sync, Async & Dedicated Pub/Sub)
==========================================================
Fixes P0-02: Uses redis-py 5.0.x-compatible TLS arguments (`ssl_ca_certs`,
`ssl_certfile`, `ssl_keyfile`, `ssl_cert_reqs`) instead of `ssl_context`
(which raises `TypeError` on `redis==5.0.1`).
Also enforces bounded `max_connections`, `health_check_interval`, dynamic
Vault password resolution, asyncio.Lock initialization safety, and clean
dual-client shutdown.
"""

import asyncio
import logging
import os
import redis
import redis.asyncio as async_redis

from config import (
    REDIS_CACHE_DB,
    REDIS_CACHE_HOST,
    REDIS_CACHE_PASSWORD,
    REDIS_CACHE_PORT,
    REDIS_HOST,
    REDIS_PORT,
    settings,
)
from services.secrets_manager import get_redis_password
from services.tls_manager import get_ssl_context, get_tls_cert_paths

logger = logging.getLogger(__name__)

_redis_client = None
_async_redis_client = None
_async_redis_loop = None
_async_redis_lock: asyncio.Lock | None = None
_async_redis_lock_loop = None

_async_cache_redis_client = None
_async_cache_redis_loop = None
_async_cache_redis_lock: asyncio.Lock | None = None
_async_cache_redis_lock_loop = None


def _get_cache_init_lock(current_loop) -> asyncio.Lock:
    global _async_cache_redis_lock, _async_cache_redis_lock_loop
    if _async_cache_redis_lock is None or _async_cache_redis_lock_loop is not current_loop:
        _async_cache_redis_lock = asyncio.Lock()
        _async_cache_redis_lock_loop = current_loop
    return _async_cache_redis_lock


def _get_init_lock(current_loop) -> asyncio.Lock:
    global _async_redis_lock, _async_redis_lock_loop
    if _async_redis_lock is None or _async_redis_lock_loop is not current_loop:
        _async_redis_lock = asyncio.Lock()
        _async_redis_lock_loop = current_loop
    return _async_redis_lock


def _build_redis_tls_kwargs() -> dict:
    """
    Validates TLS via `get_ssl_context()` (preserving strict mTLS fail-closed semantics)
    and returns redis==5.0.1-compatible SSL keyword arguments (fixes P0-02).
    """
    ssl_ctx = get_ssl_context()
    if ssl_ctx is None:
        return {}

    ca_path, cert_path, key_path = get_tls_cert_paths()
    tls_kwargs: dict = {
        "ssl": True,
        "ssl_cert_reqs": "required",
        "ssl_check_hostname": True,
    }
    if os.path.exists(ca_path):
        tls_kwargs["ssl_ca_certs"] = ca_path
    if os.path.exists(cert_path) and os.path.exists(key_path):
        tls_kwargs["ssl_certfile"] = cert_path
        tls_kwargs["ssl_keyfile"] = key_path
    return tls_kwargs


def get_redis_client():
    global _redis_client
    if _redis_client is None:
        try:
            pwd = get_redis_password()
            kwargs = {
                "host": REDIS_HOST,
                "port": REDIS_PORT,
                "decode_responses": True,
                "socket_connect_timeout": 1.0,
                "socket_timeout": 1.0,
                "max_connections": 50,
                "health_check_interval": 30,
            }
            if pwd:
                kwargs["password"] = pwd
            kwargs.update(_build_redis_tls_kwargs())

            _redis_client = redis.Redis(**kwargs)
            _redis_client.ping()
            logger.info("Redis connection established.")
        except Exception as e:
            _redis_client = None
            logger.error("Failed to connect to Redis: %s", e)
            raise e
    return _redis_client


async def get_async_redis_client():
    global _async_redis_client, _async_redis_loop
    current_loop = asyncio.get_running_loop()
    if _async_redis_client is not None and (
        _async_redis_loop is not current_loop or _async_redis_loop.is_closed()
    ):
        _async_redis_client = None
        _async_redis_loop = None

    if _async_redis_client is not None:
        return _async_redis_client

    async with _get_init_lock(current_loop):
        if _async_redis_client is not None and _async_redis_loop is current_loop:
            return _async_redis_client
        try:
            pwd = get_redis_password()
            kwargs = {
                "host": REDIS_HOST,
                "port": REDIS_PORT,
                "decode_responses": True,
                "socket_connect_timeout": 1.0,
                "socket_timeout": 1.0,
                "max_connections": 50,
                "health_check_interval": 30,
            }
            if pwd:
                kwargs["password"] = pwd
            kwargs.update(_build_redis_tls_kwargs())

            _async_redis_client = async_redis.Redis(**kwargs)
            await _async_redis_client.ping()
            _async_redis_loop = current_loop
            logger.info("Async Redis connection established.")
        except Exception as e:
            _async_redis_client = None
            _async_redis_loop = None
            logger.error("Failed to connect to Async Redis: %s", e)
            raise e
    return _async_redis_client


async def get_async_redis_pubsub_client():
    """
    Dedicated Async Redis client for long-lived Pub/Sub subscriptions WITHOUT socket_timeout=1.0
    so idle Pub/Sub channels never experience periodic timeout disconnects.
    """
    pwd = get_redis_password()
    kwargs = {
        "host": REDIS_HOST,
        "port": REDIS_PORT,
        "decode_responses": True,
        "socket_connect_timeout": 2.0,
        "socket_timeout": None,
        "socket_keepalive": True,
        "health_check_interval": 30,
    }
    if pwd:
        kwargs["password"] = pwd
    kwargs.update(_build_redis_tls_kwargs())
    client = async_redis.Redis(**kwargs)
    await client.ping()
    return client


async def get_async_cache_redis_client():
    """
    Dedicated Fail-Open Async Redis client for volatile read caches (`allkeys-lfu`).
    Physically separated from State Redis (`noeviction`) in Docker Compose / K8s via
    `REDIS_CACHE_HOST:REDIS_CACHE_PORT`; falls back cleanly in single-node dev to
    `REDIS_HOST:REDIS_PORT` DB `REDIS_CACHE_DB` (default 1) while strictly enforcing
    aggressive <= 200ms timeouts and `retry_on_timeout=False`.
    Returns `None` on failure so read endpoints fail open to PostgreSQL.
    """
    global _async_cache_redis_client, _async_cache_redis_loop
    current_loop = asyncio.get_running_loop()
    if _async_cache_redis_client is not None and (
        _async_cache_redis_loop is not current_loop or _async_cache_redis_loop.is_closed()
    ):
        _async_cache_redis_client = None
        _async_cache_redis_loop = None

    if _async_cache_redis_client is not None:
        return _async_cache_redis_client

    async with _get_cache_init_lock(current_loop):
        if _async_cache_redis_client is not None and _async_cache_redis_loop is current_loop:
            return _async_cache_redis_client
        try:
            cache_host = (os.getenv("REDIS_CACHE_HOST") or REDIS_CACHE_HOST or "").strip()
            if cache_host:
                host = cache_host
                port = int(os.getenv("REDIS_CACHE_PORT") or REDIS_CACHE_PORT)
                db_idx = 0
                pwd = (os.getenv("REDIS_CACHE_PASSWORD") or REDIS_CACHE_PASSWORD or get_redis_password())
            else:
                # Single-node local dev fallback: logical DB isolation + strict cache timeouts
                host = REDIS_HOST
                port = REDIS_PORT
                db_idx = int(getattr(settings, "redis_cache_db", REDIS_CACHE_DB))
                pwd = get_redis_password()

            connect_timeout = min(
                0.25,
                max(0.05, float(getattr(settings, "redis_cache_connect_timeout_seconds", 0.15))),
            )
            socket_timeout = min(
                0.25,
                max(0.05, float(getattr(settings, "redis_cache_socket_timeout_seconds", 0.20))),
            )
            kwargs = {
                "host": host,
                "port": port,
                "db": db_idx,
                "decode_responses": True,
                "socket_connect_timeout": connect_timeout,
                "socket_timeout": socket_timeout,
                "retry_on_timeout": False,
                "max_connections": 50,
                "health_check_interval": 30,
            }
            if pwd:
                kwargs["password"] = pwd
            kwargs.update(_build_redis_tls_kwargs())

            client = async_redis.Redis(**kwargs)
            await asyncio.wait_for(client.ping(), timeout=max(connect_timeout, socket_timeout) + 0.1)
            _async_cache_redis_client = client
            _async_cache_redis_loop = current_loop
            logger.info(
                "Async Cache Redis established (%s:%s db=%s timeout=%.0fms).",
                host,
                port,
                db_idx,
                socket_timeout * 1000.0,
            )
        except Exception as e:
            _async_cache_redis_client = None
            _async_cache_redis_loop = None
            logger.warning("Async Cache Redis unavailable (failing open to DB): %s", e)
            return None
    return _async_cache_redis_client


async def close_redis_client():
    """Cleanly closes state, cache, and sync Redis connections without reconnecting."""
    global _redis_client, _async_redis_client, _async_redis_loop
    global _async_cache_redis_client, _async_cache_redis_loop
    for client_attr in ("_async_redis_client", "_async_cache_redis_client"):
        cli = globals().get(client_attr)
        if cli is not None:
            try:
                await cli.aclose()
            except Exception:
                try:
                    await cli.close()
                except Exception:
                    pass
    _async_redis_client = None
    _async_redis_loop = None
    _async_cache_redis_client = None
    _async_cache_redis_loop = None
    if _redis_client is not None:
        try:
            _redis_client.close()
        except Exception:
            pass
        _redis_client = None
