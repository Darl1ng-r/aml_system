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

from config import REDIS_HOST, REDIS_PORT
from services.secrets_manager import get_redis_password
from services.tls_manager import get_ssl_context, get_tls_cert_paths

logger = logging.getLogger(__name__)

_redis_client = None
_async_redis_client = None
_async_redis_loop = None
_async_redis_lock: asyncio.Lock | None = None
_async_redis_lock_loop = None


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


async def close_redis_client():
    """Cleanly closes both sync and async Redis connections without reconnecting."""
    global _redis_client, _async_redis_client, _async_redis_loop
    if _async_redis_client is not None:
        try:
            await _async_redis_client.aclose()
        except Exception:
            try:
                await _async_redis_client.close()
            except Exception:
                pass
        _async_redis_client = None
        _async_redis_loop = None
    if _redis_client is not None:
        try:
            _redis_client.close()
        except Exception:
            pass
        _redis_client = None
