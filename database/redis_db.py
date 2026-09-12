import redis
import redis.asyncio as async_redis
import logging
import os
from config import REDIS_HOST, REDIS_PORT, REDIS_PASSWORD
from services.tls_manager import get_ssl_context

logger = logging.getLogger(__name__)

_redis_client = None
_async_redis_client = None

def get_redis_client():
    global _redis_client
    if _redis_client is None:
        try:
            ssl_ctx = get_ssl_context()
            pwd = REDIS_PASSWORD or os.getenv("REDIS_PASSWORD", None)
            kwargs = {
                "host": REDIS_HOST,
                "port": REDIS_PORT,
                "decode_responses": True,
                "socket_connect_timeout": 1.0,
                "socket_timeout": 1.0
            }
            if pwd:
                kwargs["password"] = pwd
            if ssl_ctx:
                kwargs["ssl"] = True
                kwargs["ssl_context"] = ssl_ctx

            _redis_client = redis.Redis(**kwargs)
            # Test connection
            _redis_client.ping()
            logger.info("Redis connection established.")
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {e}")
            raise e
    return _redis_client

async def get_async_redis_client():
    global _async_redis_client
    if _async_redis_client is None:
        try:
            ssl_ctx = get_ssl_context()
            pwd = REDIS_PASSWORD or os.getenv("REDIS_PASSWORD", None)
            kwargs = {
                "host": REDIS_HOST,
                "port": REDIS_PORT,
                "decode_responses": True,
                "socket_connect_timeout": 1.0,
                "socket_timeout": 1.0
            }
            if pwd:
                kwargs["password"] = pwd
            if ssl_ctx:
                kwargs["ssl"] = True
                kwargs["ssl_context"] = ssl_ctx

            _async_redis_client = async_redis.Redis(**kwargs)
            await _async_redis_client.ping()
            logger.info("Async Redis connection established.")
        except Exception as e:
            _async_redis_client = None
            logger.error(f"Failed to connect to Async Redis: {e}")
            raise e
    return _async_redis_client

