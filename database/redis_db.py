import redis
import logging
from config import REDIS_HOST, REDIS_PORT

logger = logging.getLogger(__name__)

_redis_client = None

def get_redis_client():
    global _redis_client
    if _redis_client is None:
        try:
            _redis_client = redis.Redis(
                host=REDIS_HOST,
                port=REDIS_PORT,
                decode_responses=True
            )
            # Test connection
            _redis_client.ping()
            logger.info("Redis connection established.")
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {e}")
            raise e
    return _redis_client
