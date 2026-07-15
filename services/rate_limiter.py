from fastapi import Request, HTTPException, status
import logging
from database.redis_db import get_async_redis_client

logger = logging.getLogger(__name__)

class RateLimiter:
    def __init__(self, limit: int, window: int):
        self.limit = limit
        self.window = window

    async def __call__(self, request: Request):
        try:
            redis = await get_async_redis_client()
            if redis is None:
                return

            client_ip = request.client.host if request.client else "unknown"
            key = f"rate_limit:{request.url.path}:{client_ip}"
            
            # Redis transaction/pipeline to increment and set expire atomically
            pipe = redis.pipeline()
            await pipe.incr(key)
            await pipe.expire(key, self.window, nx=True)
            results = await pipe.execute()
            
            current_requests = results[0]
            if current_requests > self.limit:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Too many requests. Please try again later.",
                    headers={"Retry-After": str(self.window)}
                )
        except HTTPException:
            raise
        except Exception as e:
            # Resilient design: fail-open if Redis is down or has connection issues
            logger.warning(f"Rate limiter failed to communicate with Redis: {e}")
