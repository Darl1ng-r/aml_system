import pytest
from unittest.mock import patch, MagicMock, AsyncMock
from fastapi import Request, HTTPException, status
from services.rate_limiter import RateLimiter


@pytest.mark.anyio
async def test_rate_limiter_sliding_window_allowed():
    """Verify rate limiter allows requests when count is below limit."""
    limiter = RateLimiter(limit=5, window=60)
    request = MagicMock(spec=Request)
    request.client.host = "192.168.1.100"
    request.url.path = "/api/v1/alerts"

    mock_pipe = MagicMock()
    mock_pipe.execute = AsyncMock(return_value=[0, True, 3, True])

    mock_redis = MagicMock()
    mock_redis.pipeline.return_value = mock_pipe

    with patch("services.rate_limiter.get_async_redis_client", AsyncMock(return_value=mock_redis)):
        # Should not raise any exception
        await limiter(request)

        mock_pipe.zremrangebyscore.assert_called_once()
        mock_pipe.zadd.assert_called_once()
        mock_pipe.zcard.assert_called_once()
        mock_pipe.pexpire.assert_called_once()


@pytest.mark.anyio
async def test_rate_limiter_sliding_window_exceeded_raises_429():
    """Verify rate limiter raises HTTP 429 when sliding window zcard count exceeds limit."""
    limiter = RateLimiter(limit=5, window=60)
    request = MagicMock(spec=Request)
    request.client.host = "192.168.1.100"
    request.url.path = "/api/v1/alerts"

    mock_pipe = MagicMock()
    # 6th request exceeds limit of 5
    mock_pipe.execute = AsyncMock(return_value=[0, True, 6, True])

    mock_redis = MagicMock()
    mock_redis.pipeline.return_value = mock_pipe

    with patch("services.rate_limiter.get_async_redis_client", AsyncMock(return_value=mock_redis)):
        with pytest.raises(HTTPException) as exc_info:
            await limiter(request)

        assert exc_info.value.status_code == status.HTTP_429_TOO_MANY_REQUESTS
        assert exc_info.value.headers["Retry-After"] == "60"


@pytest.mark.anyio
async def test_rate_limiter_redis_failure_fails_open():
    """Verify rate limiter fails open without raising exception when Redis errors occur."""
    limiter = RateLimiter(limit=5, window=60)
    request = MagicMock(spec=Request)
    request.client.host = "192.168.1.100"
    request.url.path = "/api/v1/alerts"

    with patch("services.rate_limiter.get_async_redis_client", AsyncMock(side_effect=Exception("Redis connection refused"))):
        # Should not raise exception (fail-open)
        await limiter(request)
