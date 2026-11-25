"""
Shared Outbound HTTP Client Pool, Circuit Breakers & Backoff Utilities
======================================================================
Centralizes outbound HTTP connection pooling, split connect/read/write/pool
timeouts, per-host/endpoint circuit breakers, full-jitter exponential backoff,
Prometheus telemetry, and safe lifecycle cleanup.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
import os
import random
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Deque, Dict, Optional
from urllib.parse import urlparse

import httpx

_ORIGINAL_ASYNC_CLIENT = httpx.AsyncClient
_ORIGINAL_ASYNC_METHODS = {
    "GET": httpx.AsyncClient.get,
    "POST": httpx.AsyncClient.post,
    "PUT": httpx.AsyncClient.put,
    "DELETE": httpx.AsyncClient.delete,
    "PATCH": httpx.AsyncClient.patch,
    "HEAD": httpx.AsyncClient.head,
}

logger = logging.getLogger(__name__)

# ── Prometheus Outbound Telemetry (graceful fallback if unavailable) ─────────
try:
    from observability.prometheus import _get_or_create_counter, _get_or_create_gauge, _get_or_create_histogram

    OUTBOUND_REQUEST_DURATION = _get_or_create_histogram(
        "aml_outbound_request_duration_seconds",
        "Duration of outbound HTTP requests by logical target and status",
        ["target", "status"],
    )
    CIRCUIT_BREAKER_STATE_GAUGE = _get_or_create_gauge(
        "aml_outbound_circuit_breaker_state",
        "Circuit breaker state per target (0=closed, 1=half_open, 2=open)",
        ["target"],
    )
    OUTBOUND_RETRY_COUNTER = _get_or_create_counter(
        "aml_outbound_retries_total",
        "Total outbound HTTP retries by target",
        ["target"],
    )
except Exception:  # pragma: no cover
    OUTBOUND_REQUEST_DURATION = None
    CIRCUIT_BREAKER_STATE_GAUGE = None
    OUTBOUND_RETRY_COUNTER = None


DEFAULT_HTTP_TIMEOUT = httpx.Timeout(connect=2.0, read=10.0, write=10.0, pool=2.0)
DEFAULT_HTTP_LIMITS = httpx.Limits(max_connections=100, max_keepalive_connections=20, keepalive_expiry=30.0)


def full_jitter_backoff(base: float, attempt: int, cap: float = 60.0) -> float:
    """
    AWS Full Jitter exponential backoff: Uniform(0, min(cap, base * 2^attempt)).
    Eliminates thundering-herd synchronized retries after dependency recovery.
    """
    ceiling = min(cap, max(0.01, base) * (2 ** max(0, int(attempt))))
    return random.uniform(0.0, ceiling)


class CircuitOpenError(RuntimeError):
    """Raised when an outbound target's circuit breaker is open."""

    def __init__(self, target: str, retry_after: float) -> None:
        self.target = target
        self.retry_after = max(0.0, retry_after)
        super().__init__(f"Circuit breaker open for target '{target}' (retry after {self.retry_after:.1f}s)")


@dataclass
class CircuitBreaker:
    """Lightweight sliding-window async circuit breaker per outbound target."""

    target: str
    failure_threshold: int = 5
    window_seconds: float = 30.0
    recovery_timeout: float = 30.0
    _state: str = field(default="closed", init=False)
    _failures: Deque[float] = field(default_factory=deque, init=False)
    _opened_at: float = field(default=0.0, init=False)
    _half_open_probe_in_flight: bool = field(default=False, init=False)

    def _emit_state(self) -> None:
        if CIRCUIT_BREAKER_STATE_GAUGE is not None:
            val = {"closed": 0.0, "half_open": 1.0, "open": 2.0}.get(self._state, 0.0)
            try:
                CIRCUIT_BREAKER_STATE_GAUGE.labels(target=self.target).set(val)
            except Exception:
                pass

    @property
    def state(self) -> str:
        now = time.monotonic()
        if self._state == "open" and (now - self._opened_at) >= self.recovery_timeout:
            self._state = "half_open"
            self._half_open_probe_in_flight = False
            self._emit_state()
        return self._state

    def allow_request(self) -> bool:
        st = self.state
        if st == "closed":
            return True
        if st == "half_open":
            if not self._half_open_probe_in_flight:
                self._half_open_probe_in_flight = True
                return True
            return False
        return False

    def retry_after_seconds(self) -> float:
        if self._state != "open":
            return 0.0
        return max(0.0, self.recovery_timeout - (time.monotonic() - self._opened_at))

    def record_success(self) -> None:
        self._failures.clear()
        self._half_open_probe_in_flight = False
        if self._state != "closed":
            self._state = "closed"
            logger.info("Circuit breaker closed for target '%s' after successful probe.", self.target)
        self._emit_state()

    def record_failure(self) -> None:
        now = time.monotonic()
        self._half_open_probe_in_flight = False
        if self._state == "half_open":
            self._state = "open"
            self._opened_at = now
            logger.warning("Circuit breaker re-opened for target '%s' after failed half-open probe.", self.target)
            self._emit_state()
            return

        cutoff = now - self.window_seconds
        while self._failures and self._failures[0] < cutoff:
            self._failures.popleft()
        self._failures.append(now)

        if len(self._failures) >= self.failure_threshold:
            self._state = "open"
            self._opened_at = now
            logger.warning(
                "Circuit breaker tripped OPEN for target '%s' (%d failures in %.0fs).",
                self.target,
                len(self._failures),
                self.window_seconds,
            )
        self._emit_state()


_breakers: Dict[str, CircuitBreaker] = {}
_MAX_BREAKERS = 512


def get_circuit_breaker(
    target: str,
    *,
    failure_threshold: int = 5,
    window_seconds: float = 30.0,
    recovery_timeout: float = 30.0,
) -> CircuitBreaker:
    """Returns or creates a bounded per-target CircuitBreaker instance."""
    key = (target or "unknown").strip().lower()[:128]
    cb = _breakers.get(key)
    if cb is None:
        if len(_breakers) >= _MAX_BREAKERS:
            # Evict oldest entry to prevent unbounded cardinality from arbitrary tenant URLs
            oldest = next(iter(_breakers))
            _breakers.pop(oldest, None)
        cb = CircuitBreaker(
            target=key,
            failure_threshold=failure_threshold,
            window_seconds=window_seconds,
            recovery_timeout=recovery_timeout,
        )
        _breakers[key] = cb
    return cb


def reset_all_circuit_breakers() -> None:
    """Clears all circuit breaker state (intended for tests)."""
    _breakers.clear()


# ── Shared Pooled httpx.AsyncClient ──────────────────────────────────────────

_shared_client: Optional[httpx.AsyncClient] = None
_shared_client_loop_id: Optional[int] = None


def get_http_client() -> httpx.AsyncClient:
    """
    Returns an application-scoped pooled httpx.AsyncClient bound to the current
    running event loop, with split timeouts and follow_redirects=False by default.
    """
    global _shared_client, _shared_client_loop_id
    try:
        current_loop_id = id(asyncio.get_running_loop())
    except RuntimeError:
        current_loop_id = None

    if (
        _shared_client is None
        or _shared_client.is_closed
        or (_shared_client_loop_id is not None and current_loop_id is not None and _shared_client_loop_id != current_loop_id)
    ):
        _shared_client = httpx.AsyncClient(
            timeout=DEFAULT_HTTP_TIMEOUT,
            limits=DEFAULT_HTTP_LIMITS,
            follow_redirects=False,
        )
        _shared_client_loop_id = current_loop_id
    return _shared_client


async def close_http_client() -> None:
    """Closes the shared pooled httpx.AsyncClient cleanly on application shutdown."""
    global _shared_client, _shared_client_loop_id
    if _shared_client is not None and not _shared_client.is_closed:
        try:
            await _shared_client.aclose()
        except Exception as exc:
            logger.debug("Error closing shared HTTP client: %s", exc)
    _shared_client = None
    _shared_client_loop_id = None


def _inject_trace_headers(headers: Optional[Dict[str, str]]) -> Dict[str, str]:
    merged = dict(headers or {})
    try:
        from opentelemetry.propagate import inject
        inject(merged)
    except Exception:
        pass
    return merged


def is_outbound_egress_allowed(target: str) -> bool:
    """
    Central kill-switch for non-production outbound egress.
    Set OUTBOUND_EGRESS_ENABLED=false in dev/staging/test to block external webhooks/APIs.
    """
    from config import settings

    if settings.is_production:
        return True
    env_override = os.getenv("OUTBOUND_EGRESS_ENABLED")
    if env_override is not None:
        return env_override.strip().lower() not in {"0", "false", "no", "off"}
    return bool(getattr(settings, "outbound_egress_enabled", True))


def target_from_url(url: str, prefix: str = "http") -> str:
    try:
        host = urlparse(url).hostname or "unknown"
        return f"{prefix}:{host}"
    except Exception:
        return f"{prefix}:unknown"


def is_httpx_patched(method: Optional[str] = None) -> bool:
    """Returns True when unit tests have monkeypatched httpx.AsyncClient or one of its verb methods."""
    if httpx.AsyncClient is not _ORIGINAL_ASYNC_CLIENT:
        return True
    if method:
        m_upper = method.upper()
        orig = _ORIGINAL_ASYNC_METHODS.get(m_upper)
        if orig is not None and getattr(httpx.AsyncClient, m_upper.lower(), None) is not orig:
            return True
    else:
        for m_upper, orig in _ORIGINAL_ASYNC_METHODS.items():
            if getattr(httpx.AsyncClient, m_upper.lower(), None) is not orig:
                return True
    return False


def _filter_callable_kwargs(fn: Any, call_kwargs: Dict[str, Any]) -> Dict[str, Any]:
    """Filters keyword arguments to those accepted by a patched test double."""
    try:
        sig = inspect.signature(fn)
    except (TypeError, ValueError):
        return call_kwargs
    for param in sig.parameters.values():
        if param.kind == inspect.Parameter.VAR_KEYWORD:
            return call_kwargs
    allowed = set(sig.parameters.keys())
    return {k: v for k, v in call_kwargs.items() if k in allowed}


async def _send_http_attempt(
    http_client: Optional[httpx.AsyncClient],
    method_upper: str,
    url: str,
    req_headers: Dict[str, str],
    req_timeout: httpx.Timeout,
    follow_redirects: bool,
    kwargs: Dict[str, Any],
) -> httpx.Response:
    method_lower = method_upper.lower()
    if http_client is None and httpx.AsyncClient is not _ORIGINAL_ASYNC_CLIENT:
        async with httpx.AsyncClient(timeout=req_timeout, follow_redirects=follow_redirects) as patched_client:
            verb = getattr(patched_client, method_lower, None)
            if callable(verb):
                call_kw = _filter_callable_kwargs(verb, {"headers": req_headers, **kwargs})
                return await verb(url, **call_kw)
            return await patched_client.request(
                method_upper,
                url,
                headers=req_headers,
                timeout=req_timeout,
                follow_redirects=follow_redirects,
                **kwargs,
            )

    active_client = http_client or get_http_client()
    orig_method = _ORIGINAL_ASYNC_METHODS.get(method_upper)
    if (
        http_client is None
        and orig_method is not None
        and getattr(httpx.AsyncClient, method_lower, None) is not orig_method
    ):
        verb = getattr(active_client, method_lower)
        call_kw = _filter_callable_kwargs(
            verb,
            {
                "headers": req_headers,
                "timeout": req_timeout,
                "follow_redirects": follow_redirects,
                **kwargs,
            },
        )
        return await verb(url, **call_kw)

    return await active_client.request(
        method_upper,
        url,
        headers=req_headers,
        timeout=req_timeout,
        follow_redirects=follow_redirects,
        **kwargs,
    )


async def request_with_resilience(
    method: str,
    url: str,
    *,
    target: Optional[str] = None,
    timeout: Optional[httpx.Timeout | float] = None,
    follow_redirects: bool = False,
    retries: int = 0,
    retry_base: float = 0.25,
    retry_statuses: tuple[int, ...] = (429, 502, 503, 504),
    use_circuit_breaker: bool = True,
    headers: Optional[Dict[str, str]] = None,
    client: Optional[httpx.AsyncClient] = None,
    **kwargs: Any,
) -> httpx.Response:
    """
    Executes an outbound HTTP request through the shared connection pool with:
      - Circuit breaker protection
      - Split connect/read/write/pool timeouts
      - Explicit follow_redirects (False by default)
      - Optional full-jitter exponential backoff retries
      - W3C traceparent propagation + Prometheus metrics
    """
    logical_target = target or target_from_url(url)
    cb = get_circuit_breaker(logical_target) if use_circuit_breaker else None

    if cb is not None and not cb.allow_request():
        raise CircuitOpenError(logical_target, cb.retry_after_seconds())

    req_timeout = (
        httpx.Timeout(connect=min(2.0, float(timeout)), read=float(timeout), write=float(timeout), pool=2.0)
        if isinstance(timeout, (int, float))
        else (timeout or DEFAULT_HTTP_TIMEOUT)
    )
    req_headers = _inject_trace_headers(headers)
    method_upper = method.upper()

    last_exc: Optional[Exception] = None
    attempts = max(1, int(retries) + 1)

    for attempt in range(attempts):
        started = time.monotonic()
        try:
            resp = await _send_http_attempt(
                client,
                method_upper,
                url,
                req_headers,
                req_timeout,
                follow_redirects,
                kwargs,
            )
            elapsed = time.monotonic() - started
            if OUTBOUND_REQUEST_DURATION is not None:
                try:
                    OUTBOUND_REQUEST_DURATION.labels(target=logical_target, status=str(resp.status_code)).observe(elapsed)
                except Exception:
                    pass

            if resp.status_code in retry_statuses:
                if cb is not None:
                    cb.record_failure()
                if attempt + 1 < attempts:
                    if OUTBOUND_RETRY_COUNTER is not None:
                        try:
                            OUTBOUND_RETRY_COUNTER.labels(target=logical_target).inc()
                        except Exception:
                            pass
                    await asyncio.sleep(full_jitter_backoff(retry_base, attempt, cap=5.0))
                    continue
                return resp

            if resp.status_code >= 500:
                if cb is not None:
                    cb.record_failure()
            elif cb is not None:
                cb.record_success()
            return resp

        except (httpx.TimeoutException, httpx.RequestError) as exc:
            elapsed = time.monotonic() - started
            if OUTBOUND_REQUEST_DURATION is not None:
                try:
                    OUTBOUND_REQUEST_DURATION.labels(target=logical_target, status="error").observe(elapsed)
                except Exception:
                    pass
            if cb is not None:
                cb.record_failure()
            last_exc = exc
            if attempt + 1 < attempts:
                if OUTBOUND_RETRY_COUNTER is not None:
                    try:
                        OUTBOUND_RETRY_COUNTER.labels(target=logical_target).inc()
                    except Exception:
                        pass
                await asyncio.sleep(full_jitter_backoff(retry_base, attempt, cap=5.0))
                continue
            raise

    assert last_exc is not None
    raise last_exc
