"""
Bounded Bulkhead Compute Executors
==================================
Isolates CPU-bound workloads from the single-threaded FastAPI `asyncio` event loop
using dedicated, bounded ThreadPoolExecutors with hard per-call deadlines so a
slow backtest, graph traversal, or ZIP export can never starve authentication or
live transaction scoring:

  - `ml`        : XGBoost / SHAP / IsolationForest inference (default 2.0s deadline)
  - `crypto`    : Argon2id hashing, RS256 manifest signing, ZIP_DEFLATED packets (default 3.0s)
  - `analytics` : Tarjan SCC, Brandes centrality, historical backtests, NumPy stats (default 10.0s)
"""

from __future__ import annotations

import asyncio
import functools
import logging
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, TypeVar

from observability.prometheus import update_executor_active_tasks

logger = logging.getLogger(__name__)

T = TypeVar("T")

_CPU_COUNT = max(2, os.cpu_count() or 2)
_POOL_SIZES = {
    "ml": min(4, _CPU_COUNT),
    "crypto": min(4, _CPU_COUNT),
    "analytics": 2,
}

_lock = threading.Lock()
_executors: dict[str, ThreadPoolExecutor] = {}


def _get_executor(pool_name: str) -> ThreadPoolExecutor:
    with _lock:
        ex = _executors.get(pool_name)
        if ex is None or getattr(ex, "_shutdown", False):
            max_workers = _POOL_SIZES.get(pool_name, 2)
            ex = ThreadPoolExecutor(
                max_workers=max_workers,
                thread_name_prefix=f"aml-{pool_name}",
            )
            _executors[pool_name] = ex
        return ex


async def run_in_bulkhead(
    pool_name: str,
    fn: Callable[..., T],
    *args: Any,
    timeout: float | None = None,
    **kwargs: Any,
) -> T:
    """Offloads a synchronous CPU-bound callable into a dedicated bounded bulkhead pool."""
    loop = asyncio.get_running_loop()
    executor = _get_executor(pool_name)
    bound_fn = functools.partial(fn, *args, **kwargs) if kwargs else functools.partial(fn, *args)

    update_executor_active_tasks(pool_name, +1)
    try:
        fut = loop.run_in_executor(executor, bound_fn)
        if timeout is not None and timeout > 0:
            return await asyncio.wait_for(fut, timeout=timeout)
        return await fut
    finally:
        update_executor_active_tasks(pool_name, -1)


async def run_ml_compute(
    fn: Callable[..., T],
    *args: Any,
    timeout: float = 2.0,
    **kwargs: Any,
) -> T:
    return await run_in_bulkhead("ml", fn, *args, timeout=timeout, **kwargs)


async def run_crypto_compute(
    fn: Callable[..., T],
    *args: Any,
    timeout: float = 3.0,
    **kwargs: Any,
) -> T:
    return await run_in_bulkhead("crypto", fn, *args, timeout=timeout, **kwargs)


async def run_analytics_compute(
    fn: Callable[..., T],
    *args: Any,
    timeout: float = 10.0,
    **kwargs: Any,
) -> T:
    return await run_in_bulkhead("analytics", fn, *args, timeout=timeout, **kwargs)


def shutdown_compute_executors(wait: bool = False) -> None:
    """Gracefully shuts down all bulkhead compute executors on application lifespan exit."""
    with _lock:
        pools = list(_executors.items())
        _executors.clear()
    for name, ex in pools:
        try:
            ex.shutdown(wait=wait, cancel_futures=True)
            logger.info("Compute bulkhead executor '%s' shut down cleanly.", name)
        except Exception as exc:
            logger.warning("Compute bulkhead executor '%s' shutdown error: %s", name, exc)


def get_executor_status() -> dict[str, dict[str, Any]]:
    """Returns diagnostic configuration for health/observability endpoints."""
    with _lock:
        return {
            name: {
                "max_workers": size,
                "active": name in _executors and not getattr(_executors[name], "_shutdown", False),
            }
            for name, size in _POOL_SIZES.items()
        }
