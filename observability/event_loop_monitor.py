"""
AsyncIO Event-Loop Lag Watchdog
===============================
Samples `asyncio` event loop scheduling latency every `interval_seconds` (default 100ms)
using monotonic `loop.time()`. Exports live and historical lag to Prometheus
(`asyncio_event_loop_lag_seconds` / `asyncio_event_loop_lag_current_seconds`) and logs
structured warnings whenever blocking code stalls the event loop beyond `warn_threshold_seconds`.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from observability.prometheus import record_event_loop_lag

logger = logging.getLogger(__name__)


class EventLoopLagMonitor:
    def __init__(
        self,
        interval_seconds: float = 0.1,
        warn_threshold_seconds: float = 0.1,
    ) -> None:
        self.interval_seconds = max(0.02, float(interval_seconds))
        self.warn_threshold_seconds = max(0.02, float(warn_threshold_seconds))
        self._task: asyncio.Task | None = None
        self._stop_event: asyncio.Event | None = None
        self.last_lag_seconds: float = 0.0
        self.max_lag_seconds: float = 0.0
        self.samples_recorded: int = 0

    async def _run(self) -> None:
        loop = asyncio.get_running_loop()
        assert self._stop_event is not None
        while not self._stop_event.is_set():
            expected = loop.time() + self.interval_seconds
            try:
                await asyncio.wait_for(self._stop_event.wait(), timeout=self.interval_seconds)
                break
            except asyncio.TimeoutError:
                pass
            actual = loop.time()
            lag = max(0.0, actual - expected)
            self.last_lag_seconds = lag
            if lag > self.max_lag_seconds:
                self.max_lag_seconds = lag
            self.samples_recorded += 1
            record_event_loop_lag(lag)
            if lag >= self.warn_threshold_seconds:
                logger.warning(
                    "AsyncIO event loop lag spike detected: %.1fms (threshold=%.0fms)",
                    lag * 1000.0,
                    self.warn_threshold_seconds * 1000.0,
                )

    def start(self) -> None:
        if self._task is not None and not self._task.done():
            return
        self._stop_event = asyncio.Event()
        self._task = asyncio.create_task(self._run(), name="event-loop-lag-monitor")

    async def stop(self) -> None:
        if self._stop_event is not None:
            self._stop_event.set()
        if self._task is not None:
            try:
                await asyncio.wait_for(self._task, timeout=1.0)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                self._task.cancel()
                try:
                    await self._task
                except (asyncio.CancelledError, Exception):
                    pass
            self._task = None

    def snapshot(self) -> dict[str, Any]:
        return {
            "running": bool(self._task is not None and not self._task.done()),
            "last_lag_ms": round(self.last_lag_seconds * 1000.0, 2),
            "max_lag_ms": round(self.max_lag_seconds * 1000.0, 2),
            "samples_recorded": self.samples_recorded,
            "warn_threshold_ms": round(self.warn_threshold_seconds * 1000.0, 2),
        }


event_loop_monitor = EventLoopLagMonitor()


def get_event_loop_health() -> dict[str, Any]:
    """Returns current event-loop lag diagnostics for readiness/observability checks."""
    return event_loop_monitor.snapshot()


def is_event_loop_saturated(max_lag_seconds: float = 0.5) -> bool:
    """Returns True if the background lag monitor recently observed lag >= max_lag_seconds."""
    return (
        event_loop_monitor._task is not None
        and not event_loop_monitor._task.done()
        and event_loop_monitor.last_lag_seconds >= max_lag_seconds
    )


async def probe_event_loop_lag_seconds() -> float:
    """Performs an immediate 1-tick monotonic scheduling probe on the running event loop."""
    loop = asyncio.get_running_loop()
    t0 = loop.time()
    await asyncio.sleep(0)
    return max(0.0, loop.time() - t0)
