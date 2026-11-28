"""
Priority-Tiered Adaptive Load Shedding Middleware (Scale Pillar Stage 3)
========================================================================
Pure-ASGI load-shedding guard preventing metastable collapse under extreme
50k-100k+ traffic surges. Classifies inbound HTTP traffic into 4 priority tiers
and gracefully sheds low-priority analytics/exports (`503` + jittered `Retry-After`)
BEFORE queue depth or event-loop saturation degrades P0 critical writes/auth:

  - `P0_CRITICAL`  : Health probes, JWKS, Auth/SSO, Transaction Ingestion, CTR filings (NEVER shed)
  - `P1_HIGH`      : Alert triage, Cases, SAR/FinCEN/STR filings, Screening, Onboarding, RFI
  - `P2_NORMAL`    : Search, Customers, Accounts, Notifications, Rules config
  - `P3_SHEDDABLE` : Reports, Metrics/KPIs, Exports (PDF/CSV/ZIP), Backtests, Network graphs, Jobs, QA
"""

from __future__ import annotations

import json
import logging
import random
from typing import Any

from starlette.types import ASGIApp, Receive, Scope, Send

from config import settings
from observability.event_loop_monitor import event_loop_monitor
from observability.middleware import correlation_id_var, get_current_trace_id

logger = logging.getLogger("aml.load_shedding")

P0_CRITICAL = "P0_CRITICAL"
P1_HIGH = "P1_HIGH"
P2_NORMAL = "P2_NORMAL"
P3_SHEDDABLE = "P3_SHEDDABLE"

try:
    from observability.prometheus import _get_or_create_counter, _get_or_create_gauge

    LOAD_SHED_COUNTER = _get_or_create_counter(
        "aml_load_shed_total",
        "Total HTTP requests gracefully shed by priority tier and trigger reason",
        ["tier", "reason"],
    )
    HTTP_IN_FLIGHT_GAUGE = _get_or_create_gauge(
        "aml_http_in_flight_requests",
        "Current number of in-flight HTTP requests on this worker",
        [],
    )
except Exception:  # pragma: no cover
    LOAD_SHED_COUNTER = None
    HTTP_IN_FLIGHT_GAUGE = None

_in_flight_requests: int = 0
_shed_total_local: int = 0


def classify_request_priority(path: str, method: str = "GET") -> str:
    """Maps an HTTP path + method deterministically to its load-shedding priority tier."""
    lower = (path or "").lower()

    # P0: Health probes, operational topology, cryptographic keys, auth, core payment ingestion & CTR
    if (
        lower.startswith("/health")
        or lower.startswith("/api/v1/health")
        or lower.startswith("/.well-known/")
        or lower.startswith("/api/v1/auth/")
        or lower.startswith("/api/v1/transactions")
        or lower.startswith("/api/v1/ctr")
    ):
        return P0_CRITICAL

    # P3: Heavy analytics, reports, bulk exports, backtests, graph layouts, async job submission
    if (
        "/export/" in lower
        or "/examiner-packet" in lower
        or "/backtest" in lower
        or lower.startswith("/api/v1/reports")
        or lower.startswith("/api/v1/metrics")
        or lower.startswith("/api/v1/network")
        or lower.startswith("/api/v1/jobs")
        or lower.startswith("/api/v1/qa")
        or lower == "/metrics"
    ):
        return P3_SHEDDABLE

    # P1: Active compliance workflows & regulatory filings
    if (
        lower.startswith("/api/v1/alerts")
        or lower.startswith("/api/v1/cases")
        or lower.startswith("/api/v1/fincen")
        or lower.startswith("/api/v1/str")
        or lower.startswith("/api/v1/screening")
        or lower.startswith("/api/v1/onboarding")
        or lower.startswith("/api/v1/rfi")
        or lower.startswith("/api/v1/locks")
        or lower.startswith("/api/v1/audit")
    ):
        return P1_HIGH

    return P2_NORMAL


def _primary_db_pool_utilization() -> float:
    """Computes current primary asyncpg pool saturation ratio in [0.0, 1.0]."""
    try:
        import database.postgres as _pg

        pool = _pg.db_pool
        if pool is None or not hasattr(pool, "get_size") or not hasattr(pool, "get_max_size"):
            return 0.0
        raw_max = pool.get_max_size()
        raw_size = pool.get_size()
        raw_idle = pool.get_idle_size() if hasattr(pool, "get_idle_size") else 0
        # Guard against unconfigured test MagicMocks whose __int__() silently returns 1
        if not isinstance(raw_max, int) or not isinstance(raw_size, int) or not isinstance(raw_idle, int):
            return 0.0
        if raw_max <= 0:
            return 0.0
        in_use = max(0, raw_size - raw_idle)
        return min(1.0, in_use / float(raw_max))
    except Exception:
        return 0.0


def _current_event_loop_lag_seconds() -> float:
    """Returns latest observed event-loop lag when the background lag watchdog is active."""
    try:
        if event_loop_monitor._task is not None and not event_loop_monitor._task.done():
            return float(event_loop_monitor.last_lag_seconds or 0.0)
    except Exception:
        pass
    return 0.0


def evaluate_shed_decision(
    path: str,
    method: str = "GET",
    *,
    in_flight: int | None = None,
    event_loop_lag_seconds: float | None = None,
    db_pool_utilization: float | None = None,
) -> tuple[bool, str, str]:
    """
    Evaluates whether a request should be shed.
    Returns `(should_shed, priority_tier, reason)`.
    """
    tier = classify_request_priority(path, method)
    if not getattr(settings, "load_shedding_enabled", True):
        return False, tier, ""
    if tier in (P0_CRITICAL, P1_HIGH):
        return False, tier, ""

    max_conc = max(10, int(getattr(settings, "load_shedding_max_concurrency", 200)))
    cur_in_flight = _in_flight_requests if in_flight is None else in_flight
    cur_lag = _current_event_loop_lag_seconds() if event_loop_lag_seconds is None else event_loop_lag_seconds
    cur_pool = _primary_db_pool_utilization() if db_pool_utilization is None else db_pool_utilization

    if tier == P3_SHEDDABLE:
        if cur_in_flight >= int(max_conc * 0.70):
            return True, tier, "concurrency_high"
        if cur_lag >= float(getattr(settings, "load_shedding_p3_lag_seconds", 0.12)):
            return True, tier, "event_loop_lag"
        if cur_pool >= float(getattr(settings, "load_shedding_p3_pool_ratio", 0.85)):
            return True, tier, "db_pool_saturation"
        return False, tier, ""

    if tier == P2_NORMAL:
        if cur_in_flight >= int(max_conc * 0.85):
            return True, tier, "concurrency_critical"
        if cur_lag >= float(getattr(settings, "load_shedding_p2_lag_seconds", 0.25)):
            return True, tier, "event_loop_lag_critical"
        if cur_pool >= float(getattr(settings, "load_shedding_p2_pool_ratio", 0.92)):
            return True, tier, "db_pool_critical"
        return False, tier, ""

    return False, tier, ""


def get_load_shedding_snapshot() -> dict[str, Any]:
    return {
        "enabled": bool(getattr(settings, "load_shedding_enabled", True)),
        "in_flight_requests": _in_flight_requests,
        "max_concurrency": int(getattr(settings, "load_shedding_max_concurrency", 200)),
        "shed_total": _shed_total_local,
        "event_loop_lag_ms": round(_current_event_loop_lag_seconds() * 1000.0, 2),
        "primary_db_pool_utilization": round(_primary_db_pool_utilization(), 3),
    }


def reset_load_shedding_state() -> None:
    """Resets in-flight and local shed counters (intended for test isolation)."""
    global _in_flight_requests, _shed_total_local
    _in_flight_requests = 0
    _shed_total_local = 0


def resolve_tenant_cell(tenant_id: str) -> str:
    """
    Zero-overhead multi-region cell-sharding routing seam (Stage 3).
    Returns the explicitly mapped cell from `TENANT_CELL_ROUTING_JSON` when configured,
    otherwise falls back to `settings.deployment_cell_id`.
    """
    raw = str(getattr(settings, "tenant_cell_routing_json", "") or "").strip()
    if raw:
        try:
            mapping = json.loads(raw)
            if isinstance(mapping, dict) and str(tenant_id) in mapping:
                return str(mapping[str(tenant_id)])
        except Exception:
            pass
    return str(getattr(settings, "deployment_cell_id", "cell-us-east-1"))


class AdaptiveLoadSheddingMiddleware:
    """Pure-ASGI adaptive load-shedding guard returning 503 + jittered Retry-After for shed tiers."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        global _in_flight_requests, _shed_total_local
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        method = scope.get("method", "GET")
        should_shed, tier, reason = evaluate_shed_decision(path, method)

        if should_shed:
            _shed_total_local += 1
            if LOAD_SHED_COUNTER is not None:
                try:
                    LOAD_SHED_COUNTER.labels(tier=tier, reason=reason).inc()
                except Exception:
                    pass
            retry_after = random.randint(2, 5)
            cid = correlation_id_var.get("") or ""
            tid = get_current_trace_id()
            body = json.dumps(
                {
                    "detail": (
                        "Service temporarily overloaded; non-critical request gracefully shed "
                        "to protect critical compliance operations."
                    ),
                    "priority_tier": tier,
                    "shed_reason": reason,
                    "retry_after_seconds": retry_after,
                    "correlation_id": cid,
                    "trace_id": tid,
                }
            ).encode("utf-8")
            headers = [
                (b"content-type", b"application/json"),
                (b"cache-control", b"no-store"),
                (b"cdn-cache-control", b"no-store"),
                (b"retry-after", str(retry_after).encode("ascii")),
                (b"x-load-shed-tier", tier.encode("ascii")),
                (b"x-load-shed-reason", reason.encode("ascii")),
                (b"content-length", str(len(body)).encode("ascii")),
            ]
            if cid:
                headers.append((b"x-correlation-id", cid.encode("latin-1")))
            logger.warning(
                "Adaptive load shed: method=%s path=%s tier=%s reason=%s retry_after=%ds",
                method,
                path,
                tier,
                reason,
                retry_after,
            )
            await send({"type": "http.response.start", "status": 503, "headers": headers})
            await send({"type": "http.response.body", "body": body})
            return

        _in_flight_requests += 1
        if HTTP_IN_FLIGHT_GAUGE is not None:
            try:
                HTTP_IN_FLIGHT_GAUGE.set(_in_flight_requests)
            except Exception:
                pass
        try:
            await self.app(scope, receive, send)
        finally:
            _in_flight_requests = max(0, _in_flight_requests - 1)
            if HTTP_IN_FLIGHT_GAUGE is not None:
                try:
                    HTTP_IN_FLIGHT_GAUGE.set(_in_flight_requests)
                except Exception:
                    pass
