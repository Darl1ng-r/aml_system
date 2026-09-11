"""
Prometheus Metrics Registry and Exposition
==========================================
Provides standard Prometheus metrics tracking for compliance, SLOs, and alerting:
- http_requests_total{method, endpoint, status}
- http_request_duration_seconds_bucket{endpoint, le}
- audit_events_total{event_type}
"""

import threading
import time
from collections import defaultdict

_lock = threading.Lock()

# Counters: (method, endpoint, status) -> count
_http_requests = defaultdict(int)

# Histogram buckets for latency in seconds
DURATION_BUCKETS = (0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)
# (endpoint, le) -> count
_duration_buckets = defaultdict(int)
# endpoint -> sum of durations
_duration_sum = defaultdict(float)
# endpoint -> total count
_duration_count = defaultdict(int)

# Audit event counters: event_type -> count
_audit_events = defaultdict(int)


def record_http_request(method: str, endpoint: str, status_code: int, duration_seconds: float):
    """Records an incoming HTTP request execution."""
    status_str = str(status_code)
    with _lock:
        _http_requests[(method, endpoint, status_str)] += 1
        _duration_sum[endpoint] += duration_seconds
        _duration_count[endpoint] += 1
        for b in DURATION_BUCKETS:
            if duration_seconds <= b:
                _duration_buckets[(endpoint, str(b))] += 1
        _duration_buckets[(endpoint, "+Inf")] += 1


def record_audit_event(event_type: str):
    """Records an emitted security / compliance audit event."""
    with _lock:
        _audit_events[event_type] += 1


def generate_metrics_text() -> str:
    """Renders all registered metrics into Prometheus text exposition format."""
    lines = []

    # 1. http_requests_total
    lines.append("# HELP http_requests_total Total number of HTTP requests processed.")
    lines.append("# TYPE http_requests_total counter")
    with _lock:
        for (method, endpoint, status), count in sorted(_http_requests.items()):
            lines.append(f'http_requests_total{{method="{method}",endpoint="{endpoint}",status="{status}"}} {count}')

        # 2. http_request_duration_seconds
        lines.append("# HELP http_request_duration_seconds HTTP request latency histogram in seconds.")
        lines.append("# TYPE http_request_duration_seconds histogram")
        endpoints = sorted(list(_duration_count.keys()))
        for ep in endpoints:
            for b in DURATION_BUCKETS:
                cnt = _duration_buckets.get((ep, str(b)), 0)
                lines.append(f'http_request_duration_seconds_bucket{{endpoint="{ep}",le="{b}"}} {cnt}')
            inf_cnt = _duration_buckets.get((ep, "+Inf"), 0)
            lines.append(f'http_request_duration_seconds_bucket{{endpoint="{ep}",le="+Inf"}} {inf_cnt}')
            lines.append(f'http_request_duration_seconds_sum{{endpoint="{ep}"}} {_duration_sum[ep]:.6f}')
            lines.append(f'http_request_duration_seconds_count{{endpoint="{ep}"}} {_duration_count[ep]}')

        # 3. audit_events_total
        lines.append("# HELP audit_events_total Total security and compliance audit events emitted.")
        lines.append("# TYPE audit_events_total counter")
        for event_type, count in sorted(_audit_events.items()):
            lines.append(f'audit_events_total{{event_type="{event_type}"}} {count}')

    lines.append("")
    return "\n".join(lines)
