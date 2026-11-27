"""
Global Pytest Environment Isolation & Safety Fixtures (§4.5)
=============================================================
Guarantees automated test runs:
  - Never accidentally hit live Supabase, FinCEN, HIBP, GDELT, or Frankfurter APIs
  - Reset circuit breakers and in-process rate limiter buckets between tests
"""

import os
import pytest


def pytest_configure(config):
    os.environ.setdefault("OUTBOUND_EGRESS_ENABLED", "false")
    os.environ.setdefault("FINCEN_SANDBOX_MODE", "true")
    os.environ.setdefault("FINCEN_TRANSPORT", "sandbox")


@pytest.fixture(autouse=True)
def _reset_http_circuit_breakers():
    from routers.health import reset_server_draining
    from services.http_client import reset_all_circuit_breakers

    reset_all_circuit_breakers()
    reset_server_draining()
    yield
    reset_all_circuit_breakers()
    reset_server_draining()
