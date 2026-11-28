"""
AML Sentinel — Stage 3 Mixed Workload & 3x Spike Locust Load Suite
==================================================================
Models realistic 50k-100k+ traffic split across priority tiers:
  - `AMLIngestionUser` (P0_CRITICAL): Idempotent transaction ingestion + health probes
  - `AMLComplianceAnalystUser` (P1_HIGH / P3_SHEDDABLE): Keyset alert triage, cached
    compliance reports, and async PDF export offload (`?async_mode=true`)
  - `ThreeXSpikeLoadShape`: Optional 3x surge + recovery load shape activated when
    `AML_LOCUST_SHAPE=3x_spike` is set in the environment.
"""

import os
import secrets
import uuid
from datetime import datetime, timezone
from locust import HttpUser, LoadTestShape, between, task

prng = secrets.SystemRandom()


def _login_session(client) -> dict[str, str]:
    username = os.getenv("AML_LOAD_USER", "admin")
    password = os.getenv("AML_LOAD_PASSWORD", "admin123")
    headers = {
        "Content-Type": "application/json",
        "X-CSRF-Protection": "1",
    }
    resp = client.post(
        "/api/v1/auth/login",
        data={"username": username, "password": password},
        headers={"X-CSRF-Protection": "1"},
    )
    if resp.status_code == 200:
        token = resp.json().get("access_token")
        if token:
            headers["Authorization"] = f"Bearer {token}"
    return headers


class AMLIngestionUser(HttpUser):
    """P0_CRITICAL: High-throughput core banking payment ingestion with Idempotency-Key."""

    weight = 3
    wait_time = between(0.1, 0.4)

    test_accounts = [
        "ACCT-0a2e9dcd",
        "ACCT-1b3f8eae",
        "ACCT-2c4a7fbf",
        "ACCT-3d5b6aca",
    ]
    channels = ["Wire", "SWIFT", "ACH", "POS", "Card"]
    countries = ["US", "DE", "GB", "AE", "KY", "PA"]
    merchants = ["Apex Clearing", "Global Remit Ltd", "Metro Retail", "Crypto Bridge Corp"]

    def on_start(self):
        self.headers = _login_session(self.client)

    @task(8)
    def submit_transaction(self):
        roll = prng.random()
        if roll < 0.10:
            amount = round(prng.uniform(9000.0, 9950.0), 2)
        elif roll < 0.15:
            amount = round(prng.uniform(10500.0, 50000.0), 2)
        else:
            amount = round(prng.uniform(15.0, 2500.0), 2)

        sender = prng.choice(self.test_accounts)
        receiver = prng.choice([acc for acc in self.test_accounts if acc != sender] or self.test_accounts)
        payload = {
            "sender_account": sender,
            "receiver_account": receiver,
            "amount": amount,
            "currency": "USD",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "country": prng.choice(self.countries),
            "merchant": prng.choice(self.merchants),
            "device": f"Terminal-{prng.randint(1, 20):02d}",
            "channel": prng.choice(self.channels),
        }
        req_headers = {**self.headers, "Idempotency-Key": f"locust-{uuid.uuid4().hex}"}

        with self.client.post(
            "/api/v1/transactions/ingest",
            json=payload,
            headers=req_headers,
            name="/api/v1/transactions/ingest [P0]",
            catch_response=True,
        ) as resp:
            if resp.status_code in (200, 201, 202):
                resp.success()
            else:
                resp.failure(f"P0 unexpected HTTP {resp.status_code}: {resp.text[:200]}")

    @task(2)
    def check_health(self):
        self.client.get("/health/ready", name="/health/ready [P0]")


class AMLComplianceAnalystUser(HttpUser):
    """P1_HIGH / P3_SHEDDABLE: Triage reads, cached compliance reports, and async exports."""

    weight = 2
    wait_time = between(0.2, 0.8)

    def on_start(self):
        self.headers = _login_session(self.client)

    @task(5)
    def list_alerts_keyset(self):
        with self.client.get(
            "/api/v1/alerts?limit=25",
            headers=self.headers,
            name="/api/v1/alerts [P1]",
            catch_response=True,
        ) as resp:
            if resp.status_code == 200:
                resp.success()
            else:
                resp.failure(f"P1 alerts HTTP {resp.status_code}")

    @task(3)
    def read_cached_sar_summary(self):
        with self.client.get(
            "/api/v1/reports/sar-summary",
            headers=self.headers,
            name="/api/v1/reports/sar-summary [P3]",
            catch_response=True,
        ) as resp:
            if resp.status_code == 200 or (resp.status_code == 503 and resp.headers.get("Retry-After")):
                resp.success()
            else:
                resp.failure(f"P3 report HTTP {resp.status_code}")

    @task(1)
    def enqueue_async_pdf_export(self):
        req_headers = {**self.headers, "Idempotency-Key": f"locust-pdf-{uuid.uuid4().hex}"}
        with self.client.get(
            "/api/v1/alerts/export/pdf?async_mode=true",
            headers=req_headers,
            name="/api/v1/alerts/export/pdf?async_mode=true [P3]",
            catch_response=True,
        ) as resp:
            if resp.status_code == 202 or (resp.status_code == 503 and resp.headers.get("Retry-After")):
                resp.success()
            else:
                resp.failure(f"P3 async export HTTP {resp.status_code}")


if os.getenv("AML_LOCUST_SHAPE", "").strip().lower() == "3x_spike":
    class ThreeXSpikeLoadShape(LoadTestShape):
        """Baseline -> 3x Spike -> Recovery load shape for Stage 3 resilience verification."""

        stages = [
            {"duration": 30, "users": 50, "spawn_rate": 10},
            {"duration": 90, "users": 150, "spawn_rate": 30},   # 3x spike
            {"duration": 150, "users": 50, "spawn_rate": 20},   # Recovery
            {"duration": 180, "users": 0, "spawn_rate": 25},    # Cooldown
        ]

        def tick(self):
            run_time = self.get_run_time()
            for stage in self.stages:
                if run_time < stage["duration"]:
                    return stage["users"], stage["spawn_rate"]
            return None
