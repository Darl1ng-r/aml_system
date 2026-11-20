import os
import secrets
from datetime import datetime, timezone
from locust import HttpUser, task, between

prng = secrets.SystemRandom()


class AMLIngestionUser(HttpUser):
    """
    Simulates authenticated high-throughput Core Banking and Payment Gateway transaction ingestion.
    Benchmarks the real-time deterministic rules engine and async outbox ingestion pipeline.
    """
    wait_time = between(0.1, 0.5)

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
        """Authenticate via OAuth2 password grant and attach Bearer + CSRF headers."""
        username = os.getenv("AML_LOAD_USER", "admin")
        password = os.getenv("AML_LOAD_PASSWORD", "admin123")
        self.headers = {
            "Content-Type": "application/json",
            "X-CSRF-Protection": "1",
        }
        resp = self.client.post(
            "/api/v1/auth/login",
            data={"username": username, "password": password},
            headers={"X-CSRF-Protection": "1"},
        )
        if resp.status_code == 200:
            token = resp.json().get("access_token")
            if token:
                self.headers["Authorization"] = f"Bearer {token}"

    @task(8)
    def submit_transaction(self):
        """Simulates authenticated transaction ingestion matching TransactionRequest schema."""
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

        with self.client.post("/api/v1/transactions/ingest", json=payload, headers=self.headers, catch_response=True) as resp:
            if resp.status_code in (200, 201, 202):
                resp.success()
            elif resp.status_code == 422:
                resp.failure(f"Validation failure: {resp.text}")
            else:
                resp.failure(f"HTTP {resp.status_code}: {resp.text}")

    @task(2)
    def check_health(self):
        """Simulates internal gateway health probe checks."""
        self.client.get("/health/live")
