import random
import uuid
from locust import HttpUser, task, between

class AMLIngestionUser(HttpUser):
    """
    Simulates high-throughput Core Banking and Payment Gateway transaction ingestion.
    Benchmarks the real-time deterministic rules engine and behavioral scoring pipeline.
    """
    wait_time = between(0.1, 0.5)  # Simulate 2 to 10 requests per user per second

    test_accounts = [
        "DE12003400567890111100",
        "US99887766554433221100",
        "GB44332211009988776655",
        "RU11223344556677889900"
    ]

    channels = ["Wire", "SWIFT", "ACH", "POS", "Card"]
    countries = ["US", "DE", "GB", "AE", "KY", "PA"]
    merchants = ["Apex Clearing", "Global Remit Ltd", "Metro Retail", "Crypto Bridge Corp"]

    def on_start(self):
        """Optionally authenticate or set up session headers."""
        self.headers = {
            "Content-Type": "application/json"
        }

    @task(8)
    def submit_transaction(self):
        """Simulates transaction ingestion payload."""
        # 10% chance of triggering Structuring ($9,000 - $9,999)
        # 5% chance of triggering Large CTR ($10,000+)
        # 85% chance of normal routine transaction ($10 - $2,500)
        roll = random.random()
        if roll < 0.10:
            amount = round(random.uniform(9000.0, 9950.0), 2)
        elif roll < 0.15:
            amount = round(random.uniform(10500.0, 50000.0), 2)
        else:
            amount = round(random.uniform(15.0, 2500.0), 2)

        sender = random.choice(self.test_accounts)
        receiver = random.choice([acc for acc in self.test_accounts if acc != sender] or self.test_accounts)

        payload = {
            "sender_account_id": sender,
            "receiver_account_id": receiver,
            "amount": amount,
            "currency": "USD",
            "country": random.choice(self.countries),
            "merchant": random.choice(self.merchants),
            "device": f"Terminal-{random.randint(1, 20):02d}",
            "channel": random.choice(self.channels)
        }

        with self.client.post("/api/v1/transactions", json=payload, headers=self.headers, catch_response=True) as resp:
            if resp.status_code in (200, 201):
                resp.success()
            elif resp.status_code == 422:
                resp.failure(f"Validation failure: {resp.text}")
            else:
                resp.failure(f"HTTP {resp.status_code}: {resp.text}")

    @task(2)
    def check_health(self):
        """Simulates internal gateway health probe checks."""
        self.client.get("/health/live")
