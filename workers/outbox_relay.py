"""
Dedicated Transactional Outbox Relay Worker
============================================
Standalone async worker process extracted from FastAPI's Uvicorn lifespan so
horizontally scaled API pods stay 100% stateless and never contend on
`transactional_outbox` polling locks.

Hardened (P1-10, P1-16, P2-24):
  - Bootstraps Vault secrets before initializing DB pools
  - Writes periodic `/tmp/outbox_relay.hb` timestamp for K8s liveness exec probe
  - Cleanly closes Vault, shared HTTP pool, Kafka producer, and DB pool on exit
"""

import asyncio
import logging
import os
import signal
import sys
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from database.outbox import OutboxRelayEngine
from database.postgres import close_db_pool, init_db_pool
from observability.logging import setup_json_logging

logger = logging.getLogger("aml.outbox_relay_worker")
HEARTBEAT_FILE = os.getenv("WORKER_HEARTBEAT_FILE", "/tmp/outbox_relay.hb")


async def _heartbeat_loop(shutdown_event: asyncio.Event) -> None:
    while not shutdown_event.is_set():
        try:
            with open(HEARTBEAT_FILE, "w", encoding="utf-8") as fh:
                fh.write(str(int(time.time())))
        except Exception:
            pass
        try:
            await asyncio.wait_for(shutdown_event.wait(), timeout=15.0)
        except asyncio.TimeoutError:
            pass


async def run_worker() -> None:
    setup_json_logging(level=logging.INFO)
    from services.vault_loader import VaultSecretsLoader
    from services.http_client import close_http_client
    from services.redpanda import close_producer

    await VaultSecretsLoader.bootstrap()

    poll_interval = float(os.getenv("OUTBOX_POLL_INTERVAL_SECONDS", "0.5"))
    batch_size = int(os.getenv("OUTBOX_BATCH_SIZE", "100"))

    logger.info(
        "Starting dedicated Outbox Relay Worker (poll_interval=%.2fs, batch_size=%d)...",
        poll_interval,
        batch_size,
    )
    await init_db_pool()

    shutdown_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, shutdown_event.set)
        except NotImplementedError:
            pass

    hb_task = asyncio.create_task(_heartbeat_loop(shutdown_event))
    engine = OutboxRelayEngine(
        poll_interval_seconds=poll_interval,
        batch_size=batch_size,
    )

    try:
        await engine.run(shutdown_event=shutdown_event)
    finally:
        shutdown_event.set()
        hb_task.cancel()
        for closer in (close_producer, close_http_client, close_db_pool, VaultSecretsLoader.shutdown):
            try:
                await closer()
            except Exception:
                pass
        logger.info("Dedicated Outbox Relay Worker exited cleanly.")


if __name__ == "__main__":
    asyncio.run(run_worker())
