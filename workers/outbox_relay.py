"""
Dedicated Transactional Outbox Relay Worker
============================================
Standalone async worker process extracted from FastAPI's Uvicorn lifespan so
horizontally scaled API pods stay 100% stateless and never contend on
`transactional_outbox` polling locks.

Run via:
    python -m workers.outbox_relay
"""

import asyncio
import logging
import os
import signal
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from database.postgres import init_db_pool, close_db_pool
from database.outbox import OutboxRelayEngine
from observability.logging import setup_json_logging

logger = logging.getLogger("aml.outbox_relay_worker")


async def run_worker() -> None:
    setup_json_logging(level=logging.INFO)
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

    engine = OutboxRelayEngine(
        poll_interval_seconds=poll_interval,
        batch_size=batch_size,
    )

    try:
        await engine.run(shutdown_event=shutdown_event)
    finally:
        await close_db_pool()
        logger.info("Dedicated Outbox Relay Worker exited cleanly.")


if __name__ == "__main__":
    asyncio.run(run_worker())
