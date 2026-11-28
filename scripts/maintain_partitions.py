"""
Automated Time-Range Partition Lifecycle Maintenance Runner (Scale Stage 3)
===========================================================================
Invoked weekly by `aml-partition-maintenance` Kubernetes CronJob to:
  1. Pre-create weekly `transactional_outbox` partitions (8 weeks ahead).
  2. Pre-create monthly `audit_log` WORM partitions (12 months ahead).
  3. Instantaneously DROP expired `transactional_outbox` partitions older than
     `OUTBOX_PARTITION_RETENTION_WEEKS` (default 2 weeks) once zero PENDING/PROCESSING
     rows remain — eliminating autovacuum bloat without table locks.
  4. Never drops `audit_log` partitions automatically (5-year BSA WORM archival is
     governed by verified S3 Object Lock export + DETACH PARTITION SOP).
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import asyncpg

from observability.logging import setup_json_logging
from services.secrets_manager import get_postgres_dsn
from services.tls_manager import get_ssl_context

logger = logging.getLogger("aml.partition_maintenance")


async def run_partition_maintenance(
    *,
    outbox_weeks_ahead: int = 8,
    audit_months_ahead: int = 12,
    outbox_retention_weeks: int = 2,
) -> dict[str, int]:
    conn = await asyncpg.connect(dsn=get_postgres_dsn(), ssl=get_ssl_context(), timeout=15.0)
    try:
        outbox_created = await conn.fetchval(
            "SELECT ensure_outbox_weekly_partitions(2, $1);",
            int(outbox_weeks_ahead),
        )
        audit_created = await conn.fetchval(
            "SELECT ensure_audit_monthly_partitions(2, $1);",
            int(audit_months_ahead),
        )
        outbox_dropped = await conn.fetchval(
            "SELECT drop_expired_outbox_partitions($1);",
            int(outbox_retention_weeks),
        )
        summary = {
            "outbox_partitions_created": int(outbox_created or 0),
            "audit_partitions_created": int(audit_created or 0),
            "outbox_partitions_dropped": int(outbox_dropped or 0),
        }
        logger.info("Partition maintenance completed: %s", json.dumps(summary))
        return summary
    finally:
        await conn.close()


async def _main() -> None:
    setup_json_logging(level=logging.INFO)
    from services.vault_loader import VaultSecretsLoader

    await VaultSecretsLoader.bootstrap()
    try:
        result = await run_partition_maintenance(
            outbox_weeks_ahead=int(os.getenv("OUTBOX_PARTITIONS_WEEKS_AHEAD", "8")),
            audit_months_ahead=int(os.getenv("AUDIT_PARTITIONS_MONTHS_AHEAD", "12")),
            outbox_retention_weeks=int(os.getenv("OUTBOX_PARTITION_RETENTION_WEEKS", "2")),
        )
        print(json.dumps(result))
    finally:
        await VaultSecretsLoader.shutdown()


if __name__ == "__main__":
    asyncio.run(_main())
