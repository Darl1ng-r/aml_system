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

from config import settings
from observability.logging import setup_json_logging
from services.secrets_manager import get_outbox_postgres_dsn, get_postgres_dsn
from services.tls_manager import get_ssl_context

logger = logging.getLogger("aml.partition_maintenance")


async def run_partition_maintenance(
    *,
    outbox_weeks_ahead: int = 8,
    audit_months_ahead: int = 12,
    outbox_retention_weeks: int = 2,
    require_drop_privilege: bool | None = None,
) -> dict[str, int]:
    is_hardened = bool(getattr(settings, "is_hardened", settings.is_production))
    enforce_drop_priv = is_hardened if require_drop_privilege is None else bool(require_drop_privilege)
    outbox_dsn = get_outbox_postgres_dsn()
    if not outbox_dsn and is_hardened:
        raise RuntimeError(
            "CRITICAL (RLS Data-Loss Guard): OUTBOX_DATABASE_URL / AML_OUTBOX_WORKER_PASSWORD "
            "must be configured for partition maintenance in hardened environments so "
            "drop_expired_outbox_partitions() cannot be blinded by NOBYPASSRLS."
        )
    dsn = outbox_dsn or get_postgres_dsn()
    conn = await asyncpg.connect(dsn=dsn, ssl=get_ssl_context(), timeout=15.0)
    try:
        outbox_created = await conn.fetchval(
            "SELECT ensure_outbox_weekly_partitions(2, $1);",
            int(outbox_weeks_ahead),
        )
        audit_created = await conn.fetchval(
            "SELECT ensure_audit_monthly_partitions(2, $1);",
            int(audit_months_ahead),
        )
        # Fail-closed RLS verification before dropping ANY outbox partition:
        # if the connected role lacks BYPASSRLS and is not a superuser, RLS would hide
        # PENDING/PROCESSING tenant rows and cause silent data loss!
        can_see_all_tenants = await conn.fetchval(
            "SELECT COALESCE(rolbypassrls OR rolsuper, FALSE) FROM pg_roles WHERE rolname = current_user;"
        )
        if not can_see_all_tenants:
            if enforce_drop_priv:
                raise PermissionError(
                    "Refusing to run drop_expired_outbox_partitions() under a NOBYPASSRLS role: "
                    "RLS would hide unpublished tenant outbox events."
                )
            logger.warning(
                "Skipping drop_expired_outbox_partitions() in non-hardened dev mode because connected "
                "PostgreSQL role lacks BYPASSRLS; configure OUTBOX_DATABASE_URL (aml_outbox_worker) "
                "to enable safe expired-outbox partition pruning."
            )
            outbox_dropped = 0
        else:
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
