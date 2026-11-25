"""
Local development utility to re-seal a forked SHA-256 audit_log hash chain
created before pg_advisory_xact_lock serialization was added to services/audit.py.

NOT for production WORM environments.
"""
import asyncio
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import settings
from database.postgres import init_db_pool, get_async_db_conn
from services.audit import GENESIS_AUDIT_HASH, compute_audit_record_hash

DEFAULT_TENANT = "00000000-0000-0000-0000-000000000001"


async def repair_chain(tenant_id: str = DEFAULT_TENANT) -> None:
    env = os.getenv("ENVIRONMENT", settings.environment).strip().lower()
    if getattr(settings, "is_hardened", settings.is_production) or env in {"production", "prod", "staging"}:
        raise RuntimeError(
            "CRITICAL (P1-14): scripts/repair_local_audit_chain.py disables WORM audit triggers and is strictly "
            "forbidden in production/staging environments."
        )
    await init_db_pool()
    async with get_async_db_conn(tenant_id=tenant_id) as conn:
        async with conn.transaction():
            # Temporarily suspend local WORM update rule inside this atomic transaction
            had_no_update_rule = await conn.fetchval(
                "SELECT 1 FROM pg_rules WHERE tablename = 'audit_log' AND rulename = 'audit_log_no_update';"
            )
            if had_no_update_rule:
                await conn.execute("DROP RULE IF EXISTS audit_log_no_update ON public.audit_log;")

            triggers = await conn.fetch(
                """
                SELECT tgname FROM pg_trigger
                WHERE tgrelid = 'audit_log'::regclass AND NOT tgisinternal;
                """
            )
            for tg in triggers:
                await conn.execute(f'ALTER TABLE audit_log DISABLE TRIGGER "{tg["tgname"]}";')

            rows = await conn.fetch(
                """
                SELECT id, actor_id, action, resource_type, resource_id, details, created_at
                FROM audit_log
                WHERE tenant_id = $1
                ORDER BY created_at ASC, id ASC;
                """,
                tenant_id,
            )

            prev_hash = GENESIS_AUDIT_HASH
            updated = 0
            for r in rows:
                raw_details = r["details"]
                if isinstance(raw_details, str):
                    try:
                        raw_details = json.loads(raw_details)
                    except Exception:
                        pass
                created_iso = r["created_at"].isoformat() if r["created_at"] else ""
                new_hash = compute_audit_record_hash(
                    prev_hash=prev_hash,
                    created_at_iso=created_iso,
                    actor_id=r["actor_id"],
                    action=r["action"],
                    resource_type=r["resource_type"],
                    resource_id=r["resource_id"],
                    details=raw_details,
                )
                await conn.execute(
                    "UPDATE audit_log SET prev_hash = $1, record_hash = $2 WHERE id = $3;",
                    prev_hash,
                    new_hash,
                    r["id"],
                )
                prev_hash = new_hash
                updated += 1

            for tg in triggers:
                await conn.execute(f'ALTER TABLE audit_log ENABLE TRIGGER "{tg["tgname"]}";')
            if had_no_update_rule:
                await conn.execute(
                    "CREATE RULE audit_log_no_update AS ON UPDATE TO public.audit_log DO INSTEAD NOTHING;"
                )

            print(f"Re-sealed {updated} audit_log records for tenant {tenant_id}. Chain head: {prev_hash[:16]}...")


if __name__ == "__main__":
    asyncio.run(repair_chain())
