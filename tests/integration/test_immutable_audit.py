"""
Integration test for tamper-evident immutable audit_log table (GAP-9)
====================================================================
Verifies that:
1. Audit records can be inserted and queried.
2. Updates on audit_log are blocked/ignored by PostgreSQL non-bypassable rule.
3. Deletions on audit_log are blocked/ignored by PostgreSQL non-bypassable rule.
"""

import pytest
import uuid
from database.postgres import get_async_db_conn
from services.audit import record_audit_event_async

@pytest.mark.asyncio
async def test_immutable_audit_log_append_and_protection():
    tenant_id = "00000000-0000-0000-0000-000000000001"
    test_action = f"TEST_ACTION_{uuid.uuid4().hex[:8]}"
    test_resource_id = f"res_{uuid.uuid4().hex[:8]}"

    # 1. Insert audit event via service
    await record_audit_event_async(
        action=test_action,
        actor_id="test_analyst_01",
        actor_role="L1_ANALYST",
        resource_type="ALERT",
        resource_id=test_resource_id,
        tenant_id=tenant_id,
        actor_username="test_analyst",
        details={"reason": "Manual test entry", "score": 0.95}
    )

    # 2. Query and verify record was inserted
    async with get_async_db_conn(tenant_id=tenant_id) as conn:
        row = await conn.fetchrow(
            "SELECT * FROM audit_log WHERE action = $1 AND resource_id = $2;",
            test_action, test_resource_id
        )
        assert row is not None
        log_id = row["id"]
        assert row["actor_id"] == "test_analyst_01"
        assert row["actor_role"] == "L1_ANALYST"

        # 3. Attempt to UPDATE the audit record — rule audit_log_no_update must prevent change
        await conn.execute(
            "UPDATE audit_log SET action = 'TAMPERED_ACTION' WHERE id = $1;",
            log_id
        )

        row_after_update = await conn.fetchrow(
            "SELECT action FROM audit_log WHERE id = $1;",
            log_id
        )
        assert row_after_update["action"] == test_action, "Audit log must not be modifiable (UPDATE must be no-op)"

        # 4. Attempt to DELETE the audit record — rule audit_log_no_delete must prevent deletion
        await conn.execute(
            "DELETE FROM audit_log WHERE id = $1;",
            log_id
        )

        row_after_delete = await conn.fetchrow(
            "SELECT id FROM audit_log WHERE id = $1;",
            log_id
        )
        assert row_after_delete is not None, "Audit log must not be deletable (DELETE must be no-op)"
