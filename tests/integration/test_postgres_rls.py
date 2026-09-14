"""
Integration Test: PostgreSQL Row Level Security (RLS) Tenant Isolation (Finding #31)
====================================================================================
Verifies that PostgreSQL Row Level Security (RLS) policies enforce fail-closed
multi-tenant isolation across accounts, transactions, and alerts tables.
"""

import uuid
import pytest
import asyncpg
from config import settings

DB_URL = f"postgresql://postgres:postgrespassword@{settings.postgres_host}:{settings.postgres_port}/{settings.postgres_db}"


async def get_test_conn():
    try:
        return await asyncpg.connect(DB_URL, timeout=3)
    except Exception:
        return None


@pytest.mark.anyio
async def test_postgres_rls_accounts_tenant_isolation():
    """
    Verifies that accounts are isolated strictly per tenant,
    unauthenticated access returns zero rows (fail-closed),
    and cross-tenant write operations are blocked by RLS CHECK constraints.
    """
    conn = await get_test_conn()
    if conn is None:
        pytest.skip(f"PostgreSQL not accessible at {settings.postgres_host}:{settings.postgres_port}")

    tenant_1 = uuid.uuid4()
    tenant_2 = uuid.uuid4()
    acc_id = uuid.uuid4()
    acc_num = f"ACC-{uuid.uuid4().hex[:8]}"

    async with conn.transaction():
        # Seed test tenants
        await conn.execute(f"INSERT INTO tenants (id, name, created_at) VALUES ('{tenant_1}', 'Tenant One Bank', NOW());")
        await conn.execute(f"INSERT INTO tenants (id, name, created_at) VALUES ('{tenant_2}', 'Tenant Two Bank', NOW());")

        # Switch to application role to enforce RLS
        await conn.execute("SET LOCAL ROLE aml_app;")

        # 1. Tenant 1 writes and reads its own account
        await conn.execute(f"SET LOCAL app.current_tenant_id = '{tenant_1}';")
        await conn.execute(
            f"INSERT INTO accounts (id, tenant_id, account_number, owner_name, risk_score, status) "
            f"VALUES ('{acc_id}', '{tenant_1}', '{acc_num}', 'Tenant 1 Customer', 0.1, 'ACTIVE');"
        )
        rows_tenant_1 = await conn.fetch(f"SELECT id FROM accounts WHERE id = '{acc_id}';")
        assert len(rows_tenant_1) == 1, "Tenant 1 must be able to read its own account"

        # 2. Tenant 2 must NOT see Tenant 1's account
        await conn.execute(f"SET LOCAL app.current_tenant_id = '{tenant_2}';")
        rows_tenant_2 = await conn.fetch(f"SELECT id FROM accounts WHERE id = '{acc_id}';")
        assert len(rows_tenant_2) == 0, "Tenant 2 must NOT see Tenant 1's account (RLS breach!)"

        # 3. Fail-Closed: Query with unset app.current_tenant_id must return 0 rows
        await conn.execute("RESET app.current_tenant_id;")
        rows_unset = await conn.fetch(f"SELECT id FROM accounts WHERE id = '{acc_id}';")
        assert len(rows_unset) == 0, "Unauthenticated session must see 0 rows (fail-closed violated!)"

        # 4. Cross-tenant spoofed insertion must be blocked by RLS WITH CHECK policy
        await conn.execute(f"SET LOCAL app.current_tenant_id = '{tenant_2}';")
        attacker_acc_id = uuid.uuid4()
        attacker_acc_num = f"ACC-{uuid.uuid4().hex[:8]}"

        with pytest.raises(asyncpg.exceptions.InsufficientPrivilegeError):
            # Tenant 2 attempts to write a record attributed to Tenant 1
            await conn.execute(
                f"INSERT INTO accounts (id, tenant_id, account_number, owner_name, risk_score, status) "
                f"VALUES ('{attacker_acc_id}', '{tenant_1}', '{attacker_acc_num}', 'Malicious Attacker', 0.9, 'ACTIVE');"
            )

    await conn.close()


@pytest.mark.anyio
async def test_postgres_rls_transactions_tenant_isolation():
    """
    Verifies that transaction records enforce fail-closed RLS policies.
    """
    conn = await get_test_conn()
    if conn is None:
        pytest.skip(f"PostgreSQL not accessible at {settings.postgres_host}:{settings.postgres_port}")

    tenant_a = uuid.uuid4()
    tenant_b = uuid.uuid4()
    tx_id = uuid.uuid4()

    async with conn.transaction():
        await conn.execute(f"INSERT INTO tenants (id, name, created_at) VALUES ('{tenant_a}', 'Bank A', NOW());")
        await conn.execute(f"INSERT INTO tenants (id, name, created_at) VALUES ('{tenant_b}', 'Bank B', NOW());")

        await conn.execute("SET LOCAL ROLE aml_app;")

        # Tenant A inserts transaction
        await conn.execute(f"SET LOCAL app.current_tenant_id = '{tenant_a}';")
        await conn.execute(
            f"INSERT INTO transactions (id, tenant_id, amount, currency, status, timestamp) "
            f"VALUES ('{tx_id}', '{tenant_a}', 50000.00, 'USD', 'COMPLETED', NOW());"
        )
        assert len(await conn.fetch(f"SELECT id FROM transactions WHERE id = '{tx_id}';")) == 1

        # Tenant B cannot see it
        await conn.execute(f"SET LOCAL app.current_tenant_id = '{tenant_b}';")
        assert len(await conn.fetch(f"SELECT id FROM transactions WHERE id = '{tx_id}';")) == 0

        # Unset tenant cannot see it
        await conn.execute("RESET app.current_tenant_id;")
        assert len(await conn.fetch(f"SELECT id FROM transactions WHERE id = '{tx_id}';")) == 0

    await conn.close()


@pytest.mark.anyio
async def test_postgres_rls_alerts_tenant_isolation():
    """
    Verifies that compliance alert records enforce fail-closed RLS policies.
    """
    conn = await get_test_conn()
    if conn is None:
        pytest.skip(f"PostgreSQL not accessible at {settings.postgres_host}:{settings.postgres_port}")

    tenant_x = uuid.uuid4()
    tenant_y = uuid.uuid4()
    alert_id = uuid.uuid4()

    async with conn.transaction():
        await conn.execute(f"INSERT INTO tenants (id, name, created_at) VALUES ('{tenant_x}', 'Bank X', NOW());")
        await conn.execute(f"INSERT INTO tenants (id, name, created_at) VALUES ('{tenant_y}', 'Bank Y', NOW());")

        await conn.execute("SET LOCAL ROLE aml_app;")

        # Tenant X inserts alert
        await conn.execute(f"SET LOCAL app.current_tenant_id = '{tenant_x}';")
        await conn.execute(
            f"INSERT INTO alerts (id, tenant_id, rule_name, threat_level, status, created_at) "
            f"VALUES ('{alert_id}', '{tenant_x}', 'STRUCTURING_RAPID_VELOCITY', 'CRITICAL', 'NEW', NOW());"
        )
        assert len(await conn.fetch(f"SELECT id FROM alerts WHERE id = '{alert_id}';")) == 1

        # Tenant Y cannot see it
        await conn.execute(f"SET LOCAL app.current_tenant_id = '{tenant_y}';")
        assert len(await conn.fetch(f"SELECT id FROM alerts WHERE id = '{alert_id}';")) == 0

        # Unset tenant cannot see it
        await conn.execute("RESET app.current_tenant_id;")
        assert len(await conn.fetch(f"SELECT id FROM alerts WHERE id = '{alert_id}';")) == 0

    await conn.close()
