"""Scale Pillar Stage 3: Time-Range Table Partitioning for `transactional_outbox` (Weekly)
and `audit_log` (Monthly) with Automated Partition Lifecycle Functions & WORM/RLS Preservation.

Note: `transactions` intentionally remains unpartitioned in Stage 3 Option A because 3 child
tables (`alerts`, `ml_feedback_samples`, `ctr_filings`) hold Foreign Keys referencing
`transactions(id)` alongside the global `(tenant_id, idempotency_key)` uniqueness index.
See `docs/architecture/multi_region_cell_sharding_blueprint.md` for the >=50M-row expand-contract
composite-FK partitioning blueprint.

Revision ID: 040
Revises: 039
Create Date: 2026-11-28 04:26:00.000000
"""

from typing import Sequence, Union
from alembic import op
from sqlalchemy import text

revision: str = "040"
down_revision: Union[str, None] = "039"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── 1. Helper Functions for Weekly Outbox & Monthly Audit Partition Management ──
    op.execute(
        text(
            r"""
            CREATE OR REPLACE FUNCTION ensure_outbox_weekly_partitions(
                weeks_back INT DEFAULT 2,
                weeks_ahead INT DEFAULT 8
            ) RETURNS INT
            LANGUAGE plpgsql
            AS $$
            DECLARE
                base_week TIMESTAMPTZ := date_trunc('week', NOW() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC';
                i INT;
                p_start TIMESTAMPTZ;
                p_end TIMESTAMPTZ;
                p_suffix TEXT;
                p_name TEXT;
                child_idx REGCLASS;
                created_count INT := 0;
            BEGIN
                FOR i IN (-weeks_back)..weeks_ahead LOOP
                    p_start := base_week + make_interval(weeks => i);
                    p_end := base_week + make_interval(weeks => i + 1);
                    p_suffix := to_char(p_start AT TIME ZONE 'UTC', '"p"IYYY_"w"IW');
                    p_name := 'transactional_outbox_' || p_suffix;

                    IF to_regclass(format('%I', p_name)) IS NULL THEN
                        EXECUTE format(
                            'CREATE TABLE %I PARTITION OF transactional_outbox FOR VALUES FROM (%L) TO (%L);',
                            p_name, p_start, p_end
                        );
                        created_count := created_count + 1;

                        -- Rename hot partial index child to include parent prefix for EXPLAIN clarity
                        SELECT ih.inhrelid::regclass INTO child_idx
                        FROM pg_inherits ih
                        JOIN pg_index ix ON ix.indexrelid = ih.inhrelid
                        WHERE ih.inhparent = 'idx_outbox_active_created_id'::regclass
                          AND ix.indrelid = format('%I', p_name)::regclass
                        LIMIT 1;
                        IF child_idx IS NOT NULL THEN
                            EXECUTE format(
                                'ALTER INDEX %s RENAME TO %I;',
                                child_idx,
                                'idx_outbox_active_created_id_' || p_suffix
                            );
                        END IF;
                    END IF;

                    -- Defense-in-depth: enforce FORCE ROW LEVEL SECURITY on every child partition too
                    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY;', p_name);
                    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY;', p_name);
                    EXECUTE format('DROP POLICY IF EXISTS transactional_outbox_tenant_isolation ON %I;', p_name);
                    EXECUTE format(
                        'CREATE POLICY transactional_outbox_tenant_isolation ON %I FOR ALL '
                        'USING (tenant_id IS NULL OR tenant_id = NULLIF(current_setting(''app.current_tenant_id'', true), '''')::uuid) '
                        'WITH CHECK (tenant_id IS NULL OR tenant_id = NULLIF(current_setting(''app.current_tenant_id'', true), '''')::uuid);',
                        p_name
                    );
                END LOOP;

                IF to_regclass('transactional_outbox_default') IS NOT NULL THEN
                    ALTER TABLE transactional_outbox_default ENABLE ROW LEVEL SECURITY;
                    ALTER TABLE transactional_outbox_default FORCE ROW LEVEL SECURITY;
                    DROP POLICY IF EXISTS transactional_outbox_tenant_isolation ON transactional_outbox_default;
                    CREATE POLICY transactional_outbox_tenant_isolation ON transactional_outbox_default
                    FOR ALL
                    USING (tenant_id IS NULL OR tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
                    WITH CHECK (tenant_id IS NULL OR tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);
                END IF;
                RETURN created_count;
            END;
            $$;
            """
        )
    )

    op.execute(
        text(
            r"""
            CREATE OR REPLACE FUNCTION drop_expired_outbox_partitions(
                retention_weeks INT DEFAULT 2
            ) RETURNS INT
            LANGUAGE plpgsql
            AS $$
            DECLARE
                cutoff TIMESTAMPTZ := (date_trunc('week', NOW() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC')
                                      - make_interval(weeks => GREATEST(1, retention_weeks));
                rec RECORD;
                bound_expr TEXT;
                upper_str TEXT;
                upper_ts TIMESTAMPTZ;
                has_active BOOLEAN;
                dropped_count INT := 0;
            BEGIN
                FOR rec IN
                    SELECT c.oid, c.relname
                    FROM pg_inherits ih
                    JOIN pg_class c ON c.oid = ih.inhrelid
                    WHERE ih.inhparent = 'transactional_outbox'::regclass
                      AND c.relname <> 'transactional_outbox_default'
                LOOP
                    SELECT pg_get_expr(c.relpartbound, c.oid) INTO bound_expr
                    FROM pg_class c WHERE c.oid = rec.oid;

                    upper_str := substring(bound_expr FROM 'TO \(''([^'']+)''\)');
                    IF upper_str IS NULL THEN
                        CONTINUE;
                    END IF;

                    upper_ts := upper_str::timestamptz;
                    IF upper_ts <= cutoff THEN
                        EXECUTE format(
                            'SELECT EXISTS (SELECT 1 FROM %I WHERE status IN (''PENDING'', ''PROCESSING'') LIMIT 1);',
                            rec.relname
                        ) INTO has_active;

                        IF NOT has_active THEN
                            EXECUTE format('DROP TABLE IF EXISTS %I;', rec.relname);
                            dropped_count := dropped_count + 1;
                        END IF;
                    END IF;
                END LOOP;
                RETURN dropped_count;
            END;
            $$;
            """
        )
    )

    op.execute(
        text(
            r"""
            CREATE OR REPLACE FUNCTION ensure_audit_monthly_partitions(
                months_back INT DEFAULT 2,
                months_ahead INT DEFAULT 12
            ) RETURNS INT
            LANGUAGE plpgsql
            AS $$
            DECLARE
                base_month TIMESTAMPTZ := date_trunc('month', NOW() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC';
                i INT;
                p_start TIMESTAMPTZ;
                p_end TIMESTAMPTZ;
                p_suffix TEXT;
                p_name TEXT;
                child_idx REGCLASS;
                created_count INT := 0;
            BEGIN
                FOR i IN (-months_back)..months_ahead LOOP
                    p_start := base_month + make_interval(months => i);
                    p_end := base_month + make_interval(months => i + 1);
                    p_suffix := to_char(p_start AT TIME ZONE 'UTC', '"p"YYYY_MM');
                    p_name := 'audit_log_' || p_suffix;

                    IF to_regclass(format('%I', p_name)) IS NULL THEN
                        EXECUTE format(
                            'CREATE TABLE %I PARTITION OF audit_log FOR VALUES FROM (%L) TO (%L);',
                            p_name, p_start, p_end
                        );
                        created_count := created_count + 1;

                        -- Rename hot keyset index child to include parent prefix for EXPLAIN clarity
                        SELECT ih.inhrelid::regclass INTO child_idx
                        FROM pg_inherits ih
                        JOIN pg_index ix ON ix.indexrelid = ih.inhrelid
                        WHERE ih.inhparent = 'idx_audit_log_tenant_occurred_id'::regclass
                          AND ix.indrelid = format('%I', p_name)::regclass
                        LIMIT 1;
                        IF child_idx IS NOT NULL THEN
                            EXECUTE format(
                                'ALTER INDEX %s RENAME TO %I;',
                                child_idx,
                                'idx_audit_log_tenant_occurred_id_' || p_suffix
                            );
                        END IF;
                    END IF;

                    -- Defense-in-depth: enforce FORCE ROW LEVEL SECURITY on every child partition too
                    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY;', p_name);
                    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY;', p_name);
                    EXECUTE format('DROP POLICY IF EXISTS audit_log_tenant_isolation ON %I;', p_name);
                    EXECUTE format(
                        'CREATE POLICY audit_log_tenant_isolation ON %I FOR SELECT '
                        'USING (tenant_id = NULLIF(current_setting(''app.current_tenant_id'', true), '''')::uuid);',
                        p_name
                    );
                    EXECUTE format('DROP POLICY IF EXISTS audit_log_insert_policy ON %I;', p_name);
                    EXECUTE format(
                        'CREATE POLICY audit_log_insert_policy ON %I FOR INSERT '
                        'WITH CHECK (tenant_id = NULLIF(current_setting(''app.current_tenant_id'', true), '''')::uuid OR tenant_id IS NULL);',
                        p_name
                    );
                END LOOP;

                IF to_regclass('audit_log_default') IS NOT NULL THEN
                    ALTER TABLE audit_log_default ENABLE ROW LEVEL SECURITY;
                    ALTER TABLE audit_log_default FORCE ROW LEVEL SECURITY;
                    DROP POLICY IF EXISTS audit_log_tenant_isolation ON audit_log_default;
                    CREATE POLICY audit_log_tenant_isolation ON audit_log_default
                    FOR SELECT
                    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);
                    DROP POLICY IF EXISTS audit_log_insert_policy ON audit_log_default;
                    CREATE POLICY audit_log_insert_policy ON audit_log_default
                    FOR INSERT
                    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid OR tenant_id IS NULL);
                END IF;
                RETURN created_count;
            END;
            $$;
            """
        )
    )

    # ── 2. Convert `transactional_outbox` to Weekly Range-Partitioned Table ──
    op.execute(
        text(
            r"""
            DO $$
            DECLARE
                rk "char";
                child_idx REGCLASS;
            BEGIN
                SELECT relkind INTO rk FROM pg_class WHERE relname = 'transactional_outbox' AND relnamespace = 'public'::regnamespace;
                IF rk = 'p' THEN
                    PERFORM ensure_outbox_weekly_partitions(2, 8);
                    RETURN;
                END IF;

                ALTER TABLE transactional_outbox RENAME TO transactional_outbox_legacy;
                ALTER INDEX IF EXISTS transactional_outbox_pkey RENAME TO transactional_outbox_legacy_pkey;
                ALTER INDEX IF EXISTS idx_outbox_status_created RENAME TO idx_outbox_status_created_legacy;
                ALTER INDEX IF EXISTS idx_outbox_aggregate RENAME TO idx_outbox_aggregate_legacy;
                ALTER INDEX IF EXISTS idx_outbox_tenant RENAME TO idx_outbox_tenant_legacy;
                ALTER INDEX IF EXISTS idx_outbox_published_prune RENAME TO idx_outbox_published_prune_legacy;
                ALTER INDEX IF EXISTS idx_outbox_pending_processing RENAME TO idx_outbox_pending_processing_legacy;
                ALTER INDEX IF EXISTS idx_outbox_active_created_id RENAME TO idx_outbox_active_created_id_legacy;

                CREATE TABLE transactional_outbox (
                    id UUID NOT NULL DEFAULT gen_random_uuid(),
                    tenant_id UUID,
                    aggregate_type VARCHAR(50) NOT NULL,
                    aggregate_id VARCHAR(100) NOT NULL,
                    event_type VARCHAR(100) NOT NULL,
                    payload JSONB NOT NULL,
                    headers JSONB DEFAULT '{}'::jsonb,
                    status VARCHAR(20) NOT NULL DEFAULT 'PENDING',
                    retry_count INTEGER NOT NULL DEFAULT 0,
                    last_error TEXT,
                    published_at TIMESTAMPTZ,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    PRIMARY KEY (id, created_at)
                ) PARTITION BY RANGE (created_at);

                CREATE INDEX idx_outbox_status_created -- partitioned-parent-zero-rows
                    ON transactional_outbox (created_at) WHERE status = 'PENDING';
                CREATE INDEX idx_outbox_aggregate -- partitioned-parent-zero-rows
                    ON transactional_outbox (aggregate_type, aggregate_id);
                CREATE INDEX idx_outbox_tenant -- partitioned-parent-zero-rows
                    ON transactional_outbox (tenant_id);
                CREATE INDEX idx_outbox_published_prune -- partitioned-parent-zero-rows
                    ON transactional_outbox (published_at) WHERE status = 'PUBLISHED';
                CREATE INDEX idx_outbox_pending_processing -- partitioned-parent-zero-rows
                    ON transactional_outbox (created_at) WHERE status IN ('PENDING', 'PROCESSING');
                CREATE INDEX idx_outbox_active_created_id -- partitioned-parent-zero-rows
                    ON transactional_outbox (created_at, id) WHERE status IN ('PENDING', 'PROCESSING');

                PERFORM ensure_outbox_weekly_partitions(2, 8);

                CREATE TABLE transactional_outbox_default PARTITION OF transactional_outbox DEFAULT;
                SELECT ih.inhrelid::regclass INTO child_idx
                FROM pg_inherits ih
                JOIN pg_index ix ON ix.indexrelid = ih.inhrelid
                WHERE ih.inhparent = 'idx_outbox_active_created_id'::regclass
                  AND ix.indrelid = 'transactional_outbox_default'::regclass
                LIMIT 1;
                IF child_idx IS NOT NULL THEN
                    EXECUTE format('ALTER INDEX %s RENAME TO idx_outbox_active_created_id_default;', child_idx);
                END IF;

                INSERT INTO transactional_outbox (
                    id, tenant_id, aggregate_type, aggregate_id, event_type, payload,
                    headers, status, retry_count, last_error, published_at, created_at
                )
                SELECT
                    id, tenant_id, aggregate_type, aggregate_id, event_type, payload,
                    headers, status, retry_count, last_error, published_at, created_at
                FROM transactional_outbox_legacy;

                DROP TABLE transactional_outbox_legacy;

                ALTER TABLE transactional_outbox ENABLE ROW LEVEL SECURITY;
                ALTER TABLE transactional_outbox FORCE ROW LEVEL SECURITY;
                DROP POLICY IF EXISTS transactional_outbox_tenant_isolation ON transactional_outbox;
                CREATE POLICY transactional_outbox_tenant_isolation ON transactional_outbox
                FOR ALL
                USING (
                    tenant_id IS NULL
                    OR tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
                )
                WITH CHECK (
                    tenant_id IS NULL
                    OR tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
                );

                IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aml_app') THEN
                    GRANT ALL PRIVILEGES ON TABLE transactional_outbox TO aml_app;
                END IF;
            END $$;
            """
        )
    )

    # ── 3. Convert `audit_log` to Monthly Range-Partitioned WORM Table ───────
    op.execute(
        text(
            r"""
            DO $$
            DECLARE
                rk "char";
                child_idx REGCLASS;
                max_audit_id BIGINT;
                has_rows BOOLEAN;
            BEGIN
                SELECT relkind INTO rk FROM pg_class WHERE relname = 'audit_log' AND relnamespace = 'public'::regnamespace;
                IF rk = 'p' THEN
                    PERFORM ensure_audit_monthly_partitions(2, 12);
                    RETURN;
                END IF;

                ALTER TABLE audit_log RENAME TO audit_log_legacy;
                ALTER INDEX IF EXISTS audit_log_pkey RENAME TO audit_log_legacy_pkey;
                ALTER INDEX IF EXISTS idx_audit_log_tenant RENAME TO idx_audit_log_tenant_legacy;
                ALTER INDEX IF EXISTS idx_audit_log_actor RENAME TO idx_audit_log_actor_legacy;
                ALTER INDEX IF EXISTS idx_audit_log_action RENAME TO idx_audit_log_action_legacy;
                ALTER INDEX IF EXISTS idx_audit_log_resource RENAME TO idx_audit_log_resource_legacy;
                ALTER INDEX IF EXISTS idx_audit_log_occurred_at RENAME TO idx_audit_log_occurred_at_legacy;
                ALTER INDEX IF EXISTS idx_audit_log_tenant_created_id RENAME TO idx_audit_log_tenant_created_id_legacy;
                ALTER INDEX IF EXISTS idx_audit_log_tenant_occurred_id RENAME TO idx_audit_log_tenant_occurred_id_legacy;

                CREATE TABLE audit_log (
                    id BIGINT NOT NULL DEFAULT nextval('audit_log_id_seq'::regclass),
                    tenant_id UUID,
                    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    actor_id VARCHAR(100),
                    actor_username VARCHAR(100),
                    actor_role VARCHAR(50),
                    actor_ip VARCHAR(50),
                    actor_user_agent TEXT,
                    session_id VARCHAR(200),
                    action VARCHAR(100) NOT NULL,
                    resource_type VARCHAR(50),
                    resource_id VARCHAR(100),
                    before_state JSONB,
                    after_state JSONB,
                    details JSONB DEFAULT '{}'::jsonb,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    prev_hash VARCHAR(64),
                    record_hash VARCHAR(64),
                    PRIMARY KEY (id, occurred_at)
                ) PARTITION BY RANGE (occurred_at);

                ALTER SEQUENCE audit_log_id_seq OWNED BY audit_log.id;

                CREATE INDEX idx_audit_log_tenant ON audit_log (tenant_id); -- partitioned-parent-zero-rows
                CREATE INDEX idx_audit_log_actor ON audit_log (actor_id); -- partitioned-parent-zero-rows
                CREATE INDEX idx_audit_log_action ON audit_log (action); -- partitioned-parent-zero-rows
                CREATE INDEX idx_audit_log_resource ON audit_log (resource_type, resource_id); -- partitioned-parent-zero-rows
                CREATE INDEX idx_audit_log_occurred_at ON audit_log (occurred_at DESC); -- partitioned-parent-zero-rows
                CREATE INDEX idx_audit_log_tenant_created_id ON audit_log (tenant_id, created_at DESC, id DESC); -- partitioned-parent-zero-rows
                CREATE INDEX idx_audit_log_tenant_occurred_id ON audit_log (tenant_id, occurred_at DESC, id DESC); -- partitioned-parent-zero-rows

                PERFORM ensure_audit_monthly_partitions(2, 12);

                CREATE TABLE audit_log_default PARTITION OF audit_log DEFAULT;
                SELECT ih.inhrelid::regclass INTO child_idx
                FROM pg_inherits ih
                JOIN pg_index ix ON ix.indexrelid = ih.inhrelid
                WHERE ih.inhparent = 'idx_audit_log_tenant_occurred_id'::regclass
                  AND ix.indrelid = 'audit_log_default'::regclass
                LIMIT 1;
                IF child_idx IS NOT NULL THEN
                    EXECUTE format('ALTER INDEX %s RENAME TO idx_audit_log_tenant_occurred_id_default;', child_idx);
                END IF;

                INSERT INTO audit_log (
                    id, tenant_id, occurred_at, actor_id, actor_username, actor_role,
                    actor_ip, actor_user_agent, session_id, action, resource_type,
                    resource_id, before_state, after_state, details, created_at,
                    prev_hash, record_hash
                )
                SELECT
                    id, tenant_id, occurred_at, actor_id, actor_username, actor_role,
                    actor_ip, actor_user_agent, session_id, action, resource_type,
                    resource_id, before_state, after_state, details, created_at,
                    prev_hash, record_hash
                FROM audit_log_legacy;

                SELECT MAX(id), COUNT(*) > 0 INTO max_audit_id, has_rows FROM audit_log;
                PERFORM setval('audit_log_id_seq', GREATEST(1, COALESCE(max_audit_id, 1)), has_rows);

                DROP RULE IF EXISTS audit_log_no_update ON audit_log_legacy;
                DROP RULE IF EXISTS audit_log_no_delete ON audit_log_legacy;
                DROP TABLE audit_log_legacy;

                -- Restore WORM immutability rules & index-friendly UUID RLS policies
                CREATE OR REPLACE RULE audit_log_no_update AS ON UPDATE TO audit_log DO INSTEAD NOTHING;
                CREATE OR REPLACE RULE audit_log_no_delete AS ON DELETE TO audit_log DO INSTEAD NOTHING;

                ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;
                ALTER TABLE audit_log FORCE ROW LEVEL SECURITY;
                DROP POLICY IF EXISTS audit_log_tenant_isolation ON audit_log;
                CREATE POLICY audit_log_tenant_isolation ON audit_log
                FOR SELECT
                USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

                DROP POLICY IF EXISTS audit_log_insert_policy ON audit_log;
                CREATE POLICY audit_log_insert_policy ON audit_log
                FOR INSERT
                WITH CHECK (
                    tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
                    OR tenant_id IS NULL
                );

                IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aml_app') THEN
                    GRANT ALL PRIVILEGES ON TABLE audit_log TO aml_app;
                    GRANT USAGE, SELECT ON SEQUENCE audit_log_id_seq TO aml_app;
                    GRANT EXECUTE ON FUNCTION ensure_outbox_weekly_partitions(INT, INT) TO aml_app;
                    GRANT EXECUTE ON FUNCTION drop_expired_outbox_partitions(INT) TO aml_app;
                    GRANT EXECUTE ON FUNCTION ensure_audit_monthly_partitions(INT, INT) TO aml_app;
                END IF;
            END $$;
            """
        )
    )


def downgrade() -> None:
    op.execute(text("DROP FUNCTION IF EXISTS ensure_outbox_weekly_partitions(INT, INT);"))
    op.execute(text("DROP FUNCTION IF EXISTS drop_expired_outbox_partitions(INT);"))
    op.execute(text("DROP FUNCTION IF EXISTS ensure_audit_monthly_partitions(INT, INT);"))
