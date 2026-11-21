"""P2 Competitive Differentiators: External RFI Portal + SLA Pause, Time-Boxed Auditor Rooms & Multi-Layer Corporate UBO Ownership Edges

Revision ID: 032
Revises: 031
Create Date: 2026-11-21 03:55:00.000000
"""

from typing import Sequence, Union
from alembic import op

revision: str = '032'
down_revision: Union[str, None] = '031'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        """
        -- 1. External Customer / RM Request-for-Information (RFI) Portal (P2-1)
        CREATE TABLE IF NOT EXISTS rfi_requests (
            id                      UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id               UUID          NOT NULL,
            case_id                 UUID          NOT NULL,
            account_id              UUID,
            token_hash              VARCHAR(64)   NOT NULL UNIQUE,
            recipient_email         VARCHAR(255)  NOT NULL DEFAULT '',
            recipient_role          VARCHAR(24)   NOT NULL DEFAULT 'CUSTOMER',
            prompt_message          TEXT          NOT NULL,
            requested_docs          TEXT[]        NOT NULL DEFAULT ARRAY['Source of Funds Statement']::TEXT[],
            status                  VARCHAR(24)   NOT NULL DEFAULT 'OPEN',
            response_notes          TEXT,
            submitted_evidence_ids  UUID[]        NOT NULL DEFAULT ARRAY[]::UUID[],
            expires_at              TIMESTAMPTZ   NOT NULL,
            submitted_at            TIMESTAMPTZ,
            created_by              VARCHAR(120)  NOT NULL DEFAULT '',
            created_at              TIMESTAMPTZ   NOT NULL DEFAULT NOW()
        );
        CREATE INDEX IF NOT EXISTS idx_rfi_requests_tenant_case
            ON rfi_requests (tenant_id, case_id, created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_rfi_requests_token_hash
            ON rfi_requests (token_hash);

        ALTER TABLE rfi_requests ENABLE ROW LEVEL SECURITY;
        ALTER TABLE rfi_requests FORCE ROW LEVEL SECURITY;
        DROP POLICY IF EXISTS rfi_requests_isolation ON rfi_requests;
        CREATE POLICY rfi_requests_isolation ON rfi_requests
            FOR ALL
            USING (tenant_id::text = NULLIF(current_setting('app.current_tenant_id', true), ''));

        -- 2. Time-Boxed Read-Only Regulatory Auditor Rooms (P2-3)
        CREATE TABLE IF NOT EXISTS auditor_rooms (
            id                UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id         UUID          NOT NULL,
            room_name         VARCHAR(180)  NOT NULL,
            examiner_org      VARCHAR(180)  NOT NULL DEFAULT 'Regulatory Examiner',
            token_hash        VARCHAR(64)   NOT NULL UNIQUE,
            allowed_case_ids  UUID[]        NOT NULL DEFAULT ARRAY[]::UUID[],
            expires_at        TIMESTAMPTZ   NOT NULL,
            revoked_at        TIMESTAMPTZ,
            access_count      INTEGER       NOT NULL DEFAULT 0,
            last_accessed_at  TIMESTAMPTZ,
            created_by        VARCHAR(120)  NOT NULL DEFAULT '',
            created_at        TIMESTAMPTZ   NOT NULL DEFAULT NOW()
        );
        CREATE INDEX IF NOT EXISTS idx_auditor_rooms_tenant_created
            ON auditor_rooms (tenant_id, created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_auditor_rooms_token_hash
            ON auditor_rooms (token_hash);

        ALTER TABLE auditor_rooms ENABLE ROW LEVEL SECURITY;
        ALTER TABLE auditor_rooms FORCE ROW LEVEL SECURITY;
        DROP POLICY IF EXISTS auditor_rooms_isolation ON auditor_rooms;
        CREATE POLICY auditor_rooms_isolation ON auditor_rooms
            FOR ALL
            USING (tenant_id::text = NULLIF(current_setting('app.current_tenant_id', true), ''));

        -- 3. Multi-Layer Corporate UBO Ownership Edges (P2-4)
        CREATE TABLE IF NOT EXISTS corporate_ownership_edges (
            id                  UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id           UUID          NOT NULL,
            parent_entity_name  VARCHAR(200)  NOT NULL,
            parent_entity_type  VARCHAR(24)   NOT NULL DEFAULT 'PERSON',
            child_company_name  VARCHAR(200)  NOT NULL,
            ownership_pct       NUMERIC(5,2)  NOT NULL CHECK (ownership_pct > 0 AND ownership_pct <= 100),
            jurisdiction        VARCHAR(16)   NOT NULL DEFAULT 'US',
            tax_id              VARCHAR(80),
            verified_source     VARCHAR(120)  NOT NULL DEFAULT 'CORPORATE_REGISTRY',
            created_at          TIMESTAMPTZ   NOT NULL DEFAULT NOW()
        );
        CREATE INDEX IF NOT EXISTS idx_ubo_edges_tenant_child
            ON corporate_ownership_edges (tenant_id, child_company_name);
        CREATE INDEX IF NOT EXISTS idx_ubo_edges_tenant_parent
            ON corporate_ownership_edges (tenant_id, parent_entity_name);

        ALTER TABLE corporate_ownership_edges ENABLE ROW LEVEL SECURITY;
        ALTER TABLE corporate_ownership_edges FORCE ROW LEVEL SECURITY;
        DROP POLICY IF EXISTS corporate_ownership_edges_isolation ON corporate_ownership_edges;
        CREATE POLICY corporate_ownership_edges_isolation ON corporate_ownership_edges
            FOR ALL
            USING (tenant_id::text = NULLIF(current_setting('app.current_tenant_id', true), ''));

        -- 4. Case SLA Clock Pause Tracking (P2-1)
        ALTER TABLE cases
            ADD COLUMN IF NOT EXISTS sla_paused_at       TIMESTAMPTZ,
            ADD COLUMN IF NOT EXISTS sla_paused_seconds  INTEGER NOT NULL DEFAULT 0;
        """
    )


def downgrade() -> None:
    op.execute(
        """
        ALTER TABLE cases
            DROP COLUMN IF EXISTS sla_paused_seconds,
            DROP COLUMN IF EXISTS sla_paused_at;

        DROP TABLE IF EXISTS corporate_ownership_edges;
        DROP TABLE IF EXISTS auditor_rooms;
        DROP TABLE IF EXISTS rfi_requests;
        """
    )
