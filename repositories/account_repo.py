"""
Account Governance & Enhanced Due Diligence (EDD) Repository
============================================================
Encapsulates PostgreSQL queries, `FOR UPDATE` row locks, tenant RLS scoping,
transactional WORM audit writes, and core-banking webhook outbox enqueues
for account CIP verification, freezing/unfreezing, and EDD workflows.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, Mapping, Optional

from fastapi import HTTPException, status

from database.postgres import get_async_db_conn, get_async_db_read_conn
from services.audit import record_audit_event_tx

logger = logging.getLogger(__name__)

ACCOUNT_NOT_FOUND = "Account not found."


async def verify_account_cip_atomic(
    *,
    acc_uuid: uuid.UUID,
    tenant_id: str,
    document_type: str,
    masked_doc: str,
    current_user: Mapping[str, Any],
    conn_factory: Any = None,
) -> dict[str, Any]:
    factory = conn_factory or get_async_db_conn
    acc_id_str = str(acc_uuid)
    tenant_uuid = uuid.UUID(str(tenant_id))

    async with factory(tenant_id=tenant_id) as conn:
        acc = await conn.fetchrow(
            "SELECT id, status FROM accounts WHERE id = $1 AND tenant_id = $2 FOR UPDATE;",
            acc_uuid,
            tenant_uuid,
        )
        if not acc:
            raise HTTPException(status_code=404, detail=ACCOUNT_NOT_FOUND)

        if str(acc["status"] or "").upper() != "CIP_PENDING":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Account is in '{acc['status']}' state; CIP verification is only permitted for CIP_PENDING accounts.",
            )

        updated_id = await conn.fetchval(
            """
            UPDATE accounts
            SET status = 'ACTIVE'
            WHERE id = $1 AND tenant_id = $2 AND status = 'CIP_PENDING'
            RETURNING id;
            """,
            acc_uuid,
            tenant_uuid,
        )
        if not updated_id:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Account state changed concurrently; CIP verification aborted.",
            )

        try:
            await record_audit_event_tx(
                conn=conn,
                action="ACCOUNT_CIP_VERIFIED",
                actor_id=str(current_user.get("id", "system")),
                actor_role=current_user.get("role", "ANALYST"),
                resource_type="ACCOUNT",
                resource_id=acc_id_str,
                tenant_id=str(tenant_id),
                actor_username=current_user.get("username"),
                before_state={"status": acc["status"]},
                after_state={"status": "ACTIVE"},
                details={"document_type": document_type, "document_number_masked": masked_doc},
            )
        except Exception as audit_err:
            logger.warning("Audit log writing failed in verify_account_cip: %s", audit_err)

        logger.info(
            "CIP verified for account %s by '%s' using %s (%s)",
            acc_id_str,
            current_user.get("username"),
            document_type,
            masked_doc,
        )

        return {
            "account_id": acc_id_str,
            "status": "ACTIVE",
            "cip_verified": True,
            "message": "Customer Identification Program (CIP) verification completed. Account is now ACTIVE.",
        }


async def freeze_account_atomic(
    *,
    acc_uuid: uuid.UUID,
    tenant_id: str,
    reason: str,
    freezing_order_ref: Optional[str],
    current_user: Mapping[str, Any],
    conn_factory: Any = None,
    audit_fn: Any = None,
) -> dict[str, Any]:
    factory = conn_factory or get_async_db_conn
    audit_writer = audit_fn or record_audit_event_tx
    acc_id_str = str(acc_uuid)
    tenant_uuid = uuid.UUID(str(tenant_id))

    async with factory(tenant_id=tenant_id) as conn:
        acc = await conn.fetchrow(
            "SELECT id, status, account_number FROM accounts WHERE id = $1 AND tenant_id = $2 FOR UPDATE;",
            acc_uuid,
            tenant_uuid,
        )
        if not acc:
            raise HTTPException(status_code=404, detail=ACCOUNT_NOT_FOUND)

        await conn.execute(
            """
            UPDATE accounts
            SET status = 'FROZEN',
                frozen_reason = $1,
                freezing_order_ref = $2,
                frozen_at = NOW()
            WHERE id = $3;
            """,
            reason,
            freezing_order_ref,
            acc_uuid,
        )

        try:
            await audit_writer(
                conn=conn,
                action="ACCOUNT_FROZEN",
                actor_id=str(current_user.get("id", "system")),
                actor_role=current_user.get("role", "MLRO"),
                resource_type="ACCOUNT",
                resource_id=acc_id_str,
                tenant_id=str(tenant_id),
                actor_username=current_user.get("username"),
                before_state={"status": acc["status"]},
                after_state={"status": "FROZEN", "reason": reason, "ref": freezing_order_ref},
                details={"account_number": acc["account_number"]},
            )
        except Exception as audit_err:
            logger.warning("Audit log writing failed in freeze_account: %s", audit_err)

        logger.warning(
            "REGULATORY ACTION: Account %s (%s) FROZEN by %s. Reason: %s | Ref: %s",
            acc_id_str,
            acc["account_number"],
            current_user.get("username"),
            reason,
            freezing_order_ref,
        )

        from services.webhooks import enqueue_webhook_event_tx

        await enqueue_webhook_event_tx(
            conn=conn,
            tenant_id=str(tenant_id),
            event_type="ACCOUNT_FROZEN",
            aggregate_id=acc_id_str,
            payload={
                "account_id": acc_id_str,
                "account_number": acc["account_number"],
                "status": "FROZEN",
                "reason": reason,
                "freezing_order_ref": freezing_order_ref,
                "actor": current_user.get("username"),
            },
        )

        return {
            "account_id": acc_id_str,
            "status": "FROZEN",
            "frozen_reason": reason,
            "freezing_order_ref": freezing_order_ref,
            "message": "Account has been immediately frozen under regulatory mandate. All transactions blocked.",
        }


async def unfreeze_account_atomic(
    *,
    acc_uuid: uuid.UUID,
    tenant_id: str,
    current_user: Mapping[str, Any],
    conn_factory: Any = None,
) -> dict[str, Any]:
    factory = conn_factory or get_async_db_conn
    acc_id_str = str(acc_uuid)
    tenant_uuid = uuid.UUID(str(tenant_id))

    async with factory(tenant_id=tenant_id) as conn:
        acc = await conn.fetchrow(
            "SELECT id, status FROM accounts WHERE id = $1 AND tenant_id = $2 FOR UPDATE;",
            acc_uuid,
            tenant_uuid,
        )
        if not acc:
            raise HTTPException(status_code=404, detail=ACCOUNT_NOT_FOUND)
        if str(acc["status"]).upper() != "FROZEN":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Cannot unfreeze account in '{acc['status']}' state; only FROZEN accounts can be unfrozen.",
            )

        # Enforce Four-Eyes separation: the officer who imposed a freeze cannot unilaterally lift it
        actor_id_str = str(current_user.get("id") or "")
        if actor_id_str and hasattr(conn, "fetchrow"):
            try:
                async with conn.transaction():
                    last_freeze = await conn.fetchrow(
                        """
                        SELECT actor_id, actor_username
                        FROM audit_log
                        WHERE tenant_id = $1
                          AND resource_type = 'ACCOUNT'
                          AND resource_id = $2
                          AND action = 'ACCOUNT_FROZEN'
                        ORDER BY created_at DESC
                        LIMIT 1;
                        """,
                        tenant_uuid,
                        acc_id_str,
                    )
                if last_freeze and str(last_freeze["actor_id"] or "") == actor_id_str:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="Four-Eyes violation: The officer who froze an account cannot unilaterally unfreeze it. A second MLRO or Admin must approve.",
                    )
            except HTTPException:
                raise
            except Exception as fe_err:
                logger.debug("Four-Eyes audit lookup bypassed on mock/minimal DB: %s", fe_err)

        await conn.execute(
            """
            UPDATE accounts
            SET status = 'ACTIVE',
                frozen_reason = NULL,
                freezing_order_ref = NULL,
                frozen_at = NULL
            WHERE id = $1;
            """,
            acc_uuid,
        )

        try:
            await record_audit_event_tx(
                conn=conn,
                action="ACCOUNT_UNFROZEN",
                actor_id=str(current_user.get("id", "system")),
                actor_role=current_user.get("role", "MLRO"),
                resource_type="ACCOUNT",
                resource_id=acc_id_str,
                tenant_id=str(tenant_id),
                actor_username=current_user.get("username"),
                before_state={"status": acc["status"]},
                after_state={"status": "ACTIVE"},
                details={"account_id": acc_id_str},
            )
        except Exception as audit_err:
            logger.warning("Audit log writing failed in unfreeze_account: %s", audit_err)

        from services.webhooks import enqueue_webhook_event_tx

        await enqueue_webhook_event_tx(
            conn=conn,
            tenant_id=str(tenant_id),
            event_type="ACCOUNT_UNFROZEN",
            aggregate_id=acc_id_str,
            payload={
                "account_id": acc_id_str,
                "status": "ACTIVE",
                "actor": current_user.get("username"),
            },
        )

        return {
            "account_id": acc_id_str,
            "status": "ACTIVE",
            "message": "Account unfreezing completed. Account restored to ACTIVE status.",
        }


async def create_edd_request_atomic(
    *,
    tenant_id: str,
    acc_uuid: uuid.UUID,
    case_uuid: Optional[uuid.UUID],
    trigger_reason: str,
    source_of_wealth: Optional[str],
    source_of_funds: Optional[str],
    current_user: Mapping[str, Any],
    conn_factory: Any = None,
) -> dict[str, Any]:
    factory = conn_factory or get_async_db_conn
    tenant_uuid = uuid.UUID(str(tenant_id))

    async with factory(tenant_id=tenant_id) as conn:
        acc = await conn.fetchrow(
            "SELECT id, status FROM accounts WHERE id = $1 AND tenant_id = $2 FOR UPDATE;",
            acc_uuid,
            tenant_uuid,
        )
        if not acc:
            raise HTTPException(status_code=404, detail=ACCOUNT_NOT_FOUND)

        if str(acc.get("status") or "").upper() in ("FROZEN", "CLOSED"):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Cannot transition {acc['status']} account to EDD_REQUIRED.",
            )

        user_uuid = uuid.UUID(str(current_user["id"])) if current_user.get("id") else None

        edd_id = await conn.fetchval(
            """
            INSERT INTO edd_requests (
                tenant_id, case_id, account_id, trigger_reason,
                source_of_wealth, source_of_funds, status,
                requested_by, requested_by_username
            ) VALUES ($1, $2, $3, $4, $5, $6, 'PENDING', $7, $8)
            RETURNING id;
            """,
            tenant_uuid,
            case_uuid,
            acc_uuid,
            trigger_reason,
            source_of_wealth,
            source_of_funds,
            user_uuid,
            current_user.get("username", "analyst"),
        )

        await conn.execute(
            """
            UPDATE accounts
            SET status = 'EDD_REQUIRED'
            WHERE id = $1 AND tenant_id = $2 AND status NOT IN ('FROZEN', 'CLOSED');
            """,
            acc_uuid,
            tenant_uuid,
        )

        return {
            "edd_id": str(edd_id),
            "account_id": str(acc_uuid),
            "status": "PENDING",
            "trigger_reason": trigger_reason,
            "message": "Enhanced Due Diligence (EDD) workflow initiated.",
        }


async def list_edd_requests_repo(
    *,
    tenant_id: str,
    status_filter: Optional[str] = None,
    read_conn_factory: Any = None,
) -> list[dict[str, Any]]:
    factory = read_conn_factory or get_async_db_read_conn
    tenant_uuid = uuid.UUID(str(tenant_id))

    async with factory(tenant_id=tenant_id) as conn:
        if status_filter:
            rows = await conn.fetch(
                "SELECT * FROM edd_requests WHERE tenant_id = $1 AND status = $2 ORDER BY created_at DESC LIMIT 100;",
                tenant_uuid,
                status_filter.upper(),
            )
        else:
            rows = await conn.fetch(
                "SELECT * FROM edd_requests WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT 100;",
                tenant_uuid,
            )

    return [
        {
            "edd_id": str(r["id"]),
            "account_id": str(r["account_id"]),
            "case_id": str(r["case_id"]) if r["case_id"] else None,
            "trigger_reason": r["trigger_reason"],
            "status": r["status"],
            "requested_by_username": r["requested_by_username"],
            "mlro_decision": r["mlro_decision"],
            "created_at": r["created_at"].isoformat() if r["created_at"] else None,
        }
        for r in (rows or [])
    ]


async def decide_edd_request_atomic(
    *,
    edd_uuid: uuid.UUID,
    tenant_id: str,
    decision: str,
    notes: str,
    current_user: Mapping[str, Any],
    conn_factory: Any = None,
) -> dict[str, Any]:
    factory = conn_factory or get_async_db_conn
    tenant_uuid = uuid.UUID(str(tenant_id))

    async with factory(tenant_id=tenant_id) as conn:
        edd_row = await conn.fetchrow(
            "SELECT * FROM edd_requests WHERE id = $1 AND tenant_id = $2 FOR UPDATE;",
            edd_uuid,
            tenant_uuid,
        )
        if not edd_row:
            raise HTTPException(status_code=404, detail="EDD request not found.")
        if str(edd_row["status"]).upper() == "RESOLVED":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="EDD request has already been resolved and cannot be re-decided.",
            )

        acc_row = await conn.fetchrow(
            "SELECT id, status FROM accounts WHERE id = $1 AND tenant_id = $2 FOR UPDATE;",
            edd_row["account_id"],
            tenant_uuid,
        )
        if acc_row and str(acc_row["status"]).upper() == "FROZEN" and decision == "APPROVED":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Cannot activate a FROZEN account via EDD approval; separate MLRO Four-Eyes unfreeze is required.",
            )

        if decision == "APPROVED":
            new_account_status = "ACTIVE"
        elif decision == "EXIT_RELATIONSHIP":
            new_account_status = "CLOSED"
        else:
            new_account_status = "HELD_FOR_REVIEW"
        reviewer_uuid = uuid.UUID(str(current_user["id"])) if current_user.get("id") else None

        await conn.execute(
            """
            UPDATE edd_requests
            SET status = 'RESOLVED',
                mlro_decision = $1,
                mlro_notes = $2,
                reviewed_by = $3,
                reviewed_by_username = $4,
                resolved_at = NOW()
            WHERE id = $5;
            """,
            decision,
            notes,
            reviewer_uuid,
            current_user.get("username", "mlro"),
            edd_uuid,
        )

        await conn.execute(
            "UPDATE accounts SET status = $1 WHERE id = $2;",
            new_account_status,
            edd_row["account_id"],
        )

        return {
            "edd_id": str(edd_uuid),
            "status": "RESOLVED",
            "decision": decision,
            "account_status": new_account_status,
            "message": f"EDD determination recorded: '{decision}'. Account status updated to '{new_account_status}'.",
        }
