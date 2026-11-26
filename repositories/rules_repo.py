"""
Rules Engine Configuration Repository
=====================================
Encapsulates PostgreSQL persistence, optimistic-concurrency `FOR UPDATE` locking,
rule version history, shadow hit queries, and global rules configuration snapshots.
"""

from __future__ import annotations

import json
import logging
import uuid
from typing import Any, Callable, Mapping, Optional

from fastapi import HTTPException, status

from database.postgres import get_async_db_conn, get_async_db_read_conn
from services.audit import record_audit_event_tx
from services.http_cache import build_version_etag, check_if_match

logger = logging.getLogger(__name__)


async def list_rule_configs_repo(
    *,
    tenant_id: str,
    conn_factory: Any = None,
) -> list[Any]:
    factory = conn_factory or get_async_db_conn
    tenant_uuid = uuid.UUID(str(tenant_id))
    async with factory(tenant_id=tenant_id) as conn:
        return await conn.fetch(
            """
            SELECT id, rule_name, enabled, mode, config, shadow_config, version,
                   updated_by_name, updated_at, description
            FROM rule_configs
            WHERE tenant_id = $1
            ORDER BY rule_name ASC;
            """,
            tenant_uuid,
        )


async def patch_rule_config_atomic(
    *,
    tenant_id: str,
    rule_name: str,
    payload: Any,
    request: Any,
    user_id: Any,
    user_uuid: Optional[uuid.UUID],
    username: str,
    actor_role: str,
    compute_updates_fn: Callable[[Any, Any], tuple[bool, dict, int]],
    conn_factory: Any = None,
) -> dict[str, Any]:
    factory = conn_factory or get_async_db_conn
    tenant_uuid = uuid.UUID(str(tenant_id))

    async with factory(tenant_id=tenant_id) as conn:
        current_row = await conn.fetchrow(
            """
            SELECT id, enabled, mode, config, shadow_config, version
            FROM rule_configs
            WHERE tenant_id = $1 AND rule_name = $2
            FOR UPDATE;
            """,
            tenant_uuid,
            rule_name,
        )

        current_version = (
            int(current_row["version"])
            if (current_row and "version" in current_row and current_row["version"] is not None)
            else 0
        )
        current_etag = build_version_etag("rule", current_version)
        check_if_match(request, current_etag, resource_label=f"rule '{rule_name}'")
        if payload.expected_version is not None and payload.expected_version != current_version:
            raise HTTPException(
                status_code=status.HTTP_412_PRECONDITION_FAILED,
                detail=(
                    f"Precondition Failed: rule '{rule_name}' is at version {current_version}, "
                    f"not {payload.expected_version}. Reload the latest configuration and retry."
                ),
                headers={"ETag": current_etag},
            )

        new_enabled, new_config, new_version = compute_updates_fn(current_row, payload)
        existing_mode = (current_row["mode"] if current_row and "mode" in current_row else "ACTIVE") or "ACTIVE"
        new_mode = payload.mode or ("DISABLED" if payload.enabled is False else existing_mode)
        if payload.mode == "DISABLED":
            new_enabled = False
        elif payload.mode in ("ACTIVE", "SHADOW") and payload.enabled is None:
            new_enabled = True

        existing_shadow = current_row["shadow_config"] if (current_row and "shadow_config" in current_row) else None
        new_shadow = payload.shadow_config if payload.shadow_config is not None else existing_shadow
        new_shadow_json = json.dumps(new_shadow) if isinstance(new_shadow, dict) else new_shadow

        saved_id = await conn.fetchval(
            """
            INSERT INTO rule_configs (
                tenant_id, rule_name, enabled, mode, config, shadow_config, version,
                updated_by, updated_by_name, updated_at
            )
            VALUES ($1, $2, $3, $4, $5::jsonb, $6::jsonb, $7, $8, $9, NOW())
            ON CONFLICT (tenant_id, rule_name) DO UPDATE
            SET enabled = EXCLUDED.enabled,
                mode = EXCLUDED.mode,
                config = EXCLUDED.config,
                shadow_config = EXCLUDED.shadow_config,
                version = EXCLUDED.version,
                updated_by = EXCLUDED.updated_by,
                updated_by_name = EXCLUDED.updated_by_name,
                updated_at = NOW()
            RETURNING id;
            """,
            tenant_uuid,
            rule_name,
            new_enabled,
            new_mode,
            json.dumps(new_config),
            new_shadow_json,
            new_version,
            user_uuid,
            username,
        )

        await conn.execute(
            """
            INSERT INTO rule_config_history (
                rule_config_id, tenant_id, rule_name, enabled, config,
                version, changed_by, changed_by_name, change_reason
            )
            VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7, $8, $9);
            """,
            saved_id,
            tenant_uuid,
            rule_name,
            new_enabled,
            json.dumps(new_config),
            new_version,
            user_uuid,
            username,
            payload.change_reason or "Rule adjusted",
        )

        try:
            await record_audit_event_tx(
                conn=conn,
                action="UPDATE_RULE",
                actor_id=str(user_id or username),
                actor_username=username,
                actor_role=actor_role,
                resource_type="RULE",
                resource_id=rule_name,
                tenant_id=str(tenant_id),
                details={"rule_name": rule_name, "version": new_version, "enabled": new_enabled, "mode": new_mode},
            )
        except Exception as audit_err:
            logger.warning("Transactional audit write skipped in patch_rule: %s", audit_err)

    return {
        "new_enabled": new_enabled,
        "new_mode": new_mode,
        "new_config": new_config,
        "new_version": new_version,
        "new_shadow": new_shadow,
    }


async def list_rule_shadow_hits_repo(
    *,
    tenant_id: str,
    rule_name: str,
    read_conn_factory: Any = None,
) -> list[Any]:
    factory = read_conn_factory or get_async_db_read_conn
    async with factory(tenant_id=tenant_id) as conn:
        return await conn.fetch(
            """
            SELECT id, rule_name, transaction_id, sender_account_id,
                   amount_base_usd, rule_version, matched_reason, created_at
            FROM rule_shadow_hits
            WHERE rule_name = $1 AND tenant_id = $2::uuid
            ORDER BY created_at DESC
            LIMIT 100;
            """,
            rule_name.upper().strip(),
            str(tenant_id),
        )


async def get_rule_history_repo(
    *,
    tenant_id: str,
    rule_name: str,
    conn_factory: Any = None,
) -> list[Any]:
    factory = conn_factory or get_async_db_conn
    tenant_uuid = uuid.UUID(str(tenant_id))
    async with factory(tenant_id=tenant_id) as conn:
        return await conn.fetch(
            """
            SELECT id, version, enabled, config, changed_by_name, changed_at, change_reason
            FROM rule_config_history
            WHERE tenant_id = $1 AND rule_name = $2
            ORDER BY version DESC;
            """,
            tenant_uuid,
            rule_name,
        )


async def persist_global_rules_config_atomic(
    *,
    payload: Mapping[str, Any],
    current_user: Mapping[str, Any],
    tenant_id: Optional[str],
    conn_factory: Any = None,
) -> None:
    factory = conn_factory or get_async_db_conn
    async with factory() as conn:
        await conn.execute(
            """
            INSERT INTO rules_configuration (rules_json, updated_by)
            VALUES ($1, $2);
            """,
            json.dumps(dict(payload)),
            current_user.get("username", "SUPER_ADMIN"),
        )
        try:
            await record_audit_event_tx(
                conn=conn,
                action="UPDATE_GLOBAL_RULES_CONFIG",
                actor_id=str(current_user.get("id") or current_user.get("username") or "super_admin"),
                actor_username=current_user.get("username", "SUPER_ADMIN"),
                actor_role=current_user.get("role", "SUPER_ADMIN"),
                resource_type="GLOBAL_RULES_CONFIG",
                resource_id="rules_config.json",
                tenant_id=tenant_id,
                details={"rule_keys": list((payload.get("rules") or {}).keys())},
            )
        except Exception:
            pass
