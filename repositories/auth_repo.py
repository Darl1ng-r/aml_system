"""
Authentication, Identity, MFA & Enterprise OIDC SSO Repository
==============================================================
Encapsulates all PostgreSQL user, session revocation, MFA, and OIDC SSO
provider queries and `FOR UPDATE` locking.
Resolves `database.postgres.get_async_db_conn` / `get_async_db_read_conn`
dynamically when `conn_factory` is omitted so both module-level and
`database.postgres.*` test monkeypatches work seamlessly.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from typing import Any, Callable, Mapping, Optional

from fastapi import HTTPException, status

import database.postgres as _pg
from services.audit import record_audit_event_tx

logger = logging.getLogger(__name__)


def _write_factory(conn_factory: Any = None) -> Any:
    return conn_factory or _pg.get_async_db_conn


def _read_factory(read_conn_factory: Any = None) -> Any:
    return read_conn_factory or _pg.get_async_db_read_conn


# ── Local & Supabase Auth Users ───────────────────────────────────────────────

async def upsert_supabase_login_user_atomic(
    *,
    user_id: str,
    username: str,
    role: str,
    tenant_id: str,
    hashed_pw: str,
    conn_factory: Any = None,
) -> tuple[bool, int]:
    """Returns `(is_mfa_enabled, token_version)`; raises 401 if local user is inactive."""
    is_mfa_enabled = False
    token_version = 1
    factory = _write_factory(conn_factory)
    async with factory(tenant_id=tenant_id, auth_lookup=True) as conn:
        existing_local = await conn.fetchrow(
            "SELECT mfa_enabled, is_active, token_version FROM users WHERE id = $1;",
            user_id,
        )
        # Note: asyncpg.Record is NOT a subclass of dict (issubclass(asyncpg.Record, dict) == False).
        # Use Mapping / non-None check so real PostgreSQL rows never silently skip is_active/MFA enforcement!
        if existing_local is not None and (isinstance(existing_local, Mapping) or hasattr(existing_local, "keys")):
            local_map = dict(existing_local)
            if local_map.get("is_active") is False:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Incorrect username or password",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            is_mfa_enabled = bool(local_map.get("mfa_enabled", False))
            token_version = int(local_map.get("token_version") or 1)

        await conn.execute(
            """
            INSERT INTO users (id, username, role, tenant_id, password_hash)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (id) DO UPDATE SET
                role = EXCLUDED.role,
                username = EXCLUDED.username,
                tenant_id = EXCLUDED.tenant_id,
                password_hash = EXCLUDED.password_hash;
            """,
            user_id,
            username,
            role,
            tenant_id,
            hashed_pw,
        )
    return is_mfa_enabled, token_version


async def authenticate_local_user_repo(
    *,
    username: str,
    password: str,
    verify_and_rehash_fn: Callable[[str, str], tuple[bool, bool]],
    hash_password_fn: Callable[[str], str],
    on_failure_fn: Callable[[str, Any, str], Any],
    conn_factory: Any = None,
) -> dict[str, Any]:
    factory = _write_factory(conn_factory)
    async with factory(auth_lookup=True) as conn:
        local_user = await conn.fetchrow(
            """
            SELECT id, role, password_hash, tenant_id, mfa_enabled, token_version
            FROM users
            WHERE username = $1 AND (is_active IS NULL OR is_active = true);
            """,
            username,
        )

        if not local_user or not local_user["password_hash"]:
            await on_failure_fn(username, None, password)

        pw_valid, needs_rehash = await asyncio.to_thread(
            verify_and_rehash_fn, password, local_user["password_hash"]
        )
        if not pw_valid:
            await on_failure_fn(username, local_user, password)

        if needs_rehash:
            try:
                new_argon2_hash = await asyncio.to_thread(hash_password_fn, password)
                await conn.execute(
                    "UPDATE users SET password_hash = $1 WHERE id = $2;",
                    new_argon2_hash,
                    local_user["id"],
                )
                logger.info("Transparently upgraded password hash to Argon2id for user %s", username)
            except Exception as rehash_err:
                logger.warning("Failed to in-place upgrade password hash: %s", rehash_err)

        local_user_id = str(local_user["id"])
        local_role = local_user["role"] or "ANALYST"
        tenant_id = (
            str(local_user["tenant_id"])
            if local_user["tenant_id"]
            else "00000000-0000-0000-0000-000000000001"
        )
        is_mfa_enabled = bool(local_user["mfa_enabled"]) if "mfa_enabled" in local_user.keys() else False
        token_version = (
            local_user["token_version"]
            if "token_version" in local_user.keys() and local_user["token_version"]
            else 1
        )
    return {
        "user_id": local_user_id,
        "role": local_role,
        "tenant_id": tenant_id,
        "is_mfa_enabled": is_mfa_enabled,
        "token_version": token_version,
    }


async def upsert_supabase_signup_user_repo(
    *,
    supabase_user_id: str,
    username: str,
    assigned_role: str,
    default_tenant_id: str,
    hashed_pw: str,
    conn_factory: Any = None,
) -> None:
    factory = _write_factory(conn_factory)
    async with factory(tenant_id=default_tenant_id) as conn:
        await conn.execute(
            """
            INSERT INTO users (id, username, role, tenant_id, password_hash)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (id) DO UPDATE SET
                username = EXCLUDED.username,
                role = EXCLUDED.role,
                password_hash = EXCLUDED.password_hash;
            """,
            supabase_user_id,
            username,
            assigned_role,
            default_tenant_id,
            hashed_pw,
        )


async def create_local_user_repo(
    *,
    username: str,
    assigned_role: str,
    tenant_id: str,
    hashed_pw: str,
    conflict_status_code: int = status.HTTP_400_BAD_REQUEST,
    conflict_detail: str = "Username already registered or invalid registration data",
    conn_factory: Any = None,
) -> str:
    factory = _write_factory(conn_factory)
    async with factory(tenant_id=tenant_id) as conn:
        existing_user = await conn.fetchrow(
            "SELECT id FROM users WHERE username = $1;",
            username,
        )
        if existing_user:
            raise HTTPException(status_code=conflict_status_code, detail=conflict_detail)

        local_user_id = str(uuid.uuid4())
        await conn.execute(
            """
            INSERT INTO users (id, username, role, tenant_id, password_hash)
            VALUES ($1, $2, $3, $4, $5);
            """,
            local_user_id,
            username,
            assigned_role,
            tenant_id,
            hashed_pw,
        )
    return local_user_id


async def list_tenant_users_repo(
    *,
    tenant_id: str,
    limit: int,
    offset: int,
    cursor: Optional[str] = None,
    conn_factory: Any = None,
) -> list[Any]:
    from database.pagination import decode_keyset_cursor, validate_legacy_offset

    factory = _write_factory(conn_factory)
    async with factory(tenant_id=tenant_id) as conn:
        if cursor:
            c_ts, c_id = decode_keyset_cursor(cursor)
            rows = await conn.fetch(
                """
                SELECT id, username, role, tenant_id, mfa_enabled, created_at
                FROM users
                WHERE tenant_id = $1 AND (created_at, id) < ($2, $3)
                ORDER BY created_at DESC, id DESC
                LIMIT $4;
                """,
                uuid.UUID(str(tenant_id)),
                c_ts,
                c_id,
                limit + 1,
            )
            return list(rows or [])

        safe_offset = validate_legacy_offset(offset)
        rows = await conn.fetch(
            """
            SELECT id, username, role, tenant_id, mfa_enabled, created_at
            FROM users
            WHERE tenant_id = $1
            ORDER BY created_at DESC, id DESC
            LIMIT $2 OFFSET $3;
            """,
            uuid.UUID(str(tenant_id)),
            limit,
            safe_offset,
        )
    return list(rows or [])


async def update_user_role_atomic(
    *,
    u_uuid: uuid.UUID,
    new_role: str,
    caller_role: str,
    tenant_id: str,
    conn_factory: Any = None,
) -> dict[str, Any]:
    factory = _write_factory(conn_factory)
    async with factory(tenant_id=tenant_id, auth_lookup=(caller_role == "SUPER_ADMIN")) as conn:
        if caller_role == "SUPER_ADMIN":
            row = await conn.fetchrow("SELECT username, role, tenant_id FROM users WHERE id = $1 FOR UPDATE;", u_uuid)
        else:
            row = await conn.fetchrow(
                "SELECT username, role, tenant_id FROM users WHERE id = $1 AND tenant_id = $2 FOR UPDATE;",
                u_uuid,
                uuid.UUID(str(tenant_id)),
            )
        if not row:
            raise HTTPException(status_code=404, detail="User not found")

        if row["role"] == "SUPER_ADMIN" and caller_role != "SUPER_ADMIN":
            raise HTTPException(status_code=403, detail="Only SUPER_ADMIN can modify a SUPER_ADMIN account.")

        target_tenant = str(row.get("tenant_id") or tenant_id)
        if caller_role == "SUPER_ADMIN":
            await conn.execute("UPDATE users SET role = $1 WHERE id = $2;", new_role, u_uuid)
        else:
            await conn.execute(
                "UPDATE users SET role = $1 WHERE id = $2 AND tenant_id = $3;",
                new_role,
                u_uuid,
                uuid.UUID(str(tenant_id)),
            )
    return {"username": row["username"], "old_role": row["role"], "target_tenant": target_tenant}


async def bump_user_token_version_on_compromise_repo(
    *,
    sub: str,
    tenant_id: str,
    conn_factory: Any = None,
) -> Optional[int]:
    factory = _write_factory(conn_factory)
    async with factory(tenant_id=tenant_id, auth_lookup=True) as conn:
        new_ver = await conn.fetchval(
            """
            UPDATE users
            SET token_version = COALESCE(token_version, 1) + 1
            WHERE id = $1
            RETURNING token_version;
            """,
            sub,
        )
        return int(new_ver) if isinstance(new_ver, (int, float, str)) else None


async def fetch_authoritative_user_for_refresh_repo(
    *,
    u_uuid: uuid.UUID,
    fallback_tenant_id: str,
    conn_factory: Any = None,
) -> Any:
    factory = _write_factory(conn_factory)
    async with factory(tenant_id=fallback_tenant_id, auth_lookup=True) as conn:
        return await conn.fetchrow(
            "SELECT role, tenant_id, token_version, is_active FROM users WHERE id = $1;",
            u_uuid,
        )


async def check_username_exists_repo(
    *,
    clean_username: str,
    conn_factory: Any = None,
) -> bool:
    factory = _write_factory(conn_factory)
    async with factory(auth_lookup=True) as conn:
        exists = await conn.fetchval(
            "SELECT 1 FROM users WHERE LOWER(username) = LOWER($1);",
            clean_username,
        )
    return bool(exists)


async def fetch_target_user_for_session_revoke_repo(
    *,
    u_uuid: uuid.UUID,
    caller_role: str,
    tenant_id: str,
    conn_factory: Any = None,
) -> Any:
    factory = _write_factory(conn_factory)
    async with factory(tenant_id=tenant_id, auth_lookup=(caller_role == "SUPER_ADMIN")) as conn:
        if caller_role == "SUPER_ADMIN":
            return await conn.fetchrow("SELECT username, role, tenant_id FROM users WHERE id = $1;", u_uuid)
        return await conn.fetchrow(
            "SELECT username, role, tenant_id FROM users WHERE id = $1 AND tenant_id = $2;",
            u_uuid,
            uuid.UUID(str(tenant_id)),
        )


# ── MFA Repository Operations ─────────────────────────────────────────────────

async def fetch_user_mfa_state_repo(
    *,
    user_id: str,
    tenant_id: Optional[str],
    conn_factory: Any = None,
) -> Any:
    factory = _write_factory(conn_factory)
    async with factory(tenant_id=tenant_id or None, auth_lookup=True) as conn:
        return await conn.fetchrow(
            "SELECT mfa_enabled, mfa_secret, password_hash FROM users WHERE id = $1;",
            user_id,
        )


async def enable_user_mfa_repo(
    *,
    user_id: str,
    tenant_id: Optional[str],
    encrypted_secret: str,
    hashed_codes: list[str],
    conn_factory: Any = None,
) -> None:
    factory = _write_factory(conn_factory)
    async with factory(tenant_id=tenant_id or None, auth_lookup=True) as conn:
        await conn.execute(
            """
            UPDATE users
            SET mfa_enabled = TRUE, mfa_secret = $1, recovery_codes = $2::jsonb
            WHERE id = $3;
            """,
            encrypted_secret,
            json.dumps(hashed_codes),
            user_id,
        )


async def verify_user_mfa_ticket_atomic(
    *,
    user_id: str,
    tenant_id: str,
    default_role: str,
    username: str,
    code: str,
    redis: Any,
    ticket_key: str,
    attempts_key: str,
    max_attempts: int,
    decrypt_secret_fn: Callable[[str, Optional[str]], str],
    verify_totp_or_recovery_fn: Callable[..., Any],
    record_failed_login_fn: Callable[..., Any],
    conn_factory: Any = None,
) -> tuple[str, int]:
    factory = _write_factory(conn_factory)
    async with factory(tenant_id=tenant_id, auth_lookup=True) as conn:
        user_row = await conn.fetchrow(
            "SELECT mfa_secret, recovery_codes, token_version, role, is_active FROM users WHERE id = $1 FOR UPDATE;",
            user_id,
        )
        if not user_row or not user_row["mfa_secret"]:
            raise HTTPException(status_code=400, detail="MFA not configured for user.")
        if user_row.get("is_active") is False:
            await redis.delete(ticket_key, attempts_key)
            raise HTTPException(status_code=401, detail="Account is disabled.")

        role = user_row.get("role") or default_role
        token_version = int(user_row.get("token_version") or 1)
        secret = decrypt_secret_fn(user_row["mfa_secret"], tenant_id)
        raw_recovery = user_row["recovery_codes"]
        recovery_hashes = json.loads(raw_recovery) if isinstance(raw_recovery, str) else (raw_recovery or [])

        verified = await verify_totp_or_recovery_fn(redis, conn, user_id, secret, recovery_hashes, code)
        if not verified:
            fail_count = await redis.incr(attempts_key)
            await redis.expire(attempts_key, 300)
            if int(fail_count) >= max_attempts:
                await redis.delete(ticket_key)
                await redis.delete(attempts_key)
                await record_failed_login_fn(username, tenant_id=tenant_id)
                raise HTTPException(
                    status_code=401,
                    detail="Too many failed MFA verification attempts. Please log in again.",
                )
            raise HTTPException(status_code=401, detail="Invalid verification code or recovery code.")
    return role, token_version


async def update_user_recovery_codes_tx(conn: Any, user_id: str, remaining_hashes: list[str]) -> None:
    await conn.execute(
        "UPDATE users SET recovery_codes = $1::jsonb WHERE id = $2;",
        json.dumps(remaining_hashes),
        user_id,
    )


async def disable_user_mfa_atomic(
    *,
    user_id: str,
    tenant_id: Optional[str],
    username: str,
    password: str,
    verify_password_fn: Callable[[str, str], bool],
    record_failed_login_fn: Callable[..., Any],
    conn_factory: Any = None,
) -> None:
    factory = _write_factory(conn_factory)
    async with factory(tenant_id=tenant_id or None, auth_lookup=True) as conn:
        row = await conn.fetchrow("SELECT password_hash FROM users WHERE id = $1 FOR UPDATE;", user_id)
        pw_valid = False
        if row and row["password_hash"]:
            pw_valid = await asyncio.to_thread(verify_password_fn, password, row["password_hash"])
        if not pw_valid:
            if username:
                await record_failed_login_fn(username, tenant_id=tenant_id or None)
            raise HTTPException(
                status_code=401,
                detail="Incorrect password. Cannot disable two-factor authentication.",
            )

        await conn.execute(
            """
            UPDATE users
            SET mfa_enabled = FALSE, mfa_secret = NULL, recovery_codes = '[]'::jsonb
            WHERE id = $1;
            """,
            user_id,
        )


# ── Enterprise OIDC SSO Providers & JIT Provisioning ──────────────────────────

async def list_public_sso_providers_repo(
    *,
    tenant_id: str,
    read_conn_factory: Any = None,
) -> list[Any]:
    factory = _read_factory(read_conn_factory)
    async with factory(tenant_id=tenant_id) as conn:
        rows = await conn.fetch(
            """
            SELECT id, provider_name
            FROM sso_providers
            WHERE enabled = TRUE
            ORDER BY provider_name ASC;
            """
        )
    return list(rows or [])


async def list_sso_providers_admin_repo(
    *,
    tenant_id: str,
    read_conn_factory: Any = None,
) -> list[Any]:
    factory = _read_factory(read_conn_factory)
    async with factory(tenant_id=tenant_id) as conn:
        rows = await conn.fetch(
            """
            SELECT id, provider_name, issuer_url, client_id, scopes,
                   group_role_mapping, default_role, enabled, created_at
            FROM sso_providers
            ORDER BY created_at DESC;
            """
        )
    return list(rows or [])


async def create_sso_provider_repo(
    *,
    tenant_id: str,
    safe_name: str,
    safe_issuer: str,
    client_id: str,
    enc_secret: str,
    scopes: str,
    group_role_mapping: Mapping[str, Any],
    default_role: str,
    enabled: bool,
    conn_factory: Any = None,
) -> uuid.UUID:
    factory = _write_factory(conn_factory)
    async with factory(tenant_id=tenant_id) as conn:
        return await conn.fetchval(
            """
            INSERT INTO sso_providers (
                tenant_id, provider_name, issuer_url, client_id, client_secret_enc,
                scopes, group_role_mapping, default_role, enabled
            )
            VALUES ($1::uuid, $2, $3, $4, $5, $6, $7::jsonb, $8, $9)
            RETURNING id;
            """,
            str(tenant_id),
            safe_name,
            safe_issuer,
            client_id,
            enc_secret,
            scopes,
            json.dumps(dict(group_role_mapping)),
            default_role,
            enabled,
        )


async def delete_sso_provider_atomic(
    *,
    p_uuid: uuid.UUID,
    tenant_id: str,
    current_user: Mapping[str, Any],
    conn_factory: Any = None,
) -> None:
    factory = _write_factory(conn_factory)
    async with factory(tenant_id=tenant_id) as conn:
        deleted = await conn.fetchval("DELETE FROM sso_providers WHERE id = $1 RETURNING id;", p_uuid)
        if not deleted:
            raise HTTPException(status_code=404, detail="SSO provider not found.")
        await record_audit_event_tx(
            conn=conn,
            action="DELETE_SSO_PROVIDER",
            actor_id=str(current_user.get("id", "")),
            actor_username=current_user.get("username", "admin"),
            actor_role=current_user.get("role", "ADMIN"),
            resource_type="SSO_PROVIDER",
            resource_id=str(p_uuid),
            tenant_id=str(tenant_id),
            details={"provider_id": str(p_uuid)},
        )


async def fetch_enabled_sso_provider_repo(
    *,
    p_uuid: uuid.UUID,
    tenant_id: str,
    read_conn_factory: Any = None,
) -> Optional[dict[str, Any]]:
    factory = _read_factory(read_conn_factory)
    async with factory(tenant_id=tenant_id) as conn:
        row = await conn.fetchrow(
            """
            SELECT id, tenant_id, provider_name, issuer_url, client_id, client_secret_enc,
                   scopes, group_role_mapping, default_role, enabled
            FROM sso_providers
            WHERE id = $1 AND enabled = TRUE;
            """,
            p_uuid,
        )
        return dict(row) if row else None


async def jit_provision_sso_user_atomic(
    *,
    user_id: str,
    username: str,
    assigned_role: str,
    tenant_id: str,
    sso_marker: str,
    conn_factory: Any = None,
) -> tuple[str, int]:
    """Returns `(resolved_username, token_version)` for deterministic SSO user provisioning."""
    factory = _write_factory(conn_factory)
    resolved_username = username
    async with factory(tenant_id=tenant_id) as conn:
        existing = await conn.fetchrow(
            "SELECT id, token_version, password_hash, is_active FROM users WHERE id = $1::uuid AND tenant_id = $2::uuid FOR UPDATE;",
            user_id,
            tenant_id,
        )
        if existing:
            if existing.get("is_active") is False:
                raise HTTPException(status_code=403, detail="SSO user account has been disabled.")
            if not str(existing.get("password_hash") or "").startswith("sso_managed:"):
                raise HTTPException(status_code=409, detail="Account collision with local user denied.")
            token_version = int(existing["token_version"] or 1)
            await conn.execute(
                "UPDATE users SET role = $1 WHERE id = $2::uuid AND tenant_id = $3::uuid;",
                assigned_role,
                user_id,
                tenant_id,
            )
        else:
            collision = await conn.fetchrow("SELECT id FROM users WHERE username = $1;", resolved_username)
            if collision:
                resolved_username = f"{resolved_username}_sso_{user_id[:6]}"
            token_version = 1
            await conn.execute(
                """
                INSERT INTO users (id, username, role, tenant_id, password_hash)
                VALUES ($1::uuid, $2, $3, $4::uuid, $5);
                """,
                user_id,
                resolved_username,
                assigned_role,
                tenant_id,
                sso_marker,
            )
    return resolved_username, token_version
