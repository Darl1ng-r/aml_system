"""
Machine-to-Machine (M2M) API Key Management Service
===================================================
Provides cryptographically secure API key generation, verification, and scoping
for automated transaction ingestion and batch screening consumers (GAP-21).
"""

import hashlib
import hmac
import secrets
import uuid
from typing import Optional, Tuple, List, Dict, Any
from datetime import datetime, timezone
from fastapi import Request, HTTPException, status
from database.postgres import get_async_db_conn

KEY_PREFIX_LENGTH = 8
SECRET_LENGTH = 32


def hash_api_secret(secret: str) -> str:
    """Computes SHA-256 hash of API secret for safe DB persistence."""
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


async def generate_api_key(
    tenant_id: str,
    name: str,
    scopes: List[str],
    created_by: Optional[str] = None
) -> Tuple[Dict[str, Any], str]:
    """
    Generates a secure API key in format: aml_live_<prefix>_<secret>
    Returns:
        (key_metadata_dict, full_raw_key_string)
    """
    prefix = secrets.token_hex(KEY_PREFIX_LENGTH // 2)
    secret = secrets.token_hex(SECRET_LENGTH)
    full_key = f"aml_live_{prefix}_{secret}"
    hashed_secret = hash_api_secret(secret)

    tenant_uuid = uuid.UUID(str(tenant_id))
    creator_uuid = uuid.UUID(str(created_by)) if created_by else None

    import json
    scopes_json = json.dumps(scopes)

    async with get_async_db_conn(tenant_id=tenant_id) as conn:
        row = await conn.fetchrow(
            """
            INSERT INTO api_keys (
                tenant_id, name, key_prefix, hashed_secret, scopes, is_active, created_by
            ) VALUES ($1, $2, $3, $4, $5::jsonb, true, $6)
            RETURNING id, tenant_id, name, key_prefix, scopes, created_at;
            """,
            tenant_uuid,
            name,
            prefix,
            hashed_secret,
            scopes_json,
            creator_uuid
        )

    scopes_val = row["scopes"]
    if isinstance(scopes_val, str):
        try:
            scopes_val = json.loads(scopes_val)
        except Exception:
            scopes_val = [scopes_val]

    return {
        "id": str(row["id"]),
        "tenant_id": str(row["tenant_id"]),
        "name": row["name"],
        "key_prefix": row["key_prefix"],
        "scopes": scopes_val,
        "created_at": row["created_at"].isoformat()
    }, full_key


async def verify_api_key(raw_key: str) -> Optional[Dict[str, Any]]:
    """
    Verifies an incoming raw API key string.
    Returns caller identity dict if valid and active, else None.
    """
    if not raw_key or not raw_key.startswith("aml_live_"):
        return None

    parts = raw_key.split("_", 3)
    if len(parts) != 4:
        return None

    _, env, prefix, secret = parts
    hashed_input = hash_api_secret(secret)

    from database.postgres import get_async_db_read_conn
    try:
        async with get_async_db_read_conn() as conn:
            row = await conn.fetchrow(
                """
                SELECT id, tenant_id, name, hashed_secret, scopes, is_active, expires_at
                FROM api_keys
                WHERE key_prefix = $1 AND is_active = true;
                """,
                prefix
            )
            if not row:
                return None

            if not hmac.compare_digest(row["hashed_secret"], hashed_input):
                return None

            if row["expires_at"] and row["expires_at"] < datetime.now(timezone.utc):
                return None

            # Update last_used_at asynchronously
            try:
                await conn.execute("UPDATE api_keys SET last_used_at = NOW() WHERE id = $1;", row["id"])
            except Exception:
                pass

            scopes_val = row["scopes"]
            if isinstance(scopes_val, str):
                import json
                try:
                    scopes_val = json.loads(scopes_val)
                except Exception:
                    scopes_val = [scopes_val]

            return {
                "id": str(row["id"]),
                "tenant_id": str(row["tenant_id"]),
                "username": f"m2m:{row['name']}",
                "role": "API_CONSUMER",
                "scopes": scopes_val,
                "is_m2m": True
            }
    except Exception:
        return None
