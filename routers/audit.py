"""
Immutable Audit Log Vault Router
=================================
Provides regulatory inspection endpoints for querying, filtering, and exporting
tamper-evident audit logs (FFIEC, BSA 31 CFR 1010.430, EU AMLD6).
Accessible by AUDITOR, GLOBAL_AUDITOR, MLRO, and ADMIN roles.
"""

import csv
import io
import json
import logging
import re
import uuid
import hashlib
from datetime import datetime, timezone
from typing import Optional, List, Any
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel

from database.postgres import get_async_db_read_conn
from services.auth import RoleChecker, enforce_tenant_data_scope
from services.rate_limiter import RateLimiter

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/audit", tags=["Audit Log Vault"])


def _escape_ilike(val: str) -> str:
    return val.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _sanitize_download_filename(name: str, fallback: str = "export") -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "_", str(name or "")).strip("._")
    return cleaned[:100] or fallback


def _build_audit_filter_clause(
    tenant_id: Any,
    actor: Optional[str],
    action: Optional[str],
    resource_type: Optional[str],
    date_from: Optional[str],
    date_to: Optional[str],
) -> tuple[str, list, int]:
    conditions = ["tenant_id = $1"]
    params = [uuid.UUID(str(tenant_id))]
    p_idx = 2

    if actor:
        conditions.append(f"(actor_username ILIKE ${p_idx} ESCAPE '\\' OR actor_id ILIKE ${p_idx} ESCAPE '\\')")
        params.append(f"%{_escape_ilike(actor)}%")
        p_idx += 1

    if action:
        conditions.append(f"action = ${p_idx}")
        params.append(action.upper())
        p_idx += 1

    if resource_type:
        conditions.append(f"resource_type = ${p_idx}")
        params.append(resource_type.upper())
        p_idx += 1

    if date_from:
        try:
            params.append(datetime.fromisoformat(date_from))
            conditions.append(f"created_at >= ${p_idx}")
            p_idx += 1
        except ValueError:
            pass

    if date_to:
        try:
            params.append(datetime.fromisoformat(date_to))
            conditions.append(f"created_at <= ${p_idx}")
            p_idx += 1
        except ValueError:
            pass

    return " AND ".join(conditions), params, p_idx


def _serialize_audit_row(r: dict) -> dict:
    details = r["details"] if isinstance(r["details"], dict) else json.loads(r["details"] or "{}")
    return {
        "id": str(r["id"]),
        "created_at": r["created_at"].isoformat() if r["created_at"] else "",
        "actor_id": r["actor_id"],
        "actor_username": r["actor_username"] or "SYSTEM",
        "actor_role": r["actor_role"],
        "actor_ip": r["actor_ip"],
        "actor_user_agent": r["actor_user_agent"],
        "session_id": r["session_id"],
        "action": r["action"],
        "resource_type": r["resource_type"],
        "resource_id": r["resource_id"],
        "has_state_diff": bool(r["before_state"] or r["after_state"]),
        "details": details
    }


@router.get("/logs")
async def list_audit_logs(
    response: Response,
    page: int = Query(default=1, ge=1),
    limit: int = Query(default=50, ge=1, le=200),
    actor: Optional[str] = Query(None, description="Username or Actor ID filter"),
    action: Optional[str] = Query(None, description="Action filter (e.g. UPDATE_RULE, ACCOUNT_FROZEN)"),
    resource_type: Optional[str] = Query(None, description="Target resource type (e.g. ALERT, CASE, RULE, ACCOUNT)"),
    date_from: Optional[str] = Query(None, description="ISO timestamp start filter"),
    date_to: Optional[str] = Query(None, description="ISO timestamp end filter"),
    current_user: dict = Depends(RoleChecker(["AUDITOR", "GLOBAL_AUDITOR", "ADMIN", "MLRO"])),
    _rate_limit=Depends(RateLimiter(limit=60, window=60))
):
    """Queries paginated audit logs with dynamic filtering within tenant boundaries."""
    tenant_id = enforce_tenant_data_scope(current_user)
    offset = (page - 1) * limit
    where_clause, params, p_idx = _build_audit_filter_clause(
        tenant_id, actor, action, resource_type, date_from, date_to
    )

    try:
        async with get_async_db_read_conn(tenant_id=tenant_id) as conn:
            count_query = f"SELECT COUNT(*) FROM audit_log WHERE {where_clause};"
            total_count = await conn.fetchval(count_query, *params)

            data_query = f"""
                SELECT id, created_at, actor_id, actor_username, actor_role,
                       actor_ip, actor_user_agent, session_id,
                       action, resource_type, resource_id,
                       before_state, after_state, details
                FROM audit_log
                WHERE {where_clause}
                ORDER BY created_at DESC
                LIMIT ${p_idx} OFFSET ${p_idx + 1};
            """
            rows = await conn.fetch(data_query, *params, limit, offset)
            items = [_serialize_audit_row(r) for r in rows]

            response.headers["X-Total-Count"] = str(total_count or 0)
            response.headers["Access-Control-Expose-Headers"] = "X-Total-Count"
            return {
                "items": items,
                "total": total_count or 0,
                "page": page,
                "limit": limit
            }
    except Exception:
        logger.exception("Failed to query audit logs")
        raise HTTPException(status_code=500, detail="Audit query failed.")


@router.get("/verify-chain")
async def verify_audit_hash_chain(
    current_user: dict = Depends(RoleChecker(["AUDITOR", "GLOBAL_AUDITOR", "ADMIN", "MLRO"])),
    _rate_limit=Depends(RateLimiter(limit=10, window=60))
):
    """
    Cryptographically verifies the immutable SHA-256 hash chain across audit records.
    Guarantees tamper-evidence and regulatory compliance (WORM storage).
    """
    tenant_id = enforce_tenant_data_scope(current_user)
    try:
        async with get_async_db_read_conn(tenant_id=tenant_id) as conn:
            try:
                rows = await conn.fetch(
                    """
                    SELECT id, created_at, actor_id, action, resource_type, resource_id, details,
                           prev_hash, record_hash
                    FROM audit_log
                    WHERE tenant_id = $1
                    ORDER BY created_at ASC, id ASC
                    LIMIT 5000;
                    """,
                    uuid.UUID(str(tenant_id))
                )
            except Exception:
                rows = await conn.fetch(
                    """
                    SELECT id, created_at, actor_id, action, resource_type, resource_id, details
                    FROM audit_log
                    WHERE tenant_id = $1
                    ORDER BY created_at ASC, id ASC
                    LIMIT 5000;
                    """,
                    uuid.UUID(str(tenant_id))
                )

        if not rows:
            return {
                "status": "VALID",
                "verified_records": 0,
                "genesis_hash": "GENESIS_EMPTY_CHAIN_00000000000000000000000000000000",
                "chain_head": "GENESIS_EMPTY_CHAIN_00000000000000000000000000000000",
                "tampered": False,
                "tampered_record_id": None,
                "verified_at": datetime.now(timezone.utc).isoformat()
            }

        from services.audit import GENESIS_AUDIT_HASH, compute_audit_record_hash
        prev_hash = GENESIS_AUDIT_HASH
        genesis_hash = prev_hash
        persisted_hash_count = 0

        for r in rows:
            raw_details = r["details"]
            if isinstance(raw_details, str):
                try:
                    raw_details = json.loads(raw_details)
                except Exception:
                    pass
            created_iso = r["created_at"].isoformat() if r["created_at"] else ""
            expected_hash = compute_audit_record_hash(
                prev_hash=prev_hash,
                created_at_iso=created_iso,
                actor_id=r["actor_id"],
                action=r["action"],
                resource_type=r["resource_type"],
                resource_id=r["resource_id"],
                details=raw_details
            )

            stored_prev = r["prev_hash"] if "prev_hash" in r else None
            stored_hash = r["record_hash"] if "record_hash" in r else None

            if stored_prev is not None and stored_prev != prev_hash:
                return {
                    "status": "TAMPERED",
                    "verified_records": len(rows),
                    "genesis_hash": genesis_hash,
                    "chain_head": prev_hash,
                    "tampered": True,
                    "tampered_record_id": str(r["id"]),
                    "reason": "Broken prev_hash link in audit chain",
                    "verified_at": datetime.now(timezone.utc).isoformat()
                }
            if stored_hash is not None:
                persisted_hash_count += 1
                if stored_hash != expected_hash:
                    return {
                        "status": "TAMPERED",
                        "verified_records": len(rows),
                        "genesis_hash": genesis_hash,
                        "chain_head": prev_hash,
                        "tampered": True,
                        "tampered_record_id": str(r["id"]),
                        "reason": "Stored SHA-256 record_hash mismatch",
                        "verified_at": datetime.now(timezone.utc).isoformat()
                    }
            prev_hash = expected_hash

        return {
            "status": "VALID",
            "verified_records": len(rows),
            "persisted_hashes_verified": persisted_hash_count,
            "genesis_hash": genesis_hash,
            "chain_head": prev_hash,
            "tampered": False,
            "tampered_record_id": None,
            "verified_at": datetime.now(timezone.utc).isoformat()
        }
    except Exception:
        logger.exception("Audit hash chain verification failed")
        raise HTTPException(status_code=500, detail="Audit chain verification failed.")


@router.get("/logs/export")
async def export_audit_logs(
    format: str = Query(default="csv", pattern=r"^(csv|json)$"),
    actor: Optional[str] = None,
    action: Optional[str] = None,
    resource_type: Optional[str] = None,
    current_user: dict = Depends(RoleChecker(["AUDITOR", "GLOBAL_AUDITOR", "ADMIN", "MLRO"])),
    _rate_limit=Depends(RateLimiter(limit=10, window=60))
):
    """Exports audit logs for regulatory submission or forensic archiving with digital checksum."""
    tenant_id = enforce_tenant_data_scope(current_user)
    conditions = ["tenant_id = $1"]
    params = [uuid.UUID(str(tenant_id))]
    p_idx = 2

    if actor:
        conditions.append(f"actor_username ILIKE ${p_idx}")
        params.append(f"%{actor}%")
        p_idx += 1

    if action:
        conditions.append(f"action = ${p_idx}")
        params.append(action.upper())
        p_idx += 1

    if resource_type:
        conditions.append(f"resource_type = ${p_idx}")
        params.append(resource_type.upper())
        p_idx += 1

    where_clause = " AND ".join(conditions)

    async with get_async_db_read_conn(tenant_id=tenant_id) as conn:
        rows = await conn.fetch(
            f"""
            SELECT id, created_at, actor_id, actor_username, actor_role,
                   actor_ip, action, resource_type, resource_id, details
            FROM audit_log
            WHERE {where_clause}
            ORDER BY created_at DESC
            LIMIT 5000;
            """,
            *params
        )

    timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    if format.lower() == "json":
        items = [
            {
                "id": str(r["id"]),
                "created_at": r["created_at"].isoformat() if r["created_at"] else "",
                "actor_id": r["actor_id"],
                "actor_username": r["actor_username"],
                "actor_role": r["actor_role"],
                "actor_ip": r["actor_ip"],
                "action": r["action"],
                "resource_type": r["resource_type"],
                "resource_id": r["resource_id"],
                "details": r["details"]
            }
            for r in rows
        ]
        body = json.dumps({"tenant_id": str(tenant_id), "exported_at": timestamp_str, "records": items}, indent=2)
        checksum = hashlib.sha256(body.encode("utf-8")).hexdigest()
        return Response(
            content=body,
            media_type="application/json",
            headers={
                "Content-Disposition": f"attachment; filename=audit_export_{timestamp_str}.json",
                "X-Audit-Checksum-SHA256": checksum
            }
        )

    # CSV Format
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Timestamp", "Actor", "Role", "IP", "Action", "ResourceType", "ResourceID", "Details"])
    for r in rows:
        ts = r["created_at"].isoformat() if r["created_at"] else ""
        det = json.dumps(r["details"]) if r["details"] else ""
        writer.writerow([str(r["id"]), ts, r["actor_username"] or r["actor_id"], r["actor_role"], r["actor_ip"], r["action"], r["resource_type"], r["resource_id"], det])

    csv_data = output.getvalue()
    checksum = hashlib.sha256(csv_data.encode("utf-8")).hexdigest()
    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={
            "Content-Disposition": f"attachment; filename=audit_export_{timestamp_str}.csv",
            "X-Audit-Checksum-SHA256": checksum
        }
    )


def _parse_json_field(val: Any) -> Any:
    if isinstance(val, str):
        try:
            return json.loads(val)
        except Exception:
            return val
    return val


@router.get("/logs/{id}")
async def get_audit_log_detail(
    id: str,
    current_user: dict = Depends(RoleChecker(["AUDITOR", "GLOBAL_AUDITOR", "ADMIN", "MLRO"])),
    _rate_limit=Depends(RateLimiter(limit=60, window=60))
):
    """Retrieves single audit record including full before/after state diff JSON."""
    try:
        log_uuid = uuid.UUID(id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid audit log ID format.")

    tenant_id = enforce_tenant_data_scope(current_user)
    try:
        async with get_async_db_read_conn(tenant_id=tenant_id) as conn:
            row = await conn.fetchrow(
                """
                SELECT id, created_at, actor_id, actor_username, actor_role,
                       actor_ip, actor_user_agent, session_id,
                       action, resource_type, resource_id,
                       before_state, after_state, details
                FROM audit_log
                WHERE id = $1 AND tenant_id = $2;
                """,
                log_uuid, uuid.UUID(str(tenant_id))
            )
            if not row:
                raise HTTPException(status_code=404, detail="Audit record not found.")

            before_val = _parse_json_field(row["before_state"])
            after_val = _parse_json_field(row["after_state"])
            details_val = _parse_json_field(row["details"]) or {}

            return {
                "id": str(row["id"]),
                "created_at": row["created_at"].isoformat() if row["created_at"] else "",
                "actor_id": row["actor_id"],
                "actor_username": row["actor_username"] or "SYSTEM",
                "actor_role": row["actor_role"],
                "actor_ip": row["actor_ip"],
                "actor_user_agent": row["actor_user_agent"],
                "session_id": row["session_id"],
                "action": row["action"],
                "resource_type": row["resource_type"],
                "resource_id": row["resource_id"],
                "before_state": before_val,
                "after_state": after_val,
                "details": details_val
            }
    except HTTPException:
        raise
    except Exception:
        logger.exception("Failed to fetch audit log detail")
        raise HTTPException(status_code=500, detail="Failed to fetch audit record.")


# ── P2-3: Cryptographically Signed Examiner Packet & Time-Boxed Auditor Rooms ──

from datetime import timedelta as _timedelta
from fastapi import status as _status
from pydantic import Field as _Field
from database.postgres import get_async_db_conn
from observability.logging import log_audit_event
from observability.sanitizer import sanitize_text
from services.examiner_packet import (
    build_signed_examiner_packet,
    generate_auditor_room_token,
    parse_auditor_room_token,
)


class AuditorRoomCreateRequest(BaseModel):
    room_name: str = _Field(..., min_length=3, max_length=180)
    examiner_org: str = _Field(default="Regulatory Examiner", min_length=2, max_length=180)
    allowed_case_ids: List[str] = _Field(..., min_length=1, max_length=50)
    expires_in_hours: int = _Field(default=72, ge=1, le=720)


@router.post("/examiner-packet/{case_id}")
async def export_signed_examiner_packet(
    case_id: str,
    current_user: dict = Depends(RoleChecker(["MLRO", "ADMIN", "AUDITOR", "GLOBAL_AUDITOR", "SUPER_ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=15, window=60)),
):
    """Exports a regulator-ready RS256-signed ZIP dossier verifiable via /.well-known/jwks.json."""
    try:
        case_uuid = uuid.UUID(case_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid case ID.")

    tenant_id = enforce_tenant_data_scope(current_user)
    async with get_async_db_read_conn(tenant_id=tenant_id) as conn:
        try:
            zip_bytes, manifest, zip_sha256 = await build_signed_examiner_packet(
                conn=conn,
                tenant_id=tenant_id,
                case_id=case_uuid,
                generated_by=current_user.get("username", "mlro"),
            )
        except KeyError:
            raise HTTPException(status_code=404, detail="Case not found.")

    log_audit_event(
        event_type="EXAMINER_PACKET_EXPORTED",
        actor_id=str(current_user.get("id", "")),
        actor_role=current_user.get("role", "MLRO"),
        action="EXPORT_EXAMINER_PACKET",
        resource_type="CASE",
        resource_id=case_id,
        tenant_id=str(tenant_id),
        details={"zip_sha256": zip_sha256, "case_number": manifest.get("case_number")},
    )

    safe_case_ref = _sanitize_download_filename(manifest.get("case_number") or case_id[:8], fallback=case_id[:8])
    fname = f"examiner_packet_{safe_case_ref}.zip"
    return Response(
        content=zip_bytes,
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="{fname}"',
            "X-Packet-SHA256": zip_sha256,
            "X-Packet-Signature-Alg": "RS256",
            "X-Content-Type-Options": "nosniff",
        },
    )


@router.post("/rooms", status_code=_status.HTTP_201_CREATED)
async def create_auditor_room(
    payload: AuditorRoomCreateRequest,
    current_user: dict = Depends(RoleChecker(["MLRO", "ADMIN", "SUPER_ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=15, window=60)),
):
    """Creates a time-boxed, revocable read-only Regulatory Auditor Room scoped to explicit tenant-owned case IDs."""
    try:
        case_uuids = [uuid.UUID(cid) for cid in payload.allowed_case_ids]
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid UUID in allowed_case_ids.")

    tenant_id = enforce_tenant_data_scope(current_user)
    raw_token, token_hash = generate_auditor_room_token(tenant_id)
    expires_at = datetime.now(timezone.utc) + _timedelta(hours=payload.expires_in_hours)
    safe_name = sanitize_text(payload.room_name)
    safe_org = sanitize_text(payload.examiner_org)

    async with get_async_db_conn(tenant_id=tenant_id) as conn:
        # Validate every requested case_id belongs to the caller's tenant
        owned_rows = await conn.fetch(
            "SELECT id FROM cases WHERE id = ANY($1::uuid[]) AND tenant_id = $2::uuid;",
            case_uuids,
            str(tenant_id),
        )
        owned_ids = {r["id"] for r in (owned_rows or [])}
        missing_cases = [str(cid) for cid in case_uuids if cid not in owned_ids]
        if missing_cases:
            raise HTTPException(
                status_code=_status.HTTP_404_NOT_FOUND,
                detail="One or more allowed_case_ids do not exist in your tenant.",
            )

        room_id = await conn.fetchval(
            """
            INSERT INTO auditor_rooms (
                tenant_id, room_name, examiner_org, token_hash, allowed_case_ids, expires_at, created_by
            )
            VALUES ($1::uuid, $2, $3, $4, $5::uuid[], $6, $7)
            RETURNING id;
            """,
            str(tenant_id),
            safe_name,
            safe_org,
            token_hash,
            case_uuids,
            expires_at,
            current_user.get("username", "mlro"),
        )
        try:
            from services.audit import record_audit_event_tx
            await record_audit_event_tx(
                conn=conn,
                action="CREATE_AUDITOR_ROOM",
                actor_id=str(current_user.get("id") or current_user.get("username") or "unknown"),
                actor_username=current_user.get("username", "mlro"),
                actor_role=current_user.get("role", "MLRO"),
                resource_type="AUDITOR_ROOM",
                resource_id=str(room_id),
                tenant_id=str(tenant_id),
                details={"room_name": safe_name, "examiner_org": safe_org, "case_count": len(case_uuids)},
            )
        except Exception as audit_err:
            logger.warning(f"Transactional audit write skipped in create_auditor_room: {audit_err}")

    log_audit_event(
        event_type="AUDITOR_ROOM_CREATED",
        actor_id=str(current_user.get("id", "")),
        actor_role=current_user.get("role", "MLRO"),
        action="CREATE_AUDITOR_ROOM",
        resource_type="AUDITOR_ROOM",
        resource_id=str(room_id),
        tenant_id=str(tenant_id),
        details={"room_name": safe_name, "examiner_org": safe_org, "case_count": len(case_uuids)},
    )

    return {
        "room_id": str(room_id),
        "room_name": safe_name,
        "examiner_org": safe_org,
        "allowed_case_ids": [str(c) for c in case_uuids],
        "expires_at": expires_at.isoformat(),
        "access_token": raw_token,
        "view_url": f"/api/v1/audit/rooms/{raw_token}/view",
    }


@router.get("/rooms")
async def list_auditor_rooms(
    current_user: dict = Depends(RoleChecker(["MLRO", "ADMIN", "AUDITOR", "GLOBAL_AUDITOR", "SUPER_ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=60, window=60)),
):
    tenant_id = enforce_tenant_data_scope(current_user)
    async with get_async_db_read_conn(tenant_id=tenant_id) as conn:
        rows = await conn.fetch(
            """
            SELECT id, room_name, examiner_org, allowed_case_ids, expires_at, revoked_at,
                   access_count, last_accessed_at, created_by, created_at
            FROM auditor_rooms
            WHERE tenant_id = $1::uuid
            ORDER BY created_at DESC
            LIMIT 50;
            """,
            str(tenant_id),
        )
    return [
        {
            "room_id": str(r["id"]),
            "room_name": r["room_name"],
            "examiner_org": r["examiner_org"],
            "allowed_case_ids": [str(c) for c in (r["allowed_case_ids"] or [])],
            "expires_at": r["expires_at"].isoformat() if r["expires_at"] else None,
            "revoked": r["revoked_at"] is not None,
            "access_count": int(r["access_count"] or 0),
            "last_accessed_at": r["last_accessed_at"].isoformat() if r["last_accessed_at"] else None,
            "created_by": r["created_by"],
        }
        for r in (rows or [])
    ]


@router.delete("/rooms/{room_id}")
async def revoke_auditor_room(
    room_id: str,
    current_user: dict = Depends(RoleChecker(["MLRO", "ADMIN", "SUPER_ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=15, window=60)),
):
    try:
        r_uuid = uuid.UUID(room_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid auditor room ID.")
    tenant_id = enforce_tenant_data_scope(current_user)
    async with get_async_db_conn(tenant_id=tenant_id) as conn:
        revoked = await conn.fetchval(
            "UPDATE auditor_rooms SET revoked_at = NOW() WHERE id = $1 AND tenant_id = $2::uuid AND revoked_at IS NULL RETURNING id;",
            r_uuid,
            str(tenant_id),
        )
        if not revoked:
            raise HTTPException(status_code=404, detail="Active auditor room not found.")
        try:
            from services.audit import record_audit_event_tx
            await record_audit_event_tx(
                conn=conn,
                action="REVOKE_AUDITOR_ROOM",
                actor_id=str(current_user.get("id") or current_user.get("username") or "unknown"),
                actor_username=current_user.get("username", "mlro"),
                actor_role=current_user.get("role", "MLRO"),
                resource_type="AUDITOR_ROOM",
                resource_id=room_id,
                tenant_id=str(tenant_id),
                details={"revoked": True},
            )
        except Exception as audit_err:
            logger.warning(f"Transactional audit write skipped in revoke_auditor_room: {audit_err}")
    return {"room_id": room_id, "status": "REVOKED"}


async def _validate_auditor_room_token(token: str):
    tenant_id, token_hash = parse_auditor_room_token(token)
    if not tenant_id:
        raise HTTPException(status_code=403, detail="Invalid auditor room access token.")

    async with get_async_db_conn(tenant_id=tenant_id) as conn:
        room = await conn.fetchrow(
            "SELECT * FROM auditor_rooms WHERE token_hash = $1;",
            token_hash,
        )
        if not room:
            raise HTTPException(status_code=403, detail="Invalid auditor room access token.")
        if room.get("revoked_at") is not None:
            raise HTTPException(status_code=403, detail="Auditor room access has been revoked.")
        exp = room["expires_at"]
        if exp and exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        if exp and exp < datetime.now(timezone.utc):
            raise HTTPException(status_code=_status.HTTP_410_GONE, detail="Auditor room access window has expired.")

        await conn.execute(
            "UPDATE auditor_rooms SET access_count = access_count + 1, last_accessed_at = NOW() WHERE id = $1;",
            room["id"],
        )
        return tenant_id, dict(room)


@router.get("/rooms/{token}/view")
async def view_auditor_room(
    token: str,
    response: Response,
    _rate_limit=Depends(RateLimiter(limit=30, window=60)),
):
    """Read-only examiner portal returning strictly allowlisted case summaries for this Auditor Room."""
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    tenant_id, room = await _validate_auditor_room_token(token)
    allowed_ids = [uuid.UUID(str(x)) for x in (room.get("allowed_case_ids") or [])]

    async with get_async_db_read_conn(tenant_id=tenant_id) as conn:
        cases_rows = await conn.fetch(
            """
            SELECT id, case_number, title, status, priority, created_at, closed_at
            FROM cases
            WHERE id = ANY($1::uuid[]) AND tenant_id = $2::uuid
            ORDER BY created_at DESC;
            """,
            allowed_ids,
            str(tenant_id),
        )

    return {
        "room_name": room["room_name"],
        "examiner_org": room["examiner_org"],
        "expires_at": room["expires_at"].isoformat() if room.get("expires_at") else None,
        "read_only": True,
        "cases": [
            {
                "case_id": str(c["id"]),
                "case_number": c["case_number"],
                "title": c["title"],
                "status": c["status"],
                "priority": c["priority"],
                "packet_download_url": f"/api/v1/audit/rooms/{token}/packet/{c['id']}",
            }
            for c in (cases_rows or [])
        ],
    }


@router.get("/rooms/{token}/packet/{case_id}")
async def download_auditor_room_packet(
    token: str,
    case_id: str,
    _rate_limit=Depends(RateLimiter(limit=15, window=60)),
):
    """Streams a signed Examiner Packet ZIP if and only if `case_id` is in the Auditor Room allowlist."""
    try:
        case_uuid = uuid.UUID(case_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid case ID.")

    tenant_id, room = await _validate_auditor_room_token(token)
    allowed_strs = {str(x) for x in (room.get("allowed_case_ids") or [])}
    if str(case_uuid) not in allowed_strs:
        raise HTTPException(status_code=403, detail="Case is outside the authorized Auditor Room scope.")

    async with get_async_db_read_conn(tenant_id=tenant_id) as conn:
        try:
            zip_bytes, manifest, zip_sha256 = await build_signed_examiner_packet(
                conn=conn,
                tenant_id=tenant_id,
                case_id=case_uuid,
                generated_by=f"EXAMINER:{room['examiner_org']}",
            )
        except KeyError:
            raise HTTPException(status_code=404, detail="Case not found.")

    safe_case_ref = _sanitize_download_filename(manifest.get("case_number") or case_id[:8], fallback=case_id[:8])
    fname = f"examiner_packet_{safe_case_ref}.zip"
    return Response(
        content=zip_bytes,
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="{fname}"',
            "X-Packet-SHA256": zip_sha256,
            "X-Packet-Signature-Alg": "RS256",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "Cache-Control": "no-store",
        },
    )
