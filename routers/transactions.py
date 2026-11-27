"""
Transaction Ingestion & Ledger Query HTTP Controller
====================================================
Pure HTTP transport layer (Functional Core / Imperative Shell).
All SQL queries live in `repositories/transaction_repo.py`, all compliance math
lives in `domain/rules_core.py` & `domain/money.py`, and all scoring/persistence
orchestration lives in `services/transaction_ingestion.py` (shared with
`workers/scoring_worker.py` for 100% sync-vs-async parity).
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request, Response, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator, model_validator

from database.postgres import get_async_db_conn, get_async_db_read_conn
from domain.money import InvalidMoneyError, parse_decimal_amount
from observability.sanitizer import sanitize_text
from repositories.transaction_repo import (
    ConcurrentAccountBlockError,
    DuplicateTransactionIdempotencyError,
    _row_val,
    get_transaction_by_id_repo,
    list_transactions_page_repo,
)
from services.auth import RoleChecker, enforce_tenant_data_scope
from services.behavioral import calculate_customer_baseline, get_customer_baseline
from services.dynamic_scorer import compute_dynamic_risk
from services.idempotency import (
    check_idempotency,
    clear_idempotency_key,
    extract_idempotency_key,
    save_idempotency_result,
)
from services.isolation_forest import get_iforest_score
from services.ml_model import anomaly_model
from services.rate_limiter import RateLimiter
from services.redpanda import publish_transaction  # retained for legacy test spies
from services.rules import RulesEngine
from services.transaction_ingestion import (
    AccountNotFoundError,
    AccountStatusBlockedError,
    IngestionDependencies,
    TransactionIngestionService,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/transactions", tags=["Transactions"])


class TransactionRequest(BaseModel):
    sender_account: str = Field(..., min_length=3, max_length=50, pattern=r"^[A-Za-z0-9_-]+$")
    receiver_account: str = Field(..., min_length=3, max_length=50, pattern=r"^[A-Za-z0-9_-]+$")
    amount: Decimal = Field(..., gt=Decimal("0"), le=Decimal("1000000000"))
    currency: str = Field("USD", min_length=3, max_length=3, pattern=r"^[A-Z]{3}$")
    timestamp: datetime
    country: str | None = Field(None, min_length=2, max_length=3, pattern=r"^[A-Za-z]{2,3}$")
    merchant: str | None = Field(None, max_length=100)
    device: str | None = Field(None, max_length=100)
    channel: str | None = Field(None, max_length=50)
    idempotency_key: str | None = Field(None, max_length=128)

    @field_validator("amount", mode="before")
    @classmethod
    def validate_exact_decimal_amount(cls, v: Any) -> Decimal:
        try:
            return parse_decimal_amount(v, allow_zero=False)
        except InvalidMoneyError as exc:
            raise ValueError(str(exc)) from exc

    @field_validator("sender_account", "receiver_account", "merchant", "device", "channel", "idempotency_key", mode="before")
    @classmethod
    def sanitize_input_strings(cls, v: str | None) -> str | None:
        return sanitize_text(v) if v is not None else None

    @model_validator(mode="after")
    def reject_self_transfer(self) -> "TransactionRequest":
        if self.sender_account == self.receiver_account:
            raise ValueError("sender_account and receiver_account must be different")
        return self


def _build_sync_deps() -> IngestionDependencies:
    return IngestionDependencies(
        read_conn_factory=get_async_db_read_conn,
        write_conn_factory=get_async_db_conn,
        rules_evaluate_fn=RulesEngine.evaluate_transaction,
        ml_predict_risk_fn=anomaly_model.predict_risk,
        baseline_loader=get_customer_baseline,
        iforest_scorer=get_iforest_score,
        dynamic_scorer=compute_dynamic_risk,
    )


def _hash_tx_request(payload: TransactionRequest) -> str:
    return hashlib.sha256(
        payload.model_dump_json(exclude={"idempotency_key"}).encode("utf-8")
    ).hexdigest()


async def _check_tx_idempotency(
    *,
    request: Request | None,
    body_key: str | None,
    tenant_id: Any,
    payload: TransactionRequest,
    response: Response | None,
    default_status: int,
    scope: str,
) -> tuple[str | None, str | None, JSONResponse | None]:
    raw_key = await extract_idempotency_key(request, body_key)
    if not raw_key:
        return None, None, None
    scoped_key = f"{scope}:{raw_key}"
    body_hash = _hash_tx_request(payload)
    is_cached, cached_val = await check_idempotency(
        scoped_key,
        tenant_id=str(tenant_id) if tenant_id else None,
        request_hash=body_hash,
    )
    if is_cached and cached_val:
        headers = {
            "Idempotency-Key": raw_key,
            "X-Cache-Lookup": "HIT",
            "Idempotency-Replayed": "true",
        }
        if response is not None:
            response.headers["Idempotency-Key"] = raw_key
            response.headers["X-Cache-Lookup"] = "HIT"
            response.headers["Idempotency-Replayed"] = "true"
        return raw_key, body_hash, JSONResponse(
            status_code=int(cached_val.get("status_code", default_status)),
            content=cached_val.get("body", {}),
            headers=headers,
        )
    return raw_key, body_hash, None


def _dispatch_post_commit_tasks(
    background_tasks: BackgroundTasks,
    *,
    tx_id: str,
    tenant_id: Any,
    acct: dict[str, Any],
    payload: TransactionRequest,
    scoring: dict[str, Any],
    tx_dt: datetime,
) -> None:
    background_tasks.add_task(
        calculate_customer_baseline,
        str(acct["sender_id"]),
        tenant_id=str(tenant_id) if tenant_id else None,
    )
    from routers.metrics import ws_manager

    event_payload = {
        "event": "NEW_ALERT" if scoring["alert_triggered"] else "NEW_TRANSACTION",
        "tenant_id": str(tenant_id) if tenant_id else None,
        "transaction_id": tx_id,
        "amount": float(payload.amount),
        "currency": payload.currency,
        "amount_base_usd": float(scoring["amount_base_usd"]),
        "fx_rate_applied": float(scoring["fx_rate_applied"]),
        "risk_score": scoring["dynamic_score"],
        "alert_triggered": scoring["alert_triggered"],
        "threat_level": scoring["threat_level"] if scoring["alert_triggered"] else "NONE",
        "rule_name": scoring["triggered_rules"][0] if scoring["triggered_rules"] else "NORMAL",
        "timestamp": tx_dt.isoformat(),
    }
    background_tasks.add_task(
        ws_manager.broadcast,
        event_payload,
        target_tenant_id=str(tenant_id) if tenant_id else None,
    )


@router.post("", status_code=status.HTTP_201_CREATED)
async def ingest_transaction(
    payload: TransactionRequest,
    background_tasks: BackgroundTasks,
    request: Request = None,
    response: Response = None,
    current_user: dict = Depends(RoleChecker(["ADMIN", "ANALYST"])),
    _rate_limit=Depends(RateLimiter(limit=100, window=60)),
):
    """
    Synchronous real-time transaction compliance ingestion endpoint.
    Enforces dual-layer idempotency (when `Idempotency-Key` is supplied), exact Decimal FX
    normalization, consolidated single-query AML rule evaluation, offloaded ML + dynamic RBA
    scoring, and single-ACID ledger/alert/CTR/audit/outbox persistence.
    """
    user_tenant_id = enforce_tenant_data_scope(current_user)
    scope = "tx_ingest"

    raw_idemp_key, body_hash, cached_resp = await _check_tx_idempotency(
        request=request,
        body_key=payload.idempotency_key,
        tenant_id=user_tenant_id,
        payload=payload,
        response=response,
        default_status=status.HTTP_201_CREATED,
        scope=scope,
    )
    if cached_resp is not None:
        return cached_resp

    scoped_idemp_key = f"{scope}:{raw_idemp_key}" if raw_idemp_key else None
    deps = _build_sync_deps()
    evaluated_at = datetime.now(timezone.utc)
    tx_id = str(uuid.uuid4())

    try:
        try:
            acct = await TransactionIngestionService.resolve_and_validate_accounts(
                sender_ref=payload.sender_account,
                receiver_ref=payload.receiver_account,
                tenant_id=user_tenant_id,
                evaluated_at=evaluated_at,
                deps=deps,
            )
        except AccountNotFoundError as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
        except AccountStatusBlockedError as exc:
            code = status.HTTP_403_FORBIDDEN if exc.status_value == "FROZEN" else status.HTTP_400_BAD_REQUEST
            raise HTTPException(status_code=code, detail=str(exc)) from exc
        except HTTPException:
            raise
        except Exception as exc:
            logger.exception("Database lookup failed for account")
            raise HTTPException(
                status_code=500,
                detail="Database lookup failed during transaction validation.",
            ) from exc

        tenant_id = acct["sender_tenant"]
        if tenant_id:
            enforce_tenant_data_scope(current_user, target_tenant_id=str(tenant_id))

        scoring = await TransactionIngestionService.compute_risk_and_decision(
            amount_original=payload.amount,
            currency=payload.currency,
            tx_timestamp=payload.timestamp,
            evaluated_at=evaluated_at,
            country=payload.country,
            merchant=payload.merchant,
            channel=payload.channel,
            acct=acct,
            tenant_id=tenant_id,
            deps=deps,
        )

        try:
            tx_dt, _ = await TransactionIngestionService.persist_decision(
                tenant_id=tenant_id,
                tx_id=tx_id,
                acct=acct,
                amount_original=payload.amount,
                currency=payload.currency,
                tx_timestamp=payload.timestamp,
                country=payload.country,
                merchant=payload.merchant,
                device=payload.device,
                channel=payload.channel,
                scoring=scoring,
                actor=current_user,
                deps=deps,
                idempotency_key=raw_idemp_key,
                upsert_on_id=False,
                ingestion_mode="SYNC",
            )
        except ConcurrentAccountBlockError as exc:
            code = status.HTTP_403_FORBIDDEN if exc.account_status == "FROZEN" else status.HTTP_400_BAD_REQUEST
            raise HTTPException(status_code=code, detail=str(exc)) from exc
        except DuplicateTransactionIdempotencyError as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Duplicate transaction rejected by database idempotency constraint.",
            ) from exc
        except HTTPException:
            raise
        except Exception as exc:
            logger.exception("Failed to record transaction %s", tx_id)
            raise HTTPException(
                status_code=500,
                detail="Failed to record transaction due to internal database error.",
            ) from exc
    except BaseException:
        if scoped_idemp_key:
            await clear_idempotency_key(scoped_idemp_key, tenant_id=str(user_tenant_id) if user_tenant_id else None)
        raise

    _dispatch_post_commit_tasks(
        background_tasks,
        tx_id=tx_id,
        tenant_id=tenant_id,
        acct=acct,
        payload=payload,
        scoring=scoring,
        tx_dt=tx_dt,
    )

    result = {
        "transaction_id": tx_id,
        "decision": scoring["decision"],
        "alert_triggered": scoring["alert_triggered"],
        "risk_score": scoring["dynamic_score"],
        "triggered_rules": scoring["triggered_rules"],
        "explainability": {
            "attributions": scoring["attributions"],
            "dynamic_risk": scoring["explainability"],
        },
        "provenance": {
            "ruleset_hash": scoring["ruleset_hash"],
            "model_version": scoring["model_version"],
            "fx_rate_source": scoring["fx_rate_source"],
            "evaluated_at": scoring["evaluated_at"].isoformat(),
            "degraded_rules": scoring["degraded_rules"],
        },
    }

    if scoped_idemp_key and raw_idemp_key:
        await save_idempotency_result(
            key=scoped_idemp_key,
            status_code=status.HTTP_201_CREATED,
            body=result,
            tenant_id=str(user_tenant_id) if user_tenant_id else None,
            request_hash=body_hash,
        )
        if response is not None:
            response.headers["Idempotency-Key"] = raw_idemp_key
            response.headers["X-Cache-Lookup"] = "MISS"

    if response is not None:
        response.headers["Location"] = f"/api/v1/transactions/{tx_id}"

    return result


@router.post("/ingest", status_code=status.HTTP_202_ACCEPTED)
async def ingest_transaction_async(
    payload: TransactionRequest,
    background_tasks: BackgroundTasks,
    request: Request = None,
    response: Response = None,
    current_user: dict = Depends(RoleChecker(["ADMIN", "ANALYST"])),
    _rate_limit=Depends(RateLimiter(limit=1000, window=60)),
):
    """
    Decoupled, high-throughput asynchronous ingestion buffer route (GAP-ASYNC).
    Validates dual-layer idempotency, persists durably to `transactional_outbox`
    (`aml.transactions.raw`) failing closed (503) on DB outage, returning HTTP 202
    for `workers.scoring_worker` (which runs the identical `TransactionIngestionService`).
    """
    user_tenant_id = enforce_tenant_data_scope(current_user)
    scope = "tx_ingest_async"

    raw_idemp_key, body_hash, cached_resp = await _check_tx_idempotency(
        request=request,
        body_key=payload.idempotency_key,
        tenant_id=user_tenant_id,
        payload=payload,
        response=response,
        default_status=status.HTTP_202_ACCEPTED,
        scope=scope,
    )
    if cached_resp is not None:
        return cached_resp

    scoped_idemp_key = f"{scope}:{raw_idemp_key}" if raw_idemp_key else None
    tx_id = str(uuid.uuid4())
    tenant_str = str(user_tenant_id) if user_tenant_id else None
    dt_utc = (
        payload.timestamp.replace(tzinfo=timezone.utc)
        if payload.timestamp.tzinfo is None
        else payload.timestamp.astimezone(timezone.utc)
    )
    buffer_payload = {
        "transaction_id": tx_id,
        "tenant_id": tenant_str,
        "sender_account": payload.sender_account,
        "receiver_account": payload.receiver_account,
        "amount": str(payload.amount),
        "currency": payload.currency,
        "timestamp": dt_utc.isoformat(),
        "country": payload.country,
        "merchant": payload.merchant,
        "device": payload.device,
        "channel": payload.channel,
        "idempotency_key": raw_idemp_key,
        "ingested_by": current_user.get("username", "api_ingest"),
        "ingested_at": datetime.now(timezone.utc).isoformat(),
    }

    try:
        from database.outbox import record_outbox_event
        from repositories.transaction_repo import buffer_async_transaction_outbox_repo

        await buffer_async_transaction_outbox_repo(
            tenant_id=user_tenant_id,
            tx_id=tx_id,
            buffer_payload=buffer_payload,
            record_outbox_fn=record_outbox_event,
            write_conn_factory=get_async_db_conn,
        )
    except Exception as ex_buf:
        if scoped_idemp_key:
            await clear_idempotency_key(scoped_idemp_key, tenant_id=tenant_str)
        logger.exception("Async ingestion durable outbox buffering failed for tx %s: %s", tx_id, ex_buf)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Durable async ingestion buffer is temporarily unavailable; transaction was not accepted.",
        ) from ex_buf

    accepted_body = {
        "status": "ACCEPTED",
        "transaction_id": tx_id,
        "message": "Transaction buffered for asynchronous AML scoring.",
        "ingestion_mode": "ASYNC_BUFFERED",
    }

    if scoped_idemp_key and raw_idemp_key:
        await save_idempotency_result(
            key=scoped_idemp_key,
            status_code=status.HTTP_202_ACCEPTED,
            body=accepted_body,
            tenant_id=tenant_str,
            request_hash=body_hash,
        )
        if response is not None:
            response.headers["Idempotency-Key"] = raw_idemp_key
            response.headers["X-Cache-Lookup"] = "MISS"

    if response is not None:
        response.headers["Location"] = f"/api/v1/transactions/{tx_id}"

    return accepted_body


@router.get("/{id}")
async def get_transaction_by_id(
    id: str,
    current_user: dict = Depends(RoleChecker(["ADMIN", "ANALYST", "AUDITOR"])),
    _rate_limit=Depends(RateLimiter(limit=60, window=60)),
):
    """Retrieves a single transaction by UUID with sender/receiver details and provenance."""
    try:
        tx_uuid = uuid.UUID(id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid transaction ID format")

    tenant_id = enforce_tenant_data_scope(current_user)
    try:
        row = await get_transaction_by_id_repo(
            tx_uuid,
            tenant_id=tenant_id,
            read_conn_factory=get_async_db_read_conn,
        )
        if not row:
            raise HTTPException(status_code=404, detail="Transaction not found")

        raw_amt = float(row["amount"])
        amt_usd = float(_row_val(row, "amount_base_usd", raw_amt))
        fx_rate = float(_row_val(row, "fx_rate_applied", 1.0))
        eval_at = _row_val(row, "evaluated_at")

        return {
            "id": str(row["id"]),
            "transaction_id": str(row["id"]),
            "amount": raw_amt,
            "amount_str": str(row["amount"]),
            "currency": row["currency"],
            "amount_base_usd": amt_usd,
            "amount_base_usd_str": str(_row_val(row, "amount_base_usd", row["amount"])),
            "fx_rate_applied": fx_rate,
            "fx_rate_applied_str": str(_row_val(row, "fx_rate_applied", "1.00000000")),
            "fx_rate_source": _row_val(row, "fx_rate_source"),
            "ruleset_hash": _row_val(row, "ruleset_hash"),
            "model_version": _row_val(row, "model_version"),
            "evaluated_at": eval_at.isoformat() if hasattr(eval_at, "isoformat") else eval_at,
            "status": row["status"],
            "timestamp": row["timestamp"].isoformat() if hasattr(row["timestamp"], "isoformat") else str(row["timestamp"]),
            "country": row["country"] or "DOMESTIC",
            "channel": row["channel"] or "Wire Transfer",
            "merchant": row["merchant"],
            "device": row["device"],
            "sender": {
                "account_number": row["sender_account"],
                "owner_name": row["sender_name"],
            },
            "receiver": {
                "account_number": row["receiver_account"],
                "owner_name": row["receiver_name"],
            },
        }
    except HTTPException:
        raise
    except Exception:
        logger.exception("Failed to fetch transaction %s", id)
        raise HTTPException(status_code=500, detail="Failed to fetch transaction details.")


def _serialize_tx_row(r: Any) -> dict:
    raw_amt = float(r["amount"])
    return {
        "id": str(r["id"]),
        "transaction_id": str(r["id"]),
        "amount": raw_amt,
        "amount_str": str(r["amount"]),
        "currency": r["currency"],
        "amount_base_usd": float(_row_val(r, "amount_base_usd", raw_amt)),
        "amount_base_usd_str": str(_row_val(r, "amount_base_usd", r["amount"])),
        "fx_rate_applied": float(_row_val(r, "fx_rate_applied", 1.0)),
        "fx_rate_applied_str": str(_row_val(r, "fx_rate_applied", "1.00000000")),
        "status": r["status"],
        "timestamp": r["timestamp"].isoformat() if hasattr(r["timestamp"], "isoformat") else str(r["timestamp"]),
        "country": r["country"] or "DOMESTIC",
        "channel": r["channel"] or "Wire",
        "sender_account": r["sender_account"],
        "sender_name": r["sender_name"],
        "receiver_account": r["receiver_account"],
        "receiver_name": r["receiver_name"],
    }


@router.get("")
async def list_transactions(
    response: Response,
    page: int = Query(default=1, ge=1, le=1000),
    limit: int = Query(default=50, ge=1, le=100),
    cursor: str | None = Query(default=None, max_length=512),
    cursor_timestamp: datetime | None = Query(default=None),
    cursor_id: uuid.UUID | None = Query(default=None),
    current_user: dict = Depends(RoleChecker(["ADMIN", "ANALYST", "AUDITOR"])),
    _rate_limit=Depends(RateLimiter(limit=60, window=60)),
):
    """Retrieves a paginated list of transactions within the caller's tenant boundary."""
    from database.pagination import encode_keyset_cursor

    tenant_id = enforce_tenant_data_scope(current_user)
    offset = (page - 1) * limit
    try:
        rows, total_count = await list_transactions_page_repo(
            tenant_id=tenant_id,
            cursor_timestamp=cursor_timestamp,
            cursor_id=cursor_id,
            limit=limit,
            offset=offset,
            cursor=cursor,
            read_conn_factory=get_async_db_read_conn,
        )
        if cursor:
            has_more = len(rows) > limit
            rows = rows[:limit]
        elif total_count is not None:
            has_more = (offset + len(rows)) < total_count
        else:
            has_more = len(rows) == limit

        transactions = [_serialize_tx_row(r) for r in rows]

        response.headers["X-Has-More"] = "true" if has_more else "false"
        if rows:
            last_r = rows[-1]
            ts_val = last_r["timestamp"]
            response.headers["X-Next-Cursor-Timestamp"] = ts_val.isoformat() if hasattr(ts_val, "isoformat") else str(ts_val)
            response.headers["X-Next-Cursor-ID"] = str(last_r["id"])
            if has_more:
                response.headers["X-Next-Cursor"] = encode_keyset_cursor(ts_val, str(last_r["id"]))

        if total_count is not None:
            response.headers["X-Total-Count"] = str(total_count)
        response.headers["Access-Control-Expose-Headers"] = (
            "X-Total-Count, X-Next-Cursor, X-Has-More, X-Next-Cursor-Timestamp, X-Next-Cursor-ID"
        )
        return transactions
    except HTTPException:
        raise
    except Exception:
        logger.exception("Failed to list transactions")
        raise HTTPException(status_code=500, detail="Failed to list transactions.")
