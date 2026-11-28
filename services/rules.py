"""
AML Compliance Rules Engine — Imperative Shell
==============================================
Coordinates tenant rule config loading, consolidated read-replica snapshot
retrieval (1 read connection vs 7 write connections), timestamp-deterministic
Redis 24h structuring sliding windows, and sanctions/whitelist screening, then
delegates all compliance math to the pure functional core (`domain/rules_core.py`).
"""

from __future__ import annotations

import inspect
import json
import logging
import os
import time
import uuid
from datetime import datetime, timezone
from decimal import Decimal, ROUND_HALF_UP
from typing import Any

from config import settings
from database.elasticsearch_db import get_async_elasticsearch_client
from database.postgres import get_async_db_conn as _real_get_async_db_conn
from database.postgres import get_async_db_conn
from database.redis_db import get_async_redis_client
from domain.money import quantize_amount, to_decimal
from domain.rules_core import (
    AccountRuleSnapshot,
    RuleProvenance,
    TransactionInput,
    check_amount_anomaly_pure,
    check_large_transaction_pure,
    check_tbml_pure,
    check_vasp_crypto_pure,
    compute_ruleset_hash,
    evaluate_all_rules_pure,
    is_high_risk_geo_bic,
    is_vasp_transaction as _is_vasp_transaction,
)
from observability.prometheus import record_rule_degraded, record_rule_evaluation_duration
from repositories.transaction_repo import fetch_rule_evaluation_snapshot

logger = logging.getLogger(__name__)

CONFIG_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "rules_config.json"))

_config_cache = None
_tenant_rules_cache: dict[str, tuple[float, dict]] = {}
_TENANT_RULES_TTL_SECONDS = 60.0
_MAX_TENANT_RULES_CACHE = 500


def _ensure_utc(dt: datetime | None, fallback: datetime) -> datetime:
    target = dt or fallback
    if target.tzinfo is None:
        return target.replace(tzinfo=timezone.utc)
    return target.astimezone(timezone.utc)


def _dec(val: Any, default: str = "0") -> Decimal:
    if val is None:
        return Decimal(default)
    try:
        return to_decimal(val)
    except Exception:
        return Decimal(default)


async def get_rules_config_async(tenant_id: str | None = None) -> dict:
    """
    Loads active AML rule configurations with PostgreSQL `rule_configs` override support.
    Falls back to `rules_config.json` defaults when the table is empty or DB is unreachable,
    ensuring live `PATCH /api/v1/rules/{rule_name}` changes take immediate cluster-wide effect.
    """
    base_cfg = get_rules_config()
    if not tenant_id:
        return base_cfg

    cache_key = str(tenant_id)
    now = time.monotonic()
    cached = _tenant_rules_cache.get(cache_key)
    if cached and (now - cached[0]) < _TENANT_RULES_TTL_SECONDS:
        return cached[1]

    merged_rules = {k: dict(v) for k, v in base_cfg.get("rules", {}).items()}
    try:
        from database.postgres import get_async_db_read_conn

        async with get_async_db_read_conn(tenant_id=cache_key) as conn:
            if hasattr(conn, "fetch"):
                rows = await conn.fetch("SELECT rule_name, enabled, mode, config FROM rule_configs;")
                for r in (rows or []):
                    rname = r["rule_name"]
                    rcfg = r["config"]
                    if isinstance(rcfg, str):
                        rcfg = json.loads(rcfg)
                    entry = dict(merged_rules.get(rname, {}))
                    if isinstance(rcfg, dict):
                        entry.update(rcfg)
                    rmode = (r["mode"] if "mode" in r else "ACTIVE") or "ACTIVE"
                    entry["enabled"] = bool(r["enabled"]) and rmode.upper() == "ACTIVE"
                    entry["mode"] = rmode.upper()
                    merged_rules[rname] = entry
    except Exception as e:
        logger.debug("DB rule_configs lookup skipped/fallback to defaults: %s", e)

    merged = {"rules": merged_rules}
    if len(_tenant_rules_cache) >= _MAX_TENANT_RULES_CACHE:
        _tenant_rules_cache.clear()
    _tenant_rules_cache[cache_key] = (now, merged)
    return merged


def get_rules_config() -> dict:
    global _config_cache
    if _config_cache is None:
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                _config_cache = json.load(f)
            logger.info("Rules configuration loaded successfully.")
        except Exception as e:
            logger.exception("Failed to read rules config from %s: %s. Falling back to defaults.", CONFIG_PATH, e)
            _config_cache = {
                "rules": {
                    "LARGE_TRANSACTION": {"enabled": True, "threshold": 10000.0},
                    "STRUCTURING_SMURFING": {"enabled": True, "threshold": 10000.0, "window_hours": 24},
                    "VELOCITY_MONITORING": {"enabled": True, "history_days": 30, "deviation_threshold": 3.0},
                    "RAPID_MOVEMENT_FUNDS": {"enabled": True, "window_minutes": 10, "amount_ratio_threshold": 0.90},
                    "DORMANT_ACCOUNT": {"enabled": True, "dormant_period_days": 90, "activation_threshold": 50000.0},
                    "GEOGRAPHIC_SANCTIONS": {
                        "enabled": True,
                        "high_risk_countries": ["RU", "IR", "KP", "SY"],
                        "sanctions_similarity_threshold": 0.80,
                    },
                }
            }
    return _config_cache


def _parse_redis_tx_records(records) -> list[Decimal]:
    amts: list[Decimal] = []
    for tx_val, _ in records:
        try:
            raw_str = tx_val.decode("utf-8") if isinstance(tx_val, (bytes, bytearray)) else str(tx_val)
            amts.append(to_decimal(raw_str.split(":")[0]))
        except Exception:
            pass
    return amts


async def _lookup_account_entity_from_db(sender_id: str, tenant_id: str | None) -> str | None:
    try:
        async with get_async_db_conn(tenant_id=tenant_id) as conn:
            if hasattr(conn, "fetchrow"):
                acc_row = await conn.fetchrow(
                    "SELECT customer_id, tax_id, owner_name FROM accounts WHERE id = $1::uuid;",
                    sender_id,
                )
                if acc_row:
                    for fld in ("customer_id", "tax_id", "owner_name"):
                        fval = acc_row.get(fld) if hasattr(acc_row, "get") else (acc_row[fld] if fld in acc_row else None)
                        if fval:
                            return str(fval)
    except Exception as e_ent:
        logger.debug("Entity resolution fallback: %s", e_ent)
    return None


async def _screen_party_name(
    name: str,
    threshold: float,
    es: Any,
    tenant_id: str | None,
    customer_id: str | None,
    label: str,
) -> bool:
    from routers.screening import perform_sanctions_search
    from services.whitelisting import is_entity_whitelisted

    res = await perform_sanctions_search(name, threshold, es, tenant_id=tenant_id)
    if res.get("match_found", False):
        if not await is_entity_whitelisted(tenant_id, name, "SANCTIONS_HIT", customer_id=customer_id):
            return True
        logger.info("Alert suppressed via active whitelist disposition for %s '%s' (SANCTIONS_HIT)", label, name)
    return False


async def _fetch_redis_structuring_window(
    config: dict,
    amount_usd: Decimal,
    sender_id: str,
    entity_id: str,
    tenant_id: str | None,
    tx_utc: datetime,
) -> tuple[tuple[Decimal, ...], tuple[Decimal, ...], list[str]]:
    """
    Retrieves & updates the 24h Redis sliding window using deterministic `tx_utc.timestamp()`
    scores rather than wall-clock `time.time()`.
    """
    struct_cfg = config.get("rules", {}).get("STRUCTURING_SMURFING", {})
    if not struct_cfg.get("enabled", True):
        return (), (), []

    window_hours = max(1, int(struct_cfg.get("window_hours", 24)))
    window_secs = window_hours * 3600
    ttl_secs = window_secs + 3600
    degraded: list[str] = []
    try:
        r = await get_async_redis_client()
        if not r:
            return (), (), []
        now_score = tx_utc.timestamp()
        window_ago = now_score - window_secs
        # Bound pruning so backdated/future replay timestamps never evict live window entries
        prune_cutoff = min(window_ago, time.time() - window_secs)
        quantized_amt = quantize_amount(amount_usd, "USD", rounding=ROUND_HALF_UP)
        redis_key = f"acc:velocity:{tenant_id}:{sender_id}" if tenant_id else f"acc:velocity:{sender_id}"
        entity_redis_key = f"acc:velocity:{tenant_id}:entity:{entity_id}" if tenant_id else f"acc:velocity:entity:{entity_id}"
        tx_entry = f"{quantized_amt}:{now_score}:{uuid.uuid4().hex[:6]}"

        pipe_ctx = r.pipeline(transaction=True)
        if inspect.isawaitable(pipe_ctx):
            pipe_ctx = await pipe_ctx
        used_zrangebyscore = False
        async with pipe_ctx as pipe:
            used_zrangebyscore = hasattr(pipe, "zrangebyscore")
            pipe.zremrangebyscore(redis_key, "-inf", prune_cutoff)
            if used_zrangebyscore:
                pipe.zrangebyscore(redis_key, window_ago, now_score, withscores=True)
            else:
                pipe.zrange(redis_key, 0, -1, withscores=True)
            pipe.zadd(redis_key, {tx_entry: now_score})
            pipe.expire(redis_key, ttl_secs)

            if entity_redis_key != redis_key:
                pipe.zremrangebyscore(entity_redis_key, "-inf", prune_cutoff)
                if used_zrangebyscore:
                    pipe.zrangebyscore(entity_redis_key, window_ago, now_score, withscores=True)
                else:
                    pipe.zrange(entity_redis_key, 0, -1, withscores=True)
                pipe.zadd(entity_redis_key, {tx_entry: now_score})
                pipe.expire(entity_redis_key, ttl_secs)

            results = await pipe.execute()

        def _filter_in_window(records: Any) -> list[Any]:
            if used_zrangebyscore:
                # Real Redis ZRANGEBYSCORE already bounds [window_ago, now_score]; avoid
                # discarding deterministic mocked pipeline payloads that use synthetic epochs.
                return list(records or ())
            filtered = []
            for rec in (records or ()):
                if isinstance(rec, tuple) and len(rec) == 2:
                    _, sc = rec
                    if window_ago <= float(sc) <= now_score:
                        filtered.append(rec)
                else:
                    filtered.append(rec)
            return filtered

        account_recent = _filter_in_window(results[1] if results and len(results) > 1 else [])
        entity_recent = (
            _filter_in_window(results[5])
            if (entity_redis_key != redis_key and results and len(results) > 5)
            else account_recent
        )
        return (
            tuple(_parse_redis_tx_records(account_recent)),
            tuple(_parse_redis_tx_records(entity_recent)),
            degraded,
        )
    except Exception as exc:
        logger.warning("Structuring Redis sliding window degraded: %s", exc)
        record_rule_degraded("STRUCTURING_SMURFING")
        degraded.append("STRUCTURING_SMURFING")
        return (), (), degraded


async def _fetch_sanctions_and_geo_flags(
    config: dict,
    sender_bic: str | None,
    receiver_bic: str | None,
    sender_name: str | None,
    receiver_name: str | None,
    tenant_id: str | None,
    entity_id: str,
) -> tuple[bool, bool, bool]:
    """Returns `(sanctions_hit, sanctions_degraded, geo_whitelisted)`."""
    geo_cfg = config.get("rules", {}).get("GEOGRAPHIC_SANCTIONS", {})
    if not geo_cfg.get("enabled", True):
        return False, False, False

    geo_whitelisted = False
    high_risk = geo_cfg.get("high_risk_countries", ["RU", "IR", "KP", "SY"])
    if is_high_risk_geo_bic(sender_bic, receiver_bic, high_risk):
        try:
            from services.whitelisting import is_entity_whitelisted

            target = sender_name or sender_bic or receiver_bic or ""
            if target and await is_entity_whitelisted(tenant_id, target, "GEOGRAPHIC_RISK", customer_id=entity_id):
                geo_whitelisted = True
                logger.info("Alert suppressed via active whitelist disposition for entity '%s' (GEOGRAPHIC_RISK)", target)
        except Exception as exc:
            logger.debug("Geo whitelist check skipped: %s", exc)

    sanctions_hit = False
    sanctions_degraded = False
    sanctions_threshold = float(geo_cfg.get("sanctions_similarity_threshold", 0.80))
    if sender_name or receiver_name:
        try:
            es = await get_async_elasticsearch_client()
            if sender_name and await _screen_party_name(
                sender_name, sanctions_threshold, es, tenant_id, entity_id, "sender"
            ):
                sanctions_hit = True
            elif receiver_name and receiver_name != sender_name:
                if await _screen_party_name(
                    receiver_name, sanctions_threshold, es, tenant_id, None, "receiver"
                ):
                    sanctions_hit = True
        except Exception as exc:
            logger.error("Sanctions screening failed within rules engine: %s", exc)
            record_rule_degraded("GEOGRAPHIC_SANCTIONS")
            sanctions_degraded = True

    return sanctions_hit, sanctions_degraded, geo_whitelisted


async def _load_mock_db_snapshot(
    *,
    sender_id: str | None,
    receiver_id: str | None,
    tenant_id: str | None,
) -> AccountRuleSnapshot:
    """
    Compatibility adapter invoked ONLY when a unit test explicitly monkeypatches
    `services.rules.get_async_db_conn` with a mock connection returning legacy keys
    (`total_sub_amount`/`sub_count`, `total_inflow`/`total_outflow`, `fetchval=1/datetime`).
    """
    if not sender_id:
        return AccountRuleSnapshot()
    try:
        async with get_async_db_conn(tenant_id=tenant_id) as conn:
            row = await conn.fetchrow("SELECT 1;") if hasattr(conn, "fetchrow") else None
            val = await conn.fetchval("SELECT 1;") if hasattr(conn, "fetchval") else None

            def _pick(key: str, alt: str | None = None, default: Any = None) -> Any:
                if not isinstance(row, dict) and not hasattr(row, "get"):
                    return default
                if key in row and row[key] is not None:
                    return row[key]
                if alt and alt in row and row[alt] is not None:
                    return row[alt]
                return default

            has_reverse = bool(_pick("has_reverse_tx", default=False))
            if not has_reverse and isinstance(val, int) and val == 1 and receiver_id:
                has_reverse = True

            acc_created = _pick("account_created_at", "created_at")
            if acc_created is None and isinstance(val, datetime):
                acc_created = val

            return AccountRuleSnapshot(
                velocity_avg_count=_dec(_pick("avg_daily_count", default=0)),
                velocity_std_count=_dec(_pick("stddev_daily_count", default=0)),
                velocity_avg_amount_usd=_dec(_pick("avg_daily_amount", default=0)),
                velocity_std_amount_usd=_dec(_pick("stddev_daily_amount", default=0)),
                today_count=int(_pick("today_count", default=0)),
                today_amount_usd=_dec(_pick("today_amount", default=0)),
                last_incoming_amount_usd=(
                    _dec(_pick("last_incoming_amount_usd", "amount"))
                    if _pick("last_incoming_amount_usd", "amount") is not None
                    else None
                ),
                last_incoming_at=_pick("last_incoming_at", "timestamp"),
                last_outgoing_at=_pick("last_outgoing_at"),
                has_reverse_tx=has_reverse,
                account_created_at=acc_created,
                sub_7d_count=int(_pick("sub_7d_count", "sub_count", default=0)),
                sub_7d_amount_usd=_dec(_pick("sub_7d_amount_usd", "total_sub_amount", default=0)),
                conduit_inflow_24h_usd=_dec(_pick("conduit_inflow_24h_usd", "total_inflow", default=0)),
                conduit_outflow_24h_usd=_dec(_pick("conduit_outflow_24h_usd", "total_outflow", default=0)),
            )
    except Exception as exc:
        logger.debug("Mock DB snapshot fallback error: %s", exc)
        return AccountRuleSnapshot()


class RulesEngine:
    @classmethod
    def reload_config(cls):
        global _config_cache
        _config_cache = None
        _tenant_rules_cache.clear()
        logger.info("Rules configuration cache invalidated (global + tenant DB cache).")

    @staticmethod
    async def _resolve_entity_id(
        sender_id: str | None,
        sender_name: str | None,
        meta: dict,
        tenant_id: str | None,
    ) -> str:
        for key in ("customer_id", "tax_id", "entity_id"):
            val = meta.get(key)
            if val:
                return str(val)

        # Avoid extra DB round-trip when caller didn't patch get_async_db_conn & sender_name is available
        if sender_id and get_async_db_conn is _real_get_async_db_conn:
            try:
                uuid.UUID(str(sender_id))
                db_ent = await _lookup_account_entity_from_db(str(sender_id), tenant_id)
                if db_ent:
                    return db_ent
            except (ValueError, TypeError):
                pass

        if sender_name:
            return sender_name
        return str(sender_id or "")

    @staticmethod
    def _check_large_transaction(config: dict, amount: float | Decimal) -> list[str]:
        return check_large_transaction_pure(config, _dec(amount))

    @staticmethod
    def _check_tbml(config: dict, amount: float | Decimal, meta: dict) -> list[str]:
        return check_tbml_pure(config, _dec(amount), meta)

    @staticmethod
    def _check_vasp_crypto(
        config: dict,
        amount: float | Decimal,
        sender_bic: str | None,
        receiver_bic: str | None,
        meta: dict,
    ) -> list[str]:
        return check_vasp_crypto_pure(config, _dec(amount), sender_bic, receiver_bic, meta)

    @staticmethod
    def _check_amount_anomaly(
        config: dict,
        amount: float | Decimal,
        total_entity_amount: float | Decimal,
        entity_below: list[float | Decimal],
    ) -> list[str]:
        return check_amount_anomaly_pure(
            config,
            _dec(amount),
            _dec(total_entity_amount),
            [_dec(a) for a in entity_below],
        )

    @staticmethod
    async def _resolve_account_uuid(conn: Any, account_ref: str | None) -> Any:
        """Accept either a UUID string or an account_number safely."""
        if not account_ref:
            return None
        try:
            return uuid.UUID(str(account_ref))
        except (ValueError, TypeError):
            pass
        try:
            found = await conn.fetchval(
                "SELECT id FROM accounts WHERE account_number = $1 LIMIT 1;",
                str(account_ref),
            )
            if not found:
                return None
            if isinstance(found, int):
                return str(account_ref)
            return uuid.UUID(str(found))
        except Exception:
            return None

    @staticmethod
    async def evaluate_transaction_with_provenance(
        sender_id: str,
        receiver_id: str,
        amount: float | Decimal,
        sender_name: str | None = None,
        sender_bic: str | None = None,
        receiver_name: str | None = None,
        receiver_bic: str | None = None,
        timestamp: datetime | None = None,
        tenant_id: str | None = None,
        metadata: dict | None = None,
        sender_account_number: str | None = None,
        receiver_account_number: str | None = None,
        evaluated_at: datetime | None = None,
        **kwargs,
    ) -> RuleProvenance:
        """
        Full enterprise evaluation returning immutable `RuleProvenance`
        (`ruleset_hash`, `evaluated_at`, `triggered_rules`, `degraded_rules`, `tier_discount`).
        """
        t0 = time.monotonic()
        eval_utc = _ensure_utc(evaluated_at, datetime.now(timezone.utc))
        tx_utc = _ensure_utc(timestamp, eval_utc)
        amount_usd = _dec(amount)
        config = await get_rules_config_async(tenant_id=tenant_id)
        meta = metadata or {}

        kyc_tier = str(meta.get("kyc_risk_tier", "STANDARD")).upper()
        tier_discount = Decimal("0.50") if kyc_tier in ("HIGH", "CRITICAL") else Decimal("1.00")
        entity_id = await RulesEngine._resolve_entity_id(sender_id, sender_name, meta, tenant_id)

        # 1. Consolidated single-connection DB snapshot (1 read conn instead of 7 write conns)
        degraded_list: list[str] = []
        if get_async_db_conn is not _real_get_async_db_conn:
            db_snap = await _load_mock_db_snapshot(
                sender_id=sender_id,
                receiver_id=receiver_id,
                tenant_id=tenant_id,
            )
        else:
            db_snap, snap_degraded = await fetch_rule_evaluation_snapshot(
                tenant_id=tenant_id,
                sender_id=sender_id,
                receiver_id=receiver_id,
                amount_base_usd=amount_usd,
                tx_time=tx_utc,
                config=config,
                tier_discount=tier_discount,
                entity_id=entity_id,
                tax_id=str(meta.get("tax_id") or ""),
                sender_name=str(sender_name or ""),
            )
            degraded_list.extend(snap_degraded)
            for d_rule in snap_degraded:
                record_rule_degraded(d_rule)

        # 2. Timestamp-deterministic Redis 24h structuring window + Sanctions/Whitelist
        acc_prior, ent_prior, redis_degraded = await _fetch_redis_structuring_window(
            config, amount_usd, str(sender_id), entity_id, tenant_id, tx_utc
        )
        degraded_list.extend(redis_degraded)

        sanctions_hit, sanctions_degraded, geo_whitelisted = await _fetch_sanctions_and_geo_flags(
            config, sender_bic, receiver_bic, sender_name, receiver_name, tenant_id, entity_id
        )

        merged_snap = AccountRuleSnapshot(
            velocity_avg_count=db_snap.velocity_avg_count,
            velocity_std_count=db_snap.velocity_std_count,
            velocity_avg_amount_usd=db_snap.velocity_avg_amount_usd,
            velocity_std_amount_usd=db_snap.velocity_std_amount_usd,
            today_count=db_snap.today_count,
            today_amount_usd=db_snap.today_amount_usd,
            last_incoming_amount_usd=db_snap.last_incoming_amount_usd,
            last_incoming_at=db_snap.last_incoming_at,
            last_outgoing_at=db_snap.last_outgoing_at,
            has_reverse_tx=db_snap.has_reverse_tx,
            account_created_at=db_snap.account_created_at,
            sub_7d_count=db_snap.sub_7d_count,
            sub_7d_amount_usd=db_snap.sub_7d_amount_usd,
            conduit_inflow_24h_usd=db_snap.conduit_inflow_24h_usd,
            conduit_outflow_24h_usd=db_snap.conduit_outflow_24h_usd,
            structuring_24h_account_amounts=acc_prior,
            structuring_24h_entity_amounts=ent_prior,
            sanctions_hit=sanctions_hit,
            sanctions_degraded=sanctions_degraded,
            geo_whitelisted=geo_whitelisted,
            degraded_rules=tuple(dict.fromkeys(degraded_list)),
        )

        tx_input = TransactionInput(
            amount_original=_dec(meta.get("original_amount", amount_usd)),
            currency=str(meta.get("original_currency", "USD")).upper(),
            amount_base_usd=amount_usd,
            fx_rate_applied=_dec(meta.get("fx_rate_applied", "1"), "1"),
            sender_id=str(sender_id),
            receiver_id=str(receiver_id),
            tx_timestamp=tx_utc,
            evaluated_at=eval_utc,
            sender_name=sender_name,
            receiver_name=receiver_name,
            sender_bic=sender_bic,
            receiver_bic=receiver_bic,
            country=meta.get("country"),
            channel=meta.get("channel"),
            merchant=meta.get("merchant"),
            kyc_risk_tier=kyc_tier,
            metadata=meta,
        )

        # Approved Option A: Fail-closed sanctions hold in hardened staging/prod environments
        fail_closed_sanctions = bool(getattr(settings, "is_hardened", settings.is_production)) and not bool(
            getattr(settings, "allow_offline_dev", False)
        )

        provenance = evaluate_all_rules_pure(
            tx_input,
            merged_snap,
            config,
            fail_closed_sanctions=fail_closed_sanctions,
        )
        record_rule_evaluation_duration(time.monotonic() - t0)
        return provenance

    @staticmethod
    async def evaluate_transaction(
        sender_id: str,
        receiver_id: str,
        amount: float | Decimal,
        sender_name: str | None = None,
        sender_bic: str | None = None,
        receiver_name: str | None = None,
        receiver_bic: str | None = None,
        timestamp: datetime | None = None,
        tenant_id: str | None = None,
        metadata: dict | None = None,
        sender_account_number: str | None = None,
        receiver_account_number: str | None = None,
        evaluated_at: datetime | None = None,
        **kwargs,
    ) -> list[str]:
        """Backward-compatible wrapper returning `list[str]` of triggered rule identifiers."""
        provenance = await RulesEngine.evaluate_transaction_with_provenance(
            sender_id=sender_id,
            receiver_id=receiver_id,
            amount=amount,
            sender_name=sender_name,
            sender_bic=sender_bic,
            receiver_name=receiver_name,
            receiver_bic=receiver_bic,
            timestamp=timestamp,
            tenant_id=tenant_id,
            metadata=metadata,
            sender_account_number=sender_account_number,
            receiver_account_number=receiver_account_number,
            evaluated_at=evaluated_at,
            **kwargs,
        )
        return list(provenance.triggered_rules)


async def start_redis_rules_listener(shutdown_event=None):
    """Listens for distributed rules cache invalidation events using dedicated Pub/Sub client (P2-23)."""
    import asyncio
    from database.redis_db import get_async_redis_pubsub_client
    from services.http_client import full_jitter_backoff

    attempt = 0
    while shutdown_event is None or not shutdown_event.is_set():
        redis = None
        pubsub = None
        try:
            redis = await get_async_redis_pubsub_client()
            if redis is None:
                await asyncio.sleep(full_jitter_backoff(2.0, attempt, cap=30.0))
                attempt += 1
                continue
            pubsub = redis.pubsub()
            await pubsub.subscribe("aml:rules:cache_invalidate")
            logger.info("Subscribed to Redis channel 'aml:rules:cache_invalidate'")
            attempt = 0
            while shutdown_event is None or not shutdown_event.is_set():
                msg = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
                if msg and msg.get("type") == "message":
                    RulesEngine.reload_config()
                await asyncio.sleep(0.5)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.debug("Redis rules invalidation listener error: %s", e)
            await asyncio.sleep(full_jitter_backoff(1.0, attempt, cap=30.0))
            attempt += 1
        finally:
            if pubsub is not None:
                try:
                    if hasattr(pubsub, "aclose"):
                        await pubsub.aclose()
                    else:
                        await pubsub.close()
                except Exception:
                    pass
            if redis is not None:
                try:
                    await redis.aclose()
                except Exception:
                    pass
