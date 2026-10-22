import time
import inspect
import json
import os
import uuid
import logging
from typing import Any
from datetime import datetime, timezone
from database.redis_db import get_async_redis_client
from database.postgres import get_async_db_conn
from database.elasticsearch_db import get_async_elasticsearch_client

logger = logging.getLogger(__name__)

CONFIG_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "rules_config.json"))

_config_cache = None

def get_rules_config() -> dict:
    global _config_cache
    if _config_cache is None:
        try:
            with open(CONFIG_PATH, "r") as f:
                _config_cache = json.load(f)
            logger.info("Rules configuration loaded successfully.")
        except Exception as e:
            logger.exception(f"Failed to read rules config from {CONFIG_PATH}: {e}. Falling back to defaults.")
            _config_cache = {
                "rules": {
                    "LARGE_TRANSACTION": {
                        "enabled": True,
                        "threshold": 10000.0
                    },
                    "STRUCTURING_SMURFING": {
                        "enabled": True,
                        "threshold": 10000.0,
                        "window_hours": 24
                    },
                    "VELOCITY_MONITORING": {
                        "enabled": True,
                        "history_days": 30,
                        "deviation_threshold": 3.0
                    },
                    "RAPID_MOVEMENT_FUNDS": {
                        "enabled": True,
                        "window_minutes": 10,
                        "amount_ratio_threshold": 0.90
                    },
                    "DORMANT_ACCOUNT": {
                        "enabled": True,
                        "dormant_period_days": 90,
                        "activation_threshold": 50000.0
                    },
                    "GEOGRAPHIC_SANCTIONS": {
                        "enabled": True,
                        "high_risk_countries": ["RU", "IR", "KP", "SY"],
                        "sanctions_similarity_threshold": 0.80
                    }
                }
            }
    return _config_cache


def _parse_redis_tx_records(records) -> list[float]:
    amts = []
    for tx_val, _ in records:
        try:
            raw_str = tx_val.decode("utf-8") if isinstance(tx_val, (bytes, bytearray)) else str(tx_val)
            amts.append(float(raw_str.split(":")[0]))
        except (ValueError, IndexError):
            pass
    return amts


def _is_vasp_transaction(meta: dict, sender_bic: str, receiver_bic: str) -> bool:
    if meta.get("is_vasp_transfer"):
        return True
    if str(meta.get("counterparty_type", "")).upper() == "VASP":
        return True
    for bic in (sender_bic, receiver_bic):
        if bic and "VASP" in bic.upper():
            return True
    return False


async def _lookup_account_entity_from_db(sender_id: str, tenant_id: str) -> str | None:
    try:
        async with get_async_db_conn(tenant_id=tenant_id) as conn:
            if hasattr(conn, "fetchrow"):
                acc_row = await conn.fetchrow(
                    "SELECT customer_id, tax_id, owner_name FROM accounts WHERE id = $1::uuid;",
                    sender_id
                )
                if acc_row:
                    for fld in ("customer_id", "tax_id", "owner_name"):
                        fval = acc_row.get(fld)
                        if fval:
                            return str(fval)
    except Exception as e_ent:
        logger.debug(f"Entity resolution fallback: {e_ent}")
    return None


async def _screen_party_name(
    name: str,
    threshold: float,
    es: Any,
    tenant_id: str,
    customer_id: str | None,
    label: str
) -> bool:
    from routers.screening import perform_sanctions_search
    from services.whitelisting import is_entity_whitelisted
    res = await perform_sanctions_search(name, threshold, es)
    if res.get("match_found", False):
        if not await is_entity_whitelisted(tenant_id, name, "SANCTIONS_HIT", customer_id=customer_id):
            return True
        logger.info(f"Alert suppressed via active whitelist disposition for {label} '{name}' (SANCTIONS_HIT)")
    return False


class RulesEngine:
    @classmethod
    def reload_config(cls):
        global _config_cache
        _config_cache = None
        logger.info("Rules configuration cache invalidated.")

    @staticmethod
    async def _resolve_entity_id(
        sender_id: str,
        sender_name: str,
        meta: dict,
        tenant_id: str
    ) -> str:
        for key in ("customer_id", "tax_id", "entity_id"):
            val = meta.get(key)
            if val:
                return str(val)

        if sender_id:
            db_ent = await _lookup_account_entity_from_db(sender_id, tenant_id)
            if db_ent:
                return db_ent

        if sender_name:
            return sender_name
        return str(sender_id)

    @staticmethod
    def _check_large_transaction(config: dict, amount: float) -> list[str]:
        large_config = config.get("rules", {}).get("LARGE_TRANSACTION", {})
        if large_config.get("enabled", True):
            threshold = large_config.get("threshold", 10000.0)
            if amount >= threshold:
                return ["LARGE_TRANSACTION_THRESHOLD"]
        return []

    @staticmethod
    async def _check_structuring_smurfing(
        config: dict,
        amount: float,
        sender_id: str,
        entity_id: str,
        tenant_id: str
    ) -> tuple[list[str], float, list[float]]:
        structuring_config = config.get("rules", {}).get("STRUCTURING_SMURFING", {})
        threshold = structuring_config.get("threshold", 10000.0)
        total_entity_amount = amount
        entity_below = [amount] if amount < threshold else []
        triggered = []

        if not structuring_config.get("enabled", True):
            return triggered, total_entity_amount, entity_below

        window_hours = structuring_config.get("window_hours", 24)
        try:
            r = await get_async_redis_client()
            now = time.time()
            window_ago = now - (window_hours * 3600)
            redis_key = f"acc:velocity:{tenant_id}:{sender_id}" if tenant_id else f"acc:velocity:{sender_id}"
            entity_redis_key = f"acc:velocity:{tenant_id}:entity:{entity_id}" if tenant_id else f"acc:velocity:entity:{entity_id}"
            tx_entry = f"{amount}:{now}:{uuid.uuid4().hex[:6]}"

            pipe_ctx = r.pipeline(transaction=True)
            if inspect.isawaitable(pipe_ctx):
                pipe_ctx = await pipe_ctx
            async with pipe_ctx as pipe:
                pipe.zremrangebyscore(redis_key, "-inf", window_ago)
                pipe.zrange(redis_key, 0, -1, withscores=True)
                pipe.zadd(redis_key, {tx_entry: now})
                pipe.expire(redis_key, 90000)

                if entity_redis_key != redis_key:
                    pipe.zremrangebyscore(entity_redis_key, "-inf", window_ago)
                    pipe.zrange(entity_redis_key, 0, -1, withscores=True)
                    pipe.zadd(entity_redis_key, {tx_entry: now})
                    pipe.expire(entity_redis_key, 90000)

                results = await pipe.execute()

            account_recent_txs = results[1]
            entity_recent_txs = results[5] if (entity_redis_key != redis_key and len(results) > 5) else account_recent_txs

            account_amts = [amount] + _parse_redis_tx_records(account_recent_txs)
            entity_amts = [amount] + _parse_redis_tx_records(entity_recent_txs)

            account_below = [amt for amt in account_amts if amt < threshold]
            entity_below = [amt for amt in entity_amts if amt < threshold]

            total_account_amount = sum(account_below)
            total_entity_amount = sum(entity_below)

            if (total_entity_amount >= threshold and len(entity_below) >= 2) or \
               (total_account_amount >= threshold and len(account_below) >= 2):
                triggered.append("STRUCTURING_VELOCITY_24H")
        except Exception as e:
            logger.exception(f"Structuring check Redis error: {e}")

        return triggered, total_entity_amount, entity_below

    @staticmethod
    async def _check_velocity_monitoring(
        config: dict,
        amount: float,
        sender_id: str,
        timestamp: datetime,
        tenant_id: str
    ) -> list[str]:
        velocity_config = config.get("rules", {}).get("VELOCITY_MONITORING", {})
        if not velocity_config.get("enabled", True):
            return []
        history_days = velocity_config.get("history_days", 30)
        dev_threshold = velocity_config.get("deviation_threshold", 3.0)
        try:
            tx_time = timestamp or datetime.now(timezone.utc)
            async with get_async_db_conn(tenant_id=tenant_id) as conn:
                hist_row = await conn.fetchrow(
                    """
                    SELECT 
                        COALESCE(AVG(daily_count), 0) as avg_daily_count,
                        COALESCE(STDDEV(daily_count), 0) as stddev_daily_count,
                        COALESCE(AVG(daily_amount), 0) as avg_daily_amount,
                        COALESCE(STDDEV(daily_amount), 0) as stddev_daily_amount
                    FROM (
                        SELECT 
                            DATE_TRUNC('day', timestamp) as tx_day,
                            COUNT(*) as daily_count,
                            SUM(amount) as daily_amount
                        FROM transactions
                        WHERE sender_account_id = $1::uuid
                          AND timestamp >= $3::timestamptz - $2 * INTERVAL '1 day'
                          AND timestamp < DATE_TRUNC('day', $3::timestamptz)
                        GROUP BY DATE_TRUNC('day', timestamp)
                    ) daily_stats;
                    """,
                    sender_id, history_days, tx_time
                )
                today_row = await conn.fetchrow(
                    """
                    SELECT 
                        COUNT(*) as today_count,
                        COALESCE(SUM(amount), 0) as today_amount
                    FROM transactions
                    WHERE sender_account_id = $1::uuid
                      AND timestamp >= DATE_TRUNC('day', $2::timestamptz)
                      AND timestamp <= $2::timestamptz;
                    """,
                    sender_id, tx_time
                )
                avg_count = float(hist_row["avg_daily_count"])
                stddev_count = float(hist_row["stddev_daily_count"])
                avg_amount = float(hist_row["avg_daily_amount"])
                stddev_amount = float(hist_row["stddev_daily_amount"])

                if avg_count > 0.0:
                    today_count = int(today_row["today_count"]) + 1
                    today_amount = float(today_row["today_amount"]) + amount
                    stddev_count = max(stddev_count, 1.0)
                    min_std_amount = max(avg_amount * 0.10, 1.0)
                    stddev_amount = max(stddev_amount, min_std_amount)

                    count_z = (today_count - avg_count) / stddev_count
                    amount_z = (today_amount - avg_amount) / stddev_amount

                    if count_z > dev_threshold or amount_z > dev_threshold:
                        logger.warning(f"Velocity spike deviation triggered for {sender_id}. Count Z: {count_z:.2f}, Amount Z: {amount_z:.2f}")
                        return ["VELOCITY_MONITORING_SPIKE"]
        except Exception as e:
            logger.exception(f"Velocity rule Postgres error: {e}")
        return []

    @staticmethod
    async def _check_rapid_movement_funds(
        config: dict,
        amount: float,
        sender_id: str,
        timestamp: datetime,
        tenant_id: str
    ) -> list[str]:
        rapid_config = config.get("rules", {}).get("RAPID_MOVEMENT_FUNDS", {})
        if not rapid_config.get("enabled", True):
            return []
        window_minutes = rapid_config.get("window_minutes", 10)
        amount_ratio_threshold = rapid_config.get("amount_ratio_threshold", 0.90)
        try:
            async with get_async_db_conn(tenant_id=tenant_id) as conn:
                incoming_row = await conn.fetchrow(
                    """
                    SELECT amount, timestamp 
                    FROM transactions 
                    WHERE receiver_account_id = $1::uuid
                      AND status = 'COMPLETED'
                      AND timestamp >= NOW() - $2 * INTERVAL '1 minute'
                    ORDER BY timestamp DESC 
                    LIMIT 1;
                    """,
                    sender_id, window_minutes
                )
                if incoming_row:
                    incoming_amount = float(incoming_row["amount"])
                    incoming_time = incoming_row["timestamp"]
                    current_time = timestamp or datetime.now(timezone.utc)
                    if incoming_time.tzinfo is None:
                        incoming_time = incoming_time.replace(tzinfo=timezone.utc)
                    if current_time.tzinfo is None:
                        current_time = current_time.replace(tzinfo=timezone.utc)
                    time_diff = (current_time - incoming_time).total_seconds()
                    if time_diff <= window_minutes * 60 and amount >= incoming_amount * amount_ratio_threshold:
                        return ["RAPID_MOVEMENT_FUNDS"]
        except Exception as e:
            logger.exception(f"Rapid movement check error: {e}")
        return []

    @staticmethod
    async def _check_dormant_account(
        config: dict,
        amount: float,
        sender_id: str,
        timestamp: datetime,
        tenant_id: str
    ) -> list[str]:
        dormant_config = config.get("rules", {}).get("DORMANT_ACCOUNT", {})
        if not dormant_config.get("enabled", True):
            return []
        dormant_period_days = dormant_config.get("dormant_period_days", 90)
        activation_threshold = dormant_config.get("activation_threshold", 50000.0)
        try:
            async with get_async_db_conn(tenant_id=tenant_id) as conn:
                last_tx_row = await conn.fetchrow(
                    """
                    SELECT timestamp 
                    FROM transactions 
                    WHERE sender_account_id = $1::uuid
                    ORDER BY timestamp DESC 
                    OFFSET 1 
                    LIMIT 1;
                    """,
                    sender_id
                )
                if last_tx_row:
                    last_activity = last_tx_row["timestamp"]
                    current_time = timestamp or datetime.now(timezone.utc)
                    if last_activity.tzinfo is None:
                        last_activity = last_activity.replace(tzinfo=timezone.utc)
                    if current_time.tzinfo is None:
                        current_time = current_time.replace(tzinfo=timezone.utc)
                    inactivity_days = (current_time - last_activity).days
                    if inactivity_days >= dormant_period_days and amount > activation_threshold:
                        return ["DORMANT_ACCOUNT_ACTIVATION"]
        except Exception as e:
            logger.exception(f"Dormant account check error: {e}")
        return []

    @staticmethod
    async def _check_bic_geographic_risk(
        geo_config: dict,
        sender_bic: str,
        receiver_bic: str,
        sender_name: str,
        tenant_id: str,
        entity_id: str
    ) -> list[str]:
        high_risk_countries = geo_config.get("high_risk_countries", ["RU", "IR", "KP", "SY"])
        for bic in [sender_bic, receiver_bic]:
            if bic and len(bic) >= 6:
                country = bic[4:6].upper()
                if country in high_risk_countries:
                    from services.whitelisting import is_entity_whitelisted
                    target = sender_name or bic
                    if not await is_entity_whitelisted(tenant_id, target, "GEOGRAPHIC_RISK", customer_id=entity_id):
                        return ["GEOGRAPHIC_RISK"]
                    logger.info(f"Alert suppressed via active whitelist disposition for entity '{target}' (GEOGRAPHIC_RISK)")
                    break
        return []

    @staticmethod
    async def _check_sanctions_search(
        geo_config: dict,
        sender_name: str,
        receiver_name: str,
        tenant_id: str,
        entity_id: str
    ) -> list[str]:
        sanctions_threshold = geo_config.get("sanctions_similarity_threshold", 0.80)
        try:
            es = await get_async_elasticsearch_client()
            if sender_name and await _screen_party_name(sender_name, sanctions_threshold, es, tenant_id, entity_id, "sender"):
                return ["SANCTIONS_HIT"]

            if receiver_name and receiver_name != sender_name:
                if await _screen_party_name(receiver_name, sanctions_threshold, es, tenant_id, None, "receiver"):
                    return ["SANCTIONS_HIT"]
        except Exception as e:
            logger.exception(f"Sanctions check within rules engine error: {e}")

        return []

    @staticmethod
    async def _check_geographic_sanctions(
        config: dict,
        sender_bic: str,
        receiver_bic: str,
        sender_name: str,
        receiver_name: str,
        tenant_id: str,
        entity_id: str
    ) -> list[str]:
        geo_sanctions_config = config.get("rules", {}).get("GEOGRAPHIC_SANCTIONS", {})
        if not geo_sanctions_config.get("enabled", True):
            return []
        triggered = []
        triggered.extend(await RulesEngine._check_bic_geographic_risk(
            geo_sanctions_config, sender_bic, receiver_bic, sender_name, tenant_id, entity_id
        ))
        triggered.extend(await RulesEngine._check_sanctions_search(
            geo_sanctions_config, sender_name, receiver_name, tenant_id, entity_id
        ))
        return triggered

    @staticmethod
    async def _check_round_trip(
        config: dict,
        amount: float,
        sender_id: str,
        receiver_id: str,
        timestamp: datetime,
        tenant_id: str
    ) -> list[str]:
        round_trip_config = config.get("rules", {}).get("ROUND_TRIP_DETECTION", {})
        if not round_trip_config.get("enabled", True) or not (sender_id and receiver_id):
            return []
        window_hours = round_trip_config.get("window_hours", 72)
        amount_tolerance = round_trip_config.get("amount_tolerance", 0.10)
        try:
            async with get_async_db_conn(tenant_id=tenant_id) as conn:
                min_amt = amount * (1.0 - amount_tolerance)
                max_amt = amount * (1.0 + amount_tolerance)
                reverse_tx = await conn.fetchval(
                    """
                    SELECT 1 FROM transactions
                    WHERE sender_account_id = $1 
                      AND receiver_account_id = $2
                      AND amount BETWEEN $3 AND $4
                      AND timestamp >= ($5::timestamptz - ($6 || ' hours')::interval)
                    LIMIT 1;
                    """,
                    receiver_id, sender_id, min_amt, max_amt, timestamp, str(window_hours)
                )
                if reverse_tx:
                    return ["ROUND_TRIP_DETECTION"]
        except Exception as e:
            logger.debug(f"Round-trip check error: {e}")
        return []

    @staticmethod
    async def _check_newly_incorporated(
        config: dict,
        amount: float,
        sender_id: str,
        timestamp: datetime,
        tenant_id: str
    ) -> list[str]:
        newly_inc_config = config.get("rules", {}).get("NEWLY_INCORPORATED_HIGH_VALUE", {})
        if not newly_inc_config.get("enabled", True) or not sender_id:
            return []
        high_value_threshold = newly_inc_config.get("high_value_threshold", 50000.0)
        if amount < high_value_threshold:
            return []

        try:
            sender_uuid = uuid.UUID(str(sender_id))
        except (ValueError, TypeError):
            return []

        account_age_days = newly_inc_config.get("account_age_days", 90)
        try:
            async with get_async_db_conn(tenant_id=tenant_id) as conn:
                acc_created_at = await conn.fetchval(
                    "SELECT created_at FROM accounts WHERE id = $1;",
                    sender_uuid
                )
                if acc_created_at:
                    if acc_created_at.tzinfo is None:
                        acc_created_at = acc_created_at.replace(tzinfo=timezone.utc)
                    curr_ts = timestamp or datetime.now(timezone.utc)
                    if curr_ts.tzinfo is None:
                        curr_ts = curr_ts.replace(tzinfo=timezone.utc)
                    age_days = (curr_ts - acc_created_at).days
                    if age_days <= account_age_days:
                        return ["NEWLY_INCORPORATED_HIGH_VALUE"]
        except Exception as e:
            logger.debug(f"Newly incorporated check error: {e}")
        return []

    @staticmethod
    def _check_tbml(config: dict, amount: float, meta: dict) -> list[str]:
        tbml_config = config.get("rules", {}).get("TRADE_BASED_ML_OVER_UNDER_INVOICING", {})
        if not tbml_config.get("enabled", True):
            return []
        var_thresh = tbml_config.get("unit_price_variance_threshold_pct", 35.0)
        inv_thresh = tbml_config.get("invoice_amount_threshold", 100000.0)
        high_risk_goods = [g.upper() for g in tbml_config.get("high_risk_goods", ["PRECIOUS_METALS", "ELECTRONICS", "PETROLEUM", "PHARMACEUTICALS", "LUXURY_GOODS"])]

        declared_goods = str(meta.get("goods_category", "")).upper()
        unit_price_variance = float(meta.get("unit_price_variance_pct", 0.0))
        invoice_val = float(meta.get("invoice_amount", 0.0))

        is_high_risk_category = declared_goods in high_risk_goods
        has_price_variance = unit_price_variance >= var_thresh
        has_invoice_discrepancy = (invoice_val >= inv_thresh and abs(amount - invoice_val) / max(invoice_val, 1.0) >= 0.20)

        if is_high_risk_category and (has_price_variance or has_invoice_discrepancy):
            return ["TRADE_BASED_ML_OVER_UNDER_INVOICING"]
        return []

    @staticmethod
    def _check_vasp_crypto(
        config: dict,
        amount: float,
        sender_bic: str,
        receiver_bic: str,
        meta: dict
    ) -> list[str]:
        crypto_config = config.get("rules", {}).get("CRYPTO_FIAT_VASP_STRUCTURING", {})
        if not crypto_config.get("enabled", True):
            return []
        if not _is_vasp_transaction(meta, sender_bic, receiver_bic):
            return []

        travel_rule_thresh = crypto_config.get("travel_rule_threshold", 1000.0)
        travel_rule_complete = meta.get("travel_rule_complete", True)
        if amount >= travel_rule_thresh and not travel_rule_complete:
            return ["CRYPTO_FIAT_VASP_STRUCTURING"]

        rapid_count = int(meta.get("rapid_conversion_count", 0))
        max_conversions = crypto_config.get("max_consecutive_conversions", 3)
        if rapid_count >= max_conversions:
            return ["CRYPTO_FIAT_VASP_STRUCTURING"]

        return []

    @staticmethod
    async def _check_structuring_extended_7d(
        config: dict,
        amount: float,
        sender_id: str,
        sender_name: str,
        entity_id: str,
        tier_discount: float,
        timestamp: datetime,
        meta: dict,
        tenant_id: str
    ) -> list[str]:
        ext_struct_cfg = config.get("rules", {}).get("STRUCTURING_EXTENDED_7D", {})
        if not (ext_struct_cfg.get("enabled", True) and sender_id):
            return []
        window_days = ext_struct_cfg.get("window_days", 7)
        min_sub_amt = ext_struct_cfg.get("min_sub_amount", 2500.0) * tier_discount
        target_thresh = ext_struct_cfg.get("threshold", 10000.0) * tier_discount
        min_count = ext_struct_cfg.get("min_count", 3)
        tx_time = timestamp or datetime.now(timezone.utc)

        if min_sub_amt <= amount < target_thresh:
            try:
                async with get_async_db_conn(tenant_id=tenant_id) as conn:
                    query_7d = """
                        SELECT 
                            COALESCE(SUM(t.amount), 0.0) AS total_sub_amount,
                            COUNT(*) AS sub_count
                        FROM transactions t
                        WHERE (
                            t.sender_account_id = $1::uuid
                            OR t.sender_account_id IN (
                                SELECT a.id FROM accounts a
                                WHERE (a.customer_id IS NOT NULL AND a.customer_id = $6::text)
                                   OR (a.tax_id IS NOT NULL AND a.tax_id = $7::text)
                                   OR (a.owner_name = $8::text AND a.owner_name != '')
                            )
                        )
                          AND t.status IN ('COMPLETED', 'PENDING', 'HELD')
                          AND t.amount >= $2 AND t.amount < $3
                          AND t.timestamp >= ($4::timestamptz - ($5 || ' days')::interval)
                          AND t.timestamp < $4::timestamptz;
                    """
                    row_7d = await conn.fetchrow(
                        query_7d,
                        sender_id, min_sub_amt, target_thresh, tx_time, str(window_days),
                        str(entity_id), str(meta.get("tax_id") or ""), str(sender_name or "")
                    )
                    if row_7d:
                        prior_amt = float(row_7d["total_sub_amount"])
                        prior_cnt = int(row_7d["sub_count"])
                        if (prior_cnt + 1) >= min_count and (prior_amt + amount) >= target_thresh:
                            return ["STRUCTURING_EXTENDED_7D"]
            except Exception as e:
                logger.debug(f"Extended structuring check error: {e}")
        return []

    @staticmethod
    async def _check_conduit_passthrough(
        config: dict,
        amount: float,
        sender_id: str,
        tier_discount: float,
        timestamp: datetime,
        tenant_id: str
    ) -> list[str]:
        conduit_cfg = config.get("rules", {}).get("CONDUIT_RAPID_PASSTHROUGH", {})
        if not (conduit_cfg.get("enabled", True) and sender_id):
            return []
        window_hours = conduit_cfg.get("window_hours", 24)
        min_inflow = conduit_cfg.get("min_inflow", 5000.0) * tier_discount
        min_ratio = conduit_cfg.get("min_ratio", 0.85)
        max_ratio = conduit_cfg.get("max_ratio", 1.15)
        tx_time = timestamp or datetime.now(timezone.utc)

        try:
            async with get_async_db_conn(tenant_id=tenant_id) as conn:
                query_flow = """
                    WITH flow_window AS (
                        SELECT
                            COALESCE(SUM(CASE WHEN receiver_account_id = $1::uuid THEN amount ELSE 0 END), 0.0) AS total_inflow,
                            COALESCE(SUM(CASE WHEN sender_account_id = $1::uuid THEN amount ELSE 0 END), 0.0) AS total_outflow
                        FROM transactions
                        WHERE (receiver_account_id = $1::uuid OR sender_account_id = $1::uuid)
                          AND status IN ('COMPLETED', 'PENDING', 'HELD')
                          AND timestamp >= ($2::timestamptz - ($3 || ' hours')::interval)
                          AND timestamp < $2::timestamptz
                    )
                    SELECT total_inflow, total_outflow FROM flow_window;
                """
                row_flow = await conn.fetchrow(query_flow, sender_id, tx_time, str(window_hours))
                if row_flow:
                    inflow = float(row_flow["total_inflow"])
                    prior_out = float(row_flow["total_outflow"])
                    total_out = prior_out + amount
                    if inflow >= min_inflow:
                        flow_ratio = total_out / max(inflow, 1.0)
                        if min_ratio <= flow_ratio <= max_ratio:
                            return ["CONDUIT_RAPID_PASSTHROUGH"]
        except Exception as e:
            logger.debug(f"Conduit flow-through check error: {e}")
        return []

    @staticmethod
    def _check_amount_anomaly(
        config: dict,
        amount: float,
        total_entity_amount: float,
        entity_below: list[float]
    ) -> list[str]:
        anom_cfg = config.get("rules", {}).get("AMOUNT_ANOMALY_HEURISTICS", {})
        if not anom_cfg.get("enabled", True):
            return []
        triggered = []
        just_below_min = anom_cfg.get("just_below_min", 9000.0)
        just_below_max = anom_cfg.get("just_below_max", 10000.0)
        round_min = anom_cfg.get("round_number_min", 3000.0)
        round_divisor = anom_cfg.get("round_divisor", 1000.0)

        is_just_below = (just_below_min <= amount < just_below_max)
        if not is_just_below and (just_below_min <= total_entity_amount < just_below_max) and len(entity_below) >= 2:
            is_just_below = True

        if is_just_below:
            triggered.append("JUST_BELOW_CTR_THRESHOLD")

        if amount >= round_min and (int(round(amount * 100)) % int(round(round_divisor * 100)) == 0):
            triggered.append("ROUND_NUMBER_ANOMALY_1K")

        return triggered

    @staticmethod
    async def evaluate_transaction(
        sender_id: str,
        receiver_id: str,
        amount: float,
        sender_name: str = None,
        sender_bic: str = None,
        receiver_name: str = None,
        receiver_bic: str = None,
        timestamp: datetime = None,
        tenant_id: str = None,
        metadata: dict = None,
        sender_account_number: str = None,
        receiver_account_number: str = None,
        **kwargs
    ) -> list[str]:
        triggered_rules = []
        config = get_rules_config()
        meta = metadata or {}

        entity_id = await RulesEngine._resolve_entity_id(sender_id, sender_name, meta, tenant_id)

        # 1. LARGE_TRANSACTION Rule
        triggered_rules.extend(RulesEngine._check_large_transaction(config, amount))

        # 2. STRUCTURING_SMURFING Rule
        struct_rules, total_entity_amount, entity_below = await RulesEngine._check_structuring_smurfing(
            config, amount, sender_id, entity_id, tenant_id
        )
        triggered_rules.extend(struct_rules)

        # 3. VELOCITY_MONITORING Rule
        triggered_rules.extend(await RulesEngine._check_velocity_monitoring(
            config, amount, sender_id, timestamp, tenant_id
        ))

        # 4. RAPID_MOVEMENT_FUNDS Rule
        triggered_rules.extend(await RulesEngine._check_rapid_movement_funds(
            config, amount, sender_id, timestamp, tenant_id
        ))

        # 5. DORMANT_ACCOUNT Activation Rule
        triggered_rules.extend(await RulesEngine._check_dormant_account(
            config, amount, sender_id, timestamp, tenant_id
        ))

        # 6. GEOGRAPHIC_SANCTIONS Rule
        triggered_rules.extend(await RulesEngine._check_geographic_sanctions(
            config, sender_bic, receiver_bic, sender_name, receiver_name, tenant_id, entity_id
        ))

        # 7. ROUND_TRIP_DETECTION
        triggered_rules.extend(await RulesEngine._check_round_trip(
            config, amount, sender_id, receiver_id, timestamp, tenant_id
        ))

        # 8. NEWLY_INCORPORATED_HIGH_VALUE
        triggered_rules.extend(await RulesEngine._check_newly_incorporated(
            config, amount, sender_id, timestamp, tenant_id
        ))

        # 9. TRADE_BASED_ML_OVER_UNDER_INVOICING
        triggered_rules.extend(RulesEngine._check_tbml(config, amount, meta))

        # 10. CRYPTO_FIAT_VASP_STRUCTURING
        triggered_rules.extend(RulesEngine._check_vasp_crypto(
            config, amount, sender_bic, receiver_bic, meta
        ))

        # Risk tier discount (FATF RBA)
        kyc_risk_tier = str(meta.get("kyc_risk_tier", "STANDARD")).upper()
        tier_discount = 0.50 if kyc_risk_tier in ("HIGH", "CRITICAL") else 1.00

        # 11. STRUCTURING_EXTENDED_7D
        triggered_rules.extend(await RulesEngine._check_structuring_extended_7d(
            config, amount, sender_id, sender_name, entity_id, tier_discount, timestamp, meta, tenant_id
        ))

        # 12. CONDUIT_RAPID_PASSTHROUGH
        triggered_rules.extend(await RulesEngine._check_conduit_passthrough(
            config, amount, sender_id, tier_discount, timestamp, tenant_id
        ))

        # 13. AMOUNT_ANOMALY_HEURISTICS
        triggered_rules.extend(RulesEngine._check_amount_anomaly(
            config, amount, total_entity_amount, entity_below
        ))

        return triggered_rules


async def start_redis_rules_listener(shutdown_event=None):
    """Listens for distributed rules cache invalidation events across horizontal pods."""
    from database.redis_db import get_async_redis_client
    import asyncio
    while shutdown_event is None or not shutdown_event.is_set():
        try:
            redis = await get_async_redis_client()
            if redis is None:
                await asyncio.sleep(5)
                continue
            pubsub = redis.pubsub()
            await pubsub.subscribe("aml:rules:cache_invalidate")
            logger.info("Subscribed to Redis channel 'aml:rules:cache_invalidate'")
            while shutdown_event is None or not shutdown_event.is_set():
                msg = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
                if msg and msg.get("type") == "message":
                    RulesEngine.reload_config()
                await asyncio.sleep(0.5)
        except Exception as e:
            logger.debug(f"Redis rules invalidation listener error: {e}")
            await asyncio.sleep(5)
