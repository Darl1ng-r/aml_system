"""
Comprehensive Mathematical, Algorithmic, Property & Security Remediation Suite
==============================================================================
Verifies every fix and algorithmic upgrade across Phases A–D:
  - Seeded property testing of the absorbing Markov-chain UBO solver (500 DAGs + cross-holdings + closed loops)
  - Exact Hamilton basis-points attribution reconciliation across 5,000 randomized risk profiles
  - Simple-digraph Brandes centrality & unique-counterparty Fan-In/Fan-Out invariants
  - Exhaustive CTR boundary grid + fail-closed NaN/Inf/negative + Travel Rule conservative fallback
  - Tenant-isolated, byte-safe, monotonic Decimal Feature Store
  - Semi-supervised Isolation Forest retraining & SR 11-7 Champion/Challenger promotion gate
  - Kafka zero-loss partition seek/break & poison-pill DLQ routing
  - Non-dict asyncpg.Record-like Mapping auth MFA/is_active enforcement
  - Unvalidated X-API-Key rate-limit DoS & State Redis OOM protection
  - Customer-scoped vs entity-wide whitelist isolation
  - STR batch XML end-to-end validation & FinCEN REJECTED preservation
  - Rule backtest domain parity, warm-up window, and precision/recall/F1 metrics
  - Complete ISO-4217 FX fallback coverage & fail-closed FxRateUnavailableError
"""

from __future__ import annotations

import json
import math
import random
import uuid
from collections import namedtuple
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import numpy as np
import pytest
from fastapi import HTTPException, Request

from domain.money import CURRENCY_EXPONENTS, FxRateUnavailableError, InvalidMoneyError, invert_fx_rate, quantize_amount
from domain.rules_core import (
    check_newly_incorporated_pure,
    check_rapid_movement_pure,
    check_structuring_smurfing_pure,
    check_tbml_pure,
    check_vasp_crypto_pure,
    evaluate_ctr_and_structuring_pure,
    evaluate_travel_rule_pure,
    AccountRuleSnapshot,
)
from domain.scoring_core import TAINT_FLOOR_THRESHOLD, compute_dynamic_risk_pure
from domain.ubo_core import resolve_ubo_ownership_tree_pure
from services.behavioral import _calculate_frequencies, _compute_circular_hour_stats
from services.feature_store import get_rolling_window_features, record_transaction_feature_event
from services.feedback_loop import evaluate_challenger_promotion_gate
from services.fx_rates import FALLBACK_RATES_AS_OF, FALLBACK_RATES_TO_USD_DECIMAL, get_fallback_fx_rate_decimal, get_fx_rate_with_provenance
from services.isolation_forest import IsolationForestScratch, _generate_synthetic_training_data
from services.network_analysis import _add_edge_to_graph, _compute_degree_fallback, compute_betweenness_centrality
from services.rule_backtest import _run_backtest_replay_sync, evaluate_rule_on_tx_row
from services.sar_validator import validate_regulatory_xml
from services.str_batch_engine import STRBatchEngine


# ── 1. UBO Absorbing Markov-Chain Solver (500 Seeded DAGs + Cross-Holdings + Closed Loop) ─

def _brute_force_dag_ubo(edges: list[dict], target: str) -> dict[str, Decimal]:
    """Reference brute-force path enumeration for acyclic graphs."""
    by_child: dict[str, list[tuple[str, str, Decimal]]] = {}
    for e in edges:
        by_child.setdefault(e["child_company_name"].lower(), []).append(
            (e["parent_entity_name"].lower(), e["parent_entity_type"], Decimal(str(e["ownership_pct"])))
        )

    stakes: dict[str, Decimal] = {}

    def dfs(node: str, factor: Decimal):
        for p, ptype, pct in by_child.get(node, []):
            nf = factor * (pct / Decimal("100"))
            if ptype == "PERSON" or not by_child.get(p):
                stakes[p] = stakes.get(p, Decimal("0")) + nf * Decimal("100")
            else:
                dfs(p, nf)

    dfs(target.lower(), Decimal("1"))
    return stakes


def test_ubo_markov_solver_matches_bruteforce_on_500_seeded_dags():
    rng = random.Random(20261128)
    for trial in range(500):
        n_corps = rng.randint(2, 6)
        n_persons = rng.randint(1, 4)
        corps = [f"Corp_{i}" for i in range(n_corps)]
        persons = [f"Person_{i}" for i in range(n_persons)]
        edges: list[dict] = []

        # Strict topological order: Corp_i can only be owned by Corp_j (j > i) or any Person
        for i in range(n_corps):
            candidates = [(c, "COMPANY") for c in corps[i + 1 :]] + [(p, "PERSON") for p in persons]
            rng.shuffle(candidates)
            k = rng.randint(0, min(3, len(candidates)))
            chosen = candidates[:k]
            remaining = 100
            for idx, (pname, ptype) in enumerate(chosen):
                if remaining <= 0:
                    break
                max_share = remaining if idx == len(chosen) - 1 else max(1, remaining // 2)
                pct = rng.randint(1, max_share)
                remaining -= pct
                edges.append({
                    "child_company_name": corps[i],
                    "parent_entity_name": pname,
                    "parent_entity_type": ptype,
                    "ownership_pct": pct,
                })

        expected = _brute_force_dag_ubo(edges, "Corp_0")
        actual = resolve_ubo_ownership_tree_pure(edges, "Corp_0", threshold_pct=25.0)
        assert actual["cycles_detected"] is False
        assert actual["ownership_loop_unresolved"] is False
        actual_map = {
            u["entity_name"].lower(): Decimal(str(u["effective_ownership_pct"]))
            for u in actual["ultimate_beneficial_owners"]
        }
        assert set(actual_map.keys()) == set(expected.keys()), f"Trial {trial} key mismatch"
        for k, exp_val in expected.items():
            exp_rounded = exp_val.quantize(Decimal("0.01"))
            assert abs(actual_map[k] - exp_rounded) <= Decimal("0.01"), (
                f"Trial {trial} owner {k}: expected {exp_rounded}, got {actual_map[k]}"
            )


def test_ubo_cross_holding_exact_40_87_over_allocated_unrounded_threshold_and_closed_loop():
    # Audit cross-ownership counterexample:
    # Target: 15% Alice, 85% HoldCo; HoldCo: 50% Target, 10% Alice, 40% Bob
    # True economic stake: Alice = (15 + 8.5)/(1 - 0.425) = 40.8696% -> 40.87%, Bob = 59.13%
    cross_edges = [
        {"child_company_name": "Target", "parent_entity_name": "Alice", "parent_entity_type": "PERSON", "ownership_pct": 15},
        {"child_company_name": "Target", "parent_entity_name": "HoldCo", "parent_entity_type": "COMPANY", "ownership_pct": 85},
        {"child_company_name": "HoldCo", "parent_entity_name": "Target", "parent_entity_type": "COMPANY", "ownership_pct": 50},
        {"child_company_name": "HoldCo", "parent_entity_name": "Alice", "parent_entity_type": "PERSON", "ownership_pct": 10},
        {"child_company_name": "HoldCo", "parent_entity_name": "Bob", "parent_entity_type": "PERSON", "ownership_pct": 40},
    ]
    res = resolve_ubo_ownership_tree_pure(cross_edges, "Target", threshold_pct=25.0)
    assert res["cycles_detected"] is True
    assert res["ownership_loop_unresolved"] is False
    by_name = {u["entity_name"]: u for u in res["ultimate_beneficial_owners"]}
    assert by_name["Alice"]["effective_ownership_pct"] == 40.87
    assert by_name["Alice"]["exceeds_threshold"] is True
    assert by_name["Bob"]["effective_ownership_pct"] == 59.13
    assert res["unattributed_ownership_pct"] == 0.0

    # Pure closed loop with no external owners (spectral radius = 1) -> ownership_loop_unresolved=True
    closed_loop = [
        {"child_company_name": "A", "parent_entity_name": "B", "parent_entity_type": "COMPANY", "ownership_pct": 100},
        {"child_company_name": "B", "parent_entity_name": "A", "parent_entity_type": "COMPANY", "ownership_pct": 100},
    ]
    res_loop = resolve_ubo_ownership_tree_pure(closed_loop, "A")
    assert res_loop["cycles_detected"] is True
    assert res_loop["ownership_loop_unresolved"] is True
    assert res_loop["unattributed_ownership_pct"] == 100.0

    # Over-allocated entity (70% + 70% = 140%) scaled proportionally to 50% + 50%
    over_alloc = [
        {"child_company_name": "Over", "parent_entity_name": "Alice", "parent_entity_type": "PERSON", "ownership_pct": 70},
        {"child_company_name": "Over", "parent_entity_name": "Bob", "parent_entity_type": "PERSON", "ownership_pct": 70},
    ]
    res_over = resolve_ubo_ownership_tree_pure(over_alloc, "Over")
    assert "Over" in res_over["over_allocated_entities"]
    assert all(u["effective_ownership_pct"] == 50.0 for u in res_over["ultimate_beneficial_owners"])

    # Unrounded threshold comparison: 33.333% >= 33.333% must be True
    boundary = [{"child_company_name": "T", "parent_entity_name": "Alice", "parent_entity_type": "PERSON", "ownership_pct": "33.333"}]
    res_b = resolve_ubo_ownership_tree_pure(boundary, "T", threshold_pct=Decimal("33.333"))
    assert res_b["ultimate_beneficial_owners"][0]["exceeds_threshold"] is True


# ── 2. Exact Hamilton Basis-Points Attribution (5,000 Random Inputs) ─────────

def test_scoring_hamilton_bps_apportionment_exact_across_5000_random_profiles():
    rng = random.Random(42)
    pep_choices = [None, "", "NONE", "N/A", "   ", "TIER_1", "TIER_2", "TIER_3", "LOCAL"]
    rule_choices = [[], ["LARGE_TRANSACTION_THRESHOLD"], ["SANCTIONS_HIT"], ["A", "B", "C", "D"]]

    for _ in range(5000):
        rules = rng.choice(rule_choices)
        ml = rng.random()
        ifo = rng.random()
        amt = rng.uniform(0.0, 250000.0)
        avg = rng.uniform(0.0, 50000.0)
        var = rng.uniform(0.0, 1e9)
        sr = rng.random()
        rr = rng.random()
        jr = rng.random()
        pep = rng.choice(pep_choices)
        taint = rng.random()

        res = compute_dynamic_risk_pure(
            rules_triggered=rules,
            ml_score=ml,
            amount=amt,
            baseline={"avg_amount": avg, "variance_amount": var},
            iforest_score=ifo,
            sender_risk=sr,
            receiver_risk=rr,
            pep_tier=pep,
            jurisdiction_risk=jr,
            taint_risk=taint,
        )
        expl = res["explainability"]
        rec = expl["reconciled_contributions"]
        # Exact basis-point equality (not just loose tolerance!)
        rec_bps = sum(int(round(v * 10_000)) for v in rec.values())
        final_bps = int(round(res["dynamic_risk_score"] * 10_000))
        assert rec_bps == final_bps
        assert expl["efficiency_axiom_verified"] is True

        # Null PEP tokens must produce 0.0 elevation and never appear in top_drivers
        if pep in (None, "", "NONE", "N/A", "   "):
            assert expl["pep_elevation"] == 0.0
            assert not any("POLITICALLY_EXPOSED_PERSON" in d for d in res["top_drivers"])

    # Specific audit rounding counterexample: no floor/clamp triggered -> neither key emitted!
    res_exact = compute_dynamic_risk_pure(
        [], 0.11115, 100.0, {}, 0.11115, sender_risk=0.1114, receiver_risk=0.1114, jurisdiction_risk=0.1114
    )
    rec_exact = res_exact["explainability"]["reconciled_contributions"]
    assert "regulatory_floor_elevation" not in rec_exact
    assert "saturation_clamp_damping" not in rec_exact
    assert res_exact["explainability"]["attribution_sum"] == res_exact["dynamic_risk_score"]
    assert TAINT_FLOOR_THRESHOLD == 0.60


# ── 3. Simple-Digraph Brandes Centrality & Unique Degrees ────────────────────

def test_network_analysis_simple_digraph_invariance_and_self_loop_exclusion():
    simple = {"A": ["B", "D"], "B": ["C"], "D": ["C"], "C": []}
    multi = {"A": ["A", "B"] + ["B"] * 10 + ["D"], "B": ["B", "C", "C"], "D": ["C"], "C": ["C"]}

    cb_simple = compute_betweenness_centrality(simple)
    cb_multi = compute_betweenness_centrality(multi)
    assert cb_simple == cb_multi
    assert cb_multi["B"] == cb_multi["D"]
    assert all(0.0 <= v <= 1.0 for v in cb_multi.values())

    fi, fo = _compute_degree_fallback(multi)
    assert fi == [] and fo == []

    # _add_edge_to_graph tracks multiplicity separately while keeping graph simple
    g: dict = {}
    weights: dict = {}
    _add_edge_to_graph(g, "X", "X", weights)
    assert g == {}
    for _ in range(5):
        _add_edge_to_graph(g, "X", "Y", weights)
    assert g["X"] == ["Y"]
    assert weights[("X", "Y")] == 5


# ── 4. CTR Boundary Grid, Rules Guards & Travel Rule Conservative Fallback ───

def test_ctr_boundary_grid_and_fail_closed_hostile_amounts():
    # Legitimate single >= $10k cash -> CTR required, NOT structuring
    for amt in (Decimal("10000.00"), Decimal("15000.00"), Decimal("9999.995")):
        d = evaluate_ctr_and_structuring_pure(amt, "CASH", None, Decimal("0"), 0)
        assert d.requires_ctr_filing is True
        assert d.structuring_detected is False

    # $0 cash after $10,000 prior cash must NOT trigger CTR or structuring
    d_zero = evaluate_ctr_and_structuring_pure(Decimal("0"), "CASH", None, Decimal("10000"), 1)
    assert d_zero.requires_ctr_filing is False
    assert d_zero.structuring_detected is False

    # $20,000 cash after $100 prior cash -> CTR required, NOT structuring
    d_large = evaluate_ctr_and_structuring_pure(Decimal("20000"), "CASH", None, Decimal("100"), 1)
    assert d_large.requires_ctr_filing is True
    assert d_large.structuring_detected is False

    # Two sub-threshold legs ($5,000 + $5,000) -> BOTH CTR & structuring
    d_smurf = evaluate_ctr_and_structuring_pure(Decimal("5000"), "CASH", None, Decimal("5000"), 1)
    assert d_smurf.requires_ctr_filing is True
    assert d_smurf.structuring_detected is True

    # Hostile non-finite / negative -> InvalidMoneyError (fail closed)
    for bad in (float("nan"), float("inf"), float("-inf"), -100, "not_a_num"):
        with pytest.raises(InvalidMoneyError):
            evaluate_ctr_and_structuring_pure(bad, "CASH", None)

    # Structuring pure rule does not trigger on $50k above-threshold transfer
    trig, _, _ = check_structuring_smurfing_pure({}, Decimal("50000"), [Decimal("5500"), Decimal("5500")], [Decimal("5500"), Decimal("5500")])
    assert trig == []

    # Rapid movement does not trigger on $0
    now = datetime.now(timezone.utc)
    assert check_rapid_movement_pure({}, Decimal("0"), now, AccountRuleSnapshot(last_incoming_amount_usd=Decimal("0"), last_incoming_at=now)) == []

    # Backdated tx does not trigger newly incorporated
    assert check_newly_incorporated_pure({}, Decimal("60000"), now - timedelta(days=5), AccountRuleSnapshot(account_created_at=now)) == []

    # VASP strict bool("false") == False and int(None) == 0
    assert check_vasp_crypto_pure({}, Decimal("2000"), None, None, {"is_vasp_transfer": True, "travel_rule_complete": "false", "rapid_conversion_count": None}) == ["CRYPTO_FIAT_VASP_STRUCTURING"]

    # Non-USD/EUR wire without amount_usd fails conservatively (requires Travel Rule fields)
    ok_gbp, missing = evaluate_travel_rule_pure(Decimal("2500"), "GBP", "WIRE", {}, {}, amount_usd=None)
    assert ok_gbp is False and "originator_name" in missing

    # invert_fx_rate rejects underflow to 0E-8
    with pytest.raises(InvalidMoneyError):
        invert_fx_rate(Decimal("1e9"))


# ── 5. Feature Store: Monotonicity, Tenant Isolation, Bytes & Colon tx_id ────

@pytest.mark.anyio
async def test_feature_store_monotonic_tenant_isolated_bytes_and_colon_tx_id():
    store: dict[str, list[tuple[bytes, float]]] = {}

    class FakeBytesRedis:
        async def zadd(self, key: str, mapping: dict):
            bucket = store.setdefault(key, [])
            for m, sc in mapping.items():
                bucket.append((m.encode("utf-8"), float(sc)))

        async def zremrangebyscore(self, key: str, _min, max_sc):
            if key in store:
                store[key] = [(m, s) for m, s in store[key] if s > float(max_sc)]

        async def expire(self, key: str, ttl: int):
            return True

        async def zrangebyscore(self, key: str, min, max, withscores=False):
            items = [(m, s) for m, s in store.get(key, []) if float(min) <= s <= float(max)]
            return items if withscores else [m for m, _ in items]

    fake = FakeBytesRedis()
    now = 1_750_000_000.0
    with patch("services.feature_store.get_async_redis_client", AsyncMock(return_value=fake)):
        # tx_id containing colons + tenant isolation
        await record_transaction_feature_event("ACC-1", Decimal("100.10"), "tx:2026:a", ts_epoch=now - 600, tenant_id="tenant-a")
        await record_transaction_feature_event("ACC-1", Decimal("200.20"), "tx:2026:b", ts_epoch=now - 7200, tenant_id="tenant-a")
        await record_transaction_feature_event("ACC-1", Decimal("300.30"), "tx:2026:c", ts_epoch=now - 3 * 86400, tenant_id="tenant-a")
        await record_transaction_feature_event("ACC-1", Decimal("99999.00"), "tx:other", ts_epoch=now - 10, tenant_id="tenant-b")

        feats_a = await get_rolling_window_features("ACC-1", current_epoch=now, tenant_id="tenant-a")
        feats_b = await get_rolling_window_features("ACC-1", current_epoch=now, tenant_id="tenant-b")

    assert feats_a["velocity_1h"] == 1 and feats_a["amount_1h"] == 100.10
    assert feats_a["velocity_24h"] == 2 and feats_a["amount_24h"] == 300.30
    assert feats_a["velocity_7d"] == 3 and feats_a["amount_7d"] == 600.60
    assert feats_a["velocity_1h"] <= feats_a["velocity_24h"] <= feats_a["velocity_7d"]
    assert feats_b["velocity_1h"] == 1 and feats_b["amount_1h"] == 99999.0


# ── 6. Semi-Supervised Isolation Forest & Champion/Challenger Gate ───────────

def test_semi_supervised_iforest_and_champion_challenger_gate():
    X_base = _generate_synthetic_training_data()
    fp_samples = np.array([
        [450.0, 0.12, 0.15, 13.0, 0.0],
        [620.0, 0.10, 0.14, 15.0, 0.0],
        [510.0, 0.11, 0.12, 11.0, 0.0],
    ])
    sar_samples = np.array([
        [500000.0, 0.94, 0.92, 2.0, 1.0],
        [480000.0, 0.91, 0.95, 3.0, 1.0],
        [525000.0, 0.96, 0.90, 2.0, 1.0],
    ])

    # Good challenger: trained ONLY on baseline + FP*2 (SARs excluded)
    good_challenger = IsolationForestScratch(n_estimators=60, max_samples=128, seed=42).fit(
        np.vstack([X_base, fp_samples, fp_samples])
    )
    sar_scores = [good_challenger.compute_anomaly_score(r) for r in sar_samples]
    fp_scores = [good_challenger.compute_anomaly_score(r) for r in fp_samples]
    assert np.mean(sar_scores) > np.median(fp_scores)

    ok_good, _ = evaluate_challenger_promotion_gate(None, good_challenger, fp_samples, sar_samples)
    assert ok_good is True

    # Poisoned challenger (old bug: fitted directly on SARs!) MUST BE REJECTED by gate!
    poisoned = IsolationForestScratch(n_estimators=60, max_samples=3, seed=42).fit(sar_samples)
    ok_bad, metrics_bad = evaluate_challenger_promotion_gate(good_challenger, poisoned, fp_samples, sar_samples)
    assert ok_bad is False
    assert "rejection_reason" in metrics_bad


# ── 7. Kafka Zero-Loss Partition Seek & Break + Poison-Pill DLQ ──────────────

@pytest.mark.anyio
async def test_kafka_zero_loss_seeks_and_breaks_and_routes_poison_pill_bytes():
    from workers.scoring_worker import process_partition_batch

    _TP = namedtuple("TopicPartition", ["topic", "partition"])
    tp = _TP("aml.transactions.raw", 0)
    msg_fail = SimpleNamespace(offset=10, value=b'{"transaction_id":"tx-fail","tenant_id":"t1"}')
    msg_ok = SimpleNamespace(offset=11, value=b'{"transaction_id":"tx-ok","tenant_id":"t1"}')

    consumer = MagicMock(commit=AsyncMock(), seek=MagicMock())
    dlq_down = MagicMock(send_and_wait=AsyncMock(side_effect=RuntimeError("broker down")))

    async def _score_side_effect(payload):
        if payload["transaction_id"] == "tx-fail":
            raise RuntimeError("db timeout")

    with patch("workers.scoring_worker.score_transaction", side_effect=_score_side_effect), \
         patch("workers.scoring_worker.asyncio.sleep", AsyncMock()):
        res = await process_partition_batch({tp: [msg_fail, msg_ok]}, dlq_down, consumer)

    # Zero-loss: msg 10 blocked -> seek(tp, 10) and NEVER process or commit msg 11!
    assert res["blocked"] == 1 and res["committed"] == 0
    consumer.commit.assert_not_awaited()
    consumer.seek.assert_called_once_with(tp, 10)

    # Poison-pill malformed JSON bytes route to DLQ cleanly without crashing
    msg_poison = SimpleNamespace(offset=12, value=b"{not-valid-json!!")
    dlq_up = MagicMock(send_and_wait=AsyncMock())
    consumer2 = MagicMock(commit=AsyncMock(), seek=MagicMock())
    res2 = await process_partition_batch({tp: [msg_poison]}, dlq_up, consumer2)
    assert res2["dlq"] == 1
    consumer2.commit.assert_awaited_once_with({tp: 13})


# ── 8. Auth Non-Dict Record-Like Mapping (asyncpg.Record) Enforcement ────────

@pytest.mark.anyio
async def test_auth_repo_handles_non_dict_record_mapping_for_is_active_and_mfa():
    from repositories.auth_repo import upsert_supabase_login_user_atomic

    class FakeAsyncpgRecord(Mapping):
        def __init__(self, data: dict):
            self._d = data

        def __getitem__(self, k):
            return self._d[k]

        def __iter__(self):
            return iter(self._d)

        def __len__(self):
            return len(self._d)

    assert not isinstance(FakeAsyncpgRecord({}), dict)

    # Disabled user MUST get 401
    conn_disabled = AsyncMock()
    conn_disabled.fetchrow = AsyncMock(return_value=FakeAsyncpgRecord({"is_active": False, "mfa_enabled": False, "token_version": 1}))
    ctx_disabled = AsyncMock()
    ctx_disabled.__aenter__.return_value = conn_disabled
    ctx_disabled.__aexit__.return_value = None

    with pytest.raises(HTTPException) as exc:
        await upsert_supabase_login_user_atomic(
            user_id=str(uuid.uuid4()),
            username="blocked",
            role="ANALYST",
            tenant_id=str(uuid.uuid4()),
            hashed_pw="argon2id$stub",
            conn_factory=lambda **kw: ctx_disabled,
        )
    assert exc.value.status_code == 401

    # Active MFA user preserves mfa_enabled=True & token_version=7
    conn_mfa = AsyncMock()
    conn_mfa.fetchrow = AsyncMock(return_value=FakeAsyncpgRecord({"is_active": True, "mfa_enabled": True, "token_version": 7}))
    ctx_mfa = AsyncMock()
    ctx_mfa.__aenter__.return_value = conn_mfa
    ctx_mfa.__aexit__.return_value = None

    mfa, ver = await upsert_supabase_login_user_atomic(
        user_id=str(uuid.uuid4()),
        username="mfa_user",
        role="MLRO",
        tenant_id=str(uuid.uuid4()),
        hashed_pw="argon2id$stub",
        conn_factory=lambda **kw: ctx_mfa,
    )
    assert mfa is True and ver == 7


@pytest.mark.anyio
async def test_outbox_partition_drop_fails_closed_under_nobypassrls():
    """Defense-in-depth: BOTH Python runner and PostgreSQL function block NOBYPASSRLS partition drops."""
    import asyncpg
    from scripts.maintain_partitions import run_partition_maintenance
    from services.secrets_manager import get_postgres_dsn

    # 1. Python runner rejects drop under NOBYPASSRLS when privilege is required
    with pytest.raises(PermissionError, match="NOBYPASSRLS"):
        await run_partition_maintenance(
            outbox_weeks_ahead=4,
            audit_months_ahead=4,
            outbox_retention_weeks=2,
            require_drop_privilege=True,
        )

    # 2. PostgreSQL drop_expired_outbox_partitions() itself refuses under NOBYPASSRLS (SQLSTATE 42501)
    conn = await asyncpg.connect(get_postgres_dsn())
    try:
        can_bypass = await conn.fetchval(
            "SELECT COALESCE(rolbypassrls OR rolsuper, FALSE) FROM pg_roles WHERE rolname = current_user;"
        )
        if not can_bypass:
            with pytest.raises(asyncpg.InsufficientPrivilegeError):
                await conn.fetchval("SELECT drop_expired_outbox_partitions(2);")
    finally:
        await conn.close()


# ── 9. Rate Limiter Unvalidated X-API-Key DoS & OOM Defense ──────────────────

@pytest.mark.anyio
async def test_rate_limiter_blocks_200_random_unvalidated_api_keys_without_key_explosion():
    from services.rate_limiter import RateLimiter

    zsets: dict[str, list[str]] = {}

    class FakeEvalRedis:
        async def eval(self, script, numkeys, key, now_ms, window_start_ms, limit, window_ms, member):
            bucket = zsets.setdefault(key, [])
            if len(bucket) >= int(limit):
                return [0, len(bucket)]
            bucket.append(member)
            return [1, len(bucket)]

    limiter = RateLimiter(limit=5, window=60)
    fake_redis = FakeEvalRedis()
    allowed_count = 0
    rejected_count = 0

    with patch("services.rate_limiter.get_async_redis_client", AsyncMock(return_value=fake_redis)):
        for i in range(200):
            req = MagicMock(spec=Request)
            req.headers = {"X-API-Key": f"attacker-random-key-{i}-{uuid.uuid4()}"}
            req.cookies = {}
            req.client = MagicMock(host="198.51.100.77")
            req.state = SimpleNamespace(client_ip="198.51.100.77")
            req.url = MagicMock(path="/api/v1/transactions/ingest")
            req.scope = {"route": MagicMock(path="/api/v1/transactions/ingest")}
            try:
                await limiter(req)
                allowed_count += 1
            except HTTPException as exc:
                assert exc.status_code == 429
                rejected_count += 1

    assert allowed_count == 5 and rejected_count == 195
    # Zero per-random-header ZSET keys created in State Redis!
    assert len(zsets) == 1
    assert not any("apikey:" in k for k in zsets)


# ── 10. Whitelist Scope Isolation (Customer Row Never Poisons Entity Key) ────

@pytest.mark.anyio
async def test_whitelist_customer_scope_never_poisons_tenant_entity_cache():
    from services.whitelisting import _LOCAL_WHITELIST_STORE, _check_l3_db_whitelist, is_entity_whitelisted

    _LOCAL_WHITELIST_STORE.clear()
    tenant = str(uuid.uuid4())
    cust1_row = {
        "id": uuid.uuid4(),
        "tenant_id": tenant,
        "customer_id": "CUST-001",
        "matched_entity_name": "Sanctioned Shell LLC",
        "matched_rule": "SANCTIONS_HIT",
        "disposition": "FALSE_POSITIVE",
        "cleared_by": "mlro",
        "cleared_at": datetime.now(timezone.utc),
        "expires_at": datetime.now(timezone.utc) + timedelta(days=7),
        "notes": "Cust-1 only",
    }

    mock_conn_cust1 = AsyncMock()
    mock_conn_cust1.fetchrow = AsyncMock(return_value=cust1_row)
    mock_conn_cust2 = AsyncMock()
    mock_conn_cust2.fetchrow = AsyncMock(return_value=None)

    with patch("services.whitelisting.get_async_redis_client", AsyncMock(return_value=None)):
        # Customer 1 matches L3
        assert await _check_l3_db_whitelist(tenant, "SANCTIONS_HIT", "Sanctioned Shell LLC", "CUST-001", datetime.now(timezone.utc), conn=mock_conn_cust1) is True
        # Customer 2 MUST NOT be suppressed by L1 cache poisoning!
        assert await is_entity_whitelisted(tenant, "Sanctioned Shell LLC", "SANCTIONS_HIT", customer_id="CUST-002", conn=mock_conn_cust2) is False


# ── 11. STR Batch XML Validation, FinCEN REJECTED, Backtest Parity & FX Coverage ─

def test_str_batch_xml_passes_validator_and_goaml_negative_rejected():
    alerts = [
        {"id": "a1", "amount": Decimal("100.005"), "amount_base_usd": Decimal("100.005"), "currency": "USD", "rule_name": "STRUCTURING"},
        {"id": "a2", "amount": Decimal("250.005"), "amount_base_usd": Decimal("250.005"), "currency": "USD", "rule_name": "LARGE_TX"},
    ]
    xml = STRBatchEngine.construct_batch_xml("STR-BATCH-TEST-1", alerts)
    ok, errors = validate_regulatory_xml(xml, "FINCEN_BSABATCH")
    assert ok is True, f"Expected valid STR batch XML, got errors: {errors}"
    assert 'total_batch_amount="350.01"' in xml

    # Empty narrative rejected
    ok_empty, _ = validate_regulatory_xml("<SuspiciousActivityReport><Narrative>   </Narrative></SuspiciousActivityReport>")
    assert ok_empty is False

    # goAML negative amount_local rejected
    bad_goaml = (
        "<report><rentity_id>1</rentity_id><submission_code>E</submission_code><report_code>STR</report_code>"
        "<submission_date>2026-01-01</submission_date><currency_code_local>EUR</currency_code_local>"
        "<reason>Test</reason><transaction><transactionnumber>1</transactionnumber>"
        "<date_transaction>2026-01-01</date_transaction><amount_local>-500</amount_local></transaction></report>"
    )
    ok_g, _ = validate_regulatory_xml(bad_goaml, "GOAML_5")
    assert ok_g is False


@pytest.mark.anyio
async def test_fincen_rejected_receipt_never_marks_sar_draft_filed():
    from repositories.fincen_repo import persist_fincen_receipt_atomic

    executed_sql: list[str] = []
    mock_conn = AsyncMock()

    async def _record_exec(sql, *args):
        executed_sql.append(sql)

    mock_conn.execute = AsyncMock(side_effect=_record_exec)
    mock_conn.transaction = None
    ctx = AsyncMock()
    ctx.__aenter__.return_value = mock_conn
    ctx.__aexit__.return_value = None

    await persist_fincen_receipt_atomic(
        receipt={"status": "REJECTED", "fincen_tracking_id": "REJ-1"},
        alert_id=str(uuid.uuid4()),
        alert_uuid=uuid.uuid4(),
        draft_to_validate={"id": uuid.uuid4()},
        current_user={"id": "u1", "username": "mlro", "role": "MLRO"},
        tenant_id=str(uuid.uuid4()),
        conn_factory=lambda **kw: ctx,
    )
    draft_updates = [s for s in executed_sql if "UPDATE sar_drafts" in s]
    assert len(draft_updates) == 1
    assert "status = 'REJECTED'" in draft_updates[0]
    assert "status = 'FILED'" not in draft_updates[0]


def test_backtest_parity_metrics_behavioral_and_complete_fx_coverage():
    # Backtest ROUND_HALF_UP parity on $9,999.995 + min_tx_count + unsupported snapshot rule
    hit_half_up, _ = evaluate_rule_on_tx_row("LARGE_TRANSACTION", {"enabled": True, "threshold": 10000}, {"amount_base_usd": Decimal("9999.995")})
    assert hit_half_up is True

    hit_min_cnt, _ = evaluate_rule_on_tx_row(
        "STRUCTURING_SMURFING", {"enabled": True, "threshold": 10000, "min_tx_count": 5}, {"amount_base_usd": 5000}, sender_24h_sum=10000, sender_24h_count=2
    )
    assert hit_min_cnt is False

    hit_dormant, reason_dormant = evaluate_rule_on_tx_row("DORMANT_ACCOUNT", {"enabled": True}, {"amount_base_usd": 50000})
    assert hit_dormant is False and "UNSUPPORTED_IN_BACKTEST" in reason_dormant

    # Replay warm-up + F1 metrics
    now = datetime.now(timezone.utc)
    txs = [
        {"id": uuid.uuid4(), "sender_account_id": "s1", "amount_base_usd": Decimal("12000"), "timestamp": now - timedelta(hours=2), "historical_alert_status": "CLOSED_SAR"},
        {"id": uuid.uuid4(), "sender_account_id": "s1", "amount_base_usd": Decimal("11000"), "timestamp": now - timedelta(hours=1), "historical_alert_status": "CLOSED_FALSE_POSITIVE"},
    ]
    replay = _run_backtest_replay_sync(
        "LARGE_TRANSACTION", 30, {"enabled": True, "threshold": 10000}, {"enabled": True, "threshold": 11500}, txs
    )
    assert replay["coverage"] == "FULL"
    assert replay["challenger_metrics"]["precision"] == 1.0
    assert replay["challenger_metrics"]["recall"] == 1.0
    assert replay["challenger_metrics"]["f1"] == 1.0

    # Behavioral antipodal circular mean + smooth burst frequency
    mean_anti, _ = _compute_circular_hour_stats([0, 12])
    assert mean_anti == 0.0
    daily, _, _ = _calculate_frequencies([{"timestamp": now - timedelta(minutes=5)}, {"timestamp": now}])
    assert daily <= 2.0 / 7.0 + 1e-6

    # Complete CURRENCY_EXPONENTS coverage in FX fallback table
    missing_currencies = [c for c in CURRENCY_EXPONENTS if c not in FALLBACK_RATES_TO_USD_DECIMAL]
    assert missing_currencies == []
    assert get_fallback_fx_rate_decimal("VND", "USD") < Decimal("0.001")
    with pytest.raises(FxRateUnavailableError):
        get_fallback_fx_rate_decimal("ZZZ", "USD")


@pytest.mark.anyio
async def test_fx_fallback_returns_static_as_of_timestamp():
    with patch("services.fx_rates._fetch_live_rates_map", AsyncMock(return_value=None)), \
         patch("services.fx_rates.get_async_redis_client", AsyncMock(return_value=None)):
        rate, src, quoted_at = await get_fx_rate_with_provenance("VND", "USD")
    assert src == "ISO_FALLBACK"
    assert quoted_at == FALLBACK_RATES_AS_OF
    assert rate < Decimal("0.001")
