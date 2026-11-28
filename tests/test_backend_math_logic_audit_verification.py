"""
Principal Backend Math, Logic & State-Machine Verification Suite
================================================================
Targeted unit tests exercising standard, boundary, and hostile inputs across
critical financial math, risk scoring, ML, graph analytics, pagination,
caching, retry budgets, and compliance state machines.

Tests marked `@pytest.mark.xfail(strict=True)` provide executable,
reproducible proofs of confirmed bugs identified during the backend audit;
they will automatically flip to XPASS once each bug is remediated.
"""

from __future__ import annotations

import math
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal, ROUND_HALF_EVEN, ROUND_HALF_UP

import numpy as np
import pytest
from fastapi import HTTPException

from database.pagination import (
    decode_keyset_cursor,
    encode_keyset_cursor,
    validate_legacy_offset,
)
from domain.money import (
    InvalidMoneyError,
    Money,
    convert_money,
    invert_fx_rate,
    parse_decimal_amount,
    quantize_amount,
    to_decimal,
)
from domain.rules_core import (
    AccountRuleSnapshot,
    check_amount_anomaly_pure,
    check_conduit_passthrough_pure,
    check_large_transaction_pure,
    check_rapid_movement_pure,
    check_velocity_monitoring_pure,
    classify_transaction_decision,
    evaluate_ctr_and_structuring_pure,
    evaluate_travel_rule_pure,
)
from domain.scoring_core import _calc_z_score, _safe_float, compute_dynamic_risk_pure
from domain.state_machine import (
    AlertStatus,
    CaseStatus,
    CorruptedDomainStateError,
    DomainStateTransitionError,
    validate_alert_transition_pure,
    validate_case_transition_pure,
)
from domain.ubo_core import resolve_ubo_ownership_tree_pure
from services.behavioral import _compute_baseline_stats_sync, _compute_circular_hour_stats
from services.cache_aside import (
    _decode_envelope,
    compute_jittered_ttl,
    should_probabilistically_refresh,
)
from services.http_client import CircuitBreaker, RetryBudget
from services.isolation_forest import IsolationForestScratch, c_factor
from services.ml_model import AMLAnomalyModel
from services.network_analysis import (
    _add_edge_to_graph,
    _compute_degree_fallback,
    compute_betweenness_centrality,
    tarjan_scc,
)
from services.rfi import compute_sla_pause_delta_seconds
from services.sar_validator import validate_regulatory_xml
from services.str_batch_engine import STRBatchEngine
from services.whitelisting import _is_entry_valid


# ══════════════════════════════════════════════════════════════════════════════
# PART 1: VERIFIED SOLID MATH, BOUNDARY & HOSTILE-INPUT INVARIANTS
# ══════════════════════════════════════════════════════════════════════════════


class TestMoneyPrecisionHostileInputs:
    @pytest.mark.parametrize("bad", [True, False, None, "", "   ", float("nan"), float("inf"), float("-inf"), "NaN", "Infinity", "abc"])
    def test_to_decimal_rejects_hostile_non_finite_and_bool(self, bad):
        with pytest.raises(InvalidMoneyError):
            to_decimal(bad)

    def test_rounding_modes_bankers_vs_regulatory_half_up(self):
        # Banker's rounding (ROUND_HALF_EVEN): .225 -> .22 (even), .235 -> .24 (even)
        assert quantize_amount(Decimal("2.225"), "USD", rounding=ROUND_HALF_EVEN) == Decimal("2.22")
        assert quantize_amount(Decimal("2.235"), "USD", rounding=ROUND_HALF_EVEN) == Decimal("2.24")
        # Regulatory conservative rounding (ROUND_HALF_UP): .225 -> .23
        assert quantize_amount(Decimal("2.225"), "USD", rounding=ROUND_HALF_UP) == Decimal("2.23")

    def test_iso4217_minor_units_zero_two_and_three_decimal_currencies(self):
        jpy = Money.from_minor_units(1500, "JPY")
        assert jpy.amount == Decimal("1500")
        assert jpy.to_minor_units() == 1500

        kwd = Money.from_minor_units(12345, "KWD")
        assert kwd.amount == Decimal("12.345")
        assert kwd.to_minor_units() == 12345

        with pytest.raises(InvalidMoneyError):
            _ = Money.of("10.00", "USD") + Money.of("10.00", "EUR")

    def test_parse_decimal_amount_scale_and_sign_guards(self):
        assert parse_decimal_amount("123.4567", currency="USD") == Decimal("123.4567")
        with pytest.raises(InvalidMoneyError):
            parse_decimal_amount("123.45678", currency="USD")
        with pytest.raises(InvalidMoneyError):
            parse_decimal_amount("-0.01", currency="USD")
        with pytest.raises(InvalidMoneyError):
            parse_decimal_amount("0", currency="USD", allow_zero=False)

    def test_invert_fx_rate_rejects_zero_and_negative(self):
        with pytest.raises(InvalidMoneyError):
            invert_fx_rate(0)
        with pytest.raises(InvalidMoneyError):
            invert_fx_rate("-1.25")
        assert invert_fx_rate("0.80") == Decimal("1.25000000")


class TestRulesAndScoringBoundaries:
    def test_large_transaction_conservative_half_up_boundary(self):
        cfg = {"rules": {"LARGE_TRANSACTION": {"enabled": True, "threshold": "10000.00"}}}
        assert check_large_transaction_pure(cfg, Decimal("9999.994")) == []
        assert check_large_transaction_pure(cfg, Decimal("9999.995")) == ["LARGE_TRANSACTION_THRESHOLD"]

    def test_velocity_zero_stddev_floor_prevents_div_by_zero(self):
        cfg = {"rules": {"VELOCITY_MONITORING": {"enabled": True, "deviation_threshold": "3.0"}}}
        snap = AccountRuleSnapshot(
            velocity_avg_count=Decimal("1"),
            velocity_std_count=Decimal("0"),
            velocity_avg_amount_usd=Decimal("100"),
            velocity_std_amount_usd=Decimal("0"),
            today_count=0,
            today_amount_usd=Decimal("0"),
        )
        # Normal amount -> no trigger, zero ZeroDivisionError
        assert check_velocity_monitoring_pure(cfg, Decimal("100"), snap) == []
        # Huge spike -> triggers cleanly
        assert check_velocity_monitoring_pure(cfg, Decimal("500"), snap) == ["VELOCITY_MONITORING_SPIKE"]

    def test_rapid_movement_exact_inclusive_and_negative_elapsed_boundaries(self):
        cfg = {"rules": {"RAPID_MOVEMENT_FUNDS": {"enabled": True, "window_minutes": 10, "amount_ratio_threshold": "0.90"}}}
        t0 = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        snap = AccountRuleSnapshot(last_incoming_amount_usd=Decimal("1000.00"), last_incoming_at=t0)

        # Exact 0s elapsed & exact 90% ratio -> triggers
        assert check_rapid_movement_pure(cfg, Decimal("900.00"), t0, snap) == ["RAPID_MOVEMENT_FUNDS"]
        # Exact 600s elapsed -> triggers
        assert check_rapid_movement_pure(cfg, Decimal("900.00"), t0 + timedelta(seconds=600), snap) == ["RAPID_MOVEMENT_FUNDS"]
        # 601s elapsed -> outside window
        assert check_rapid_movement_pure(cfg, Decimal("900.00"), t0 + timedelta(seconds=601), snap) == []
        # Negative elapsed (tx before incoming) -> never triggers
        assert check_rapid_movement_pure(cfg, Decimal("1000.00"), t0 - timedelta(seconds=1), snap) == []

    def test_conduit_and_amount_anomaly_boundaries(self):
        cfg = {"rules": {"CONDUIT_RAPID_PASSTHROUGH": {"enabled": True, "min_inflow": "5000", "min_ratio": "0.85", "max_ratio": "1.15"}}}
        snap = AccountRuleSnapshot(conduit_inflow_24h_usd=Decimal("10000"), conduit_outflow_24h_usd=Decimal("0"))
        assert check_conduit_passthrough_pure(cfg, Decimal("8500"), Decimal("1"), snap) == ["CONDUIT_RAPID_PASSTHROUGH"]
        assert check_conduit_passthrough_pure(cfg, Decimal("11500"), Decimal("1"), snap) == ["CONDUIT_RAPID_PASSTHROUGH"]
        assert check_conduit_passthrough_pure(cfg, Decimal("8499.99"), Decimal("1"), snap) == []

        anom_cfg = {"rules": {"AMOUNT_ANOMALY_HEURISTICS": {"enabled": True}}}
        assert "ROUND_NUMBER_ANOMALY_1K" in check_amount_anomaly_pure(anom_cfg, Decimal("3000.00"), Decimal("3000.00"), [Decimal("3000.00")])
        assert "JUST_BELOW_CTR_THRESHOLD" in check_amount_anomaly_pure(anom_cfg, Decimal("9999.99"), Decimal("9999.99"), [Decimal("9999.99")])
        assert "JUST_BELOW_CTR_THRESHOLD" not in check_amount_anomaly_pure(anom_cfg, Decimal("10000.00"), Decimal("0"), [])

    def test_travel_rule_eur_and_usd_exact_thresholds(self):
        orig = {"name": "Alice Smith", "account_number": "DE89370400440532013000", "address": "1 Main St"}
        bene = {"name": "Bob Jones", "account_number": "US12345678"}

        ok_below_eur, missing_below = evaluate_travel_rule_pure(Decimal("999.99"), "EUR", "SEPA", {}, {})
        assert ok_below_eur is True and missing_below == []

        ok_at_eur, missing_at = evaluate_travel_rule_pure(Decimal("1000.00"), "EUR", "SEPA", {}, {})
        assert ok_at_eur is False and "originator_name" in missing_at

        ok_complete, missing_ok = evaluate_travel_rule_pure(Decimal("3000.00"), "USD", "WIRE", orig, bene)
        assert ok_complete is True and missing_ok == []

    def test_dynamic_risk_efficiency_axiom_under_hostile_and_floor_inputs(self):
        # NaN / Inf inputs sanitized cleanly without poisoning score
        res_hostile = compute_dynamic_risk_pure(
            rules_triggered=[],
            ml_score=float("nan"),
            amount=float("inf"),
            baseline={"avg_amount": float("nan"), "variance_amount": -100.0},
            iforest_score=float("-inf"),
            sender_risk=2.5,
            receiver_risk=-0.5,
            jurisdiction_risk=float("nan"),
        )
        assert 0.0 <= res_hostile["dynamic_risk_score"] <= 1.0
        assert res_hostile["explainability"]["efficiency_axiom_verified"] is True

        # Floor elevation & saturation clamping both satisfy Efficiency Axiom
        res_floor = compute_dynamic_risk_pure(
            rules_triggered=["SANCTIONS_HIT"],
            ml_score=0.05,
            amount=100.0,
            baseline={"avg_amount": 100.0, "variance_amount": 0.0},
            iforest_score=0.05,
        )
        assert res_floor["dynamic_risk_score"] >= 0.85
        assert res_floor["explainability"]["efficiency_axiom_verified"] is True

        res_sat = compute_dynamic_risk_pure(
            rules_triggered=["R1", "R2", "R3", "R4"],
            ml_score=0.99,
            amount=1_000_000.0,
            baseline={"avg_amount": 100.0, "variance_amount": 10.0},
            iforest_score=0.99,
            pep_tier="TIER_1",
        )
        assert res_sat["dynamic_risk_score"] == 1.0
        assert res_sat["explainability"]["efficiency_axiom_verified"] is True

    def test_classify_transaction_decision_boundaries(self):
        d_clean = classify_transaction_decision(Decimal("0.7499"), [])
        assert d_clean.alert_triggered is False and d_clean.threat_level == "NONE"

        d_high = classify_transaction_decision(Decimal("0.75"), [])
        assert d_high.alert_triggered is True and d_high.threat_level == "HIGH" and d_high.decision == "APPROVED"

        d_hold = classify_transaction_decision(Decimal("0.91"), ["SANCTIONS_HIT"])
        assert d_hold.decision == "HELD" and d_hold.tx_status == "HELD" and d_hold.threat_level == "CRITICAL"


class TestAlgorithmsGraphMLAndInfraMath:
    def test_ubo_diamond_and_cycle_resolution(self):
        edges = [
            {"child_company_name": "TargetCo", "parent_entity_name": "HoldCo A", "parent_entity_type": "COMPANY", "ownership_pct": 50},
            {"child_company_name": "TargetCo", "parent_entity_name": "HoldCo B", "parent_entity_type": "COMPANY", "ownership_pct": 50},
            {"child_company_name": "HoldCo A", "parent_entity_name": "Alice", "parent_entity_type": "PERSON", "ownership_pct": 60},
            {"child_company_name": "HoldCo B", "parent_entity_name": "Alice", "parent_entity_type": "PERSON", "ownership_pct": 40},
            # Introduce cycle HoldCo A -> TargetCo
            {"child_company_name": "HoldCo A", "parent_entity_name": "TargetCo", "parent_entity_type": "COMPANY", "ownership_pct": 10},
        ]
        res = resolve_ubo_ownership_tree_pure(edges, "TargetCo", threshold_pct=25)
        assert res["cycles_detected"] is True
        alice = next(u for u in res["ultimate_beneficial_owners"] if u["entity_name"] == "Alice")
        # 50%*60% + 50%*40% = 30% + 20% = 50%
        assert alice["effective_ownership_pct"] == 50.0
        assert alice["is_split_ownership"] is True
        assert alice["exceeds_threshold"] is True

    def test_isolation_forest_c_factor_nan_inf_and_empty_fit(self):
        assert c_factor(0) == 0.0
        assert c_factor(1) == 0.0
        assert c_factor(2) == 1.0
        assert c_factor(256) > 8.0

        empty_if = IsolationForestScratch(n_estimators=10, max_samples=32, seed=42).fit(np.empty((0, 5)))
        assert empty_if.compute_anomaly_score(np.zeros(5)) == 0.5

        X = np.array([[100.0, 0.1, 0.1, 10, 0], [float("nan"), float("inf"), float("-inf"), 12, 1], [500.0, 0.2, 0.2, 14, 0]])
        model = IsolationForestScratch(n_estimators=10, max_samples=3, seed=42).fit(X)
        s = model.compute_anomaly_score(np.array([float("nan"), float("inf"), 0.0, 0, 0]))
        assert 0.0 <= s <= 1.0 and not math.isnan(s)

    def test_tarjan_scc_deep_cycle_no_recursion_error_and_brandes_simple_chain(self):
        # 1,500-node cycle exceeds default Python recursion limit (~1000)
        deep_graph = {f"N{i}": [f"N{(i + 1) % 1500}"] for i in range(1500)}
        sccs = tarjan_scc(deep_graph)
        assert len(sccs) == 1 and len(sccs[0]) == 1500

        chain = {"A": ["B"], "B": ["C"], "C": []}
        cb = compute_betweenness_centrality(chain)
        # Directed Brandes scale = (n-1)*(n-2) = 2; 1 directed shortest path (A->C) through B => 1/2 = 0.5
        assert cb["B"] == 0.5 and cb["A"] == 0.0 and cb["C"] == 0.0

    def test_circular_hour_midnight_wrap_and_single_row_variance(self):
        avg_h, disp = _compute_circular_hour_stats([23, 1])
        assert avg_h in (0.0, 24.0)  # Wrap-around mean is midnight, NOT noon (12.0)
        assert disp > 0.0
        assert _compute_circular_hour_stats([]) == (0.0, 0.0)

        single_row = [{
            "amount": Decimal("500.00"),
            "timestamp": datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc),
            "receiver_account_id": str(uuid.uuid4()),
            "country": "US",
            "merchant": "WIRE",
            "device": "WEB",
            "channel": "WIRE",
        }]
        stats = _compute_baseline_stats_sync("acc-1", single_row)
        assert stats["variance_amount"] == 0.0  # No NaN from ddof=1 on N=1

    def test_cache_aside_xfetch_and_jitter_bounds(self):
        assert should_probabilistically_refresh(now_ts=100.0, expiry_ts=110.0, compute_delta_seconds=0.0, rand_val=0.001) is False
        assert should_probabilistically_refresh(now_ts=100.0, expiry_ts=110.0, compute_delta_seconds=2.0, rand_val=1.0) is False
        # Near-zero u yields large negative ln(u) -> triggers refresh
        assert should_probabilistically_refresh(now_ts=100.0, expiry_ts=110.0, compute_delta_seconds=2.0, rand_val=1e-6) is True
        for _ in range(25):
            ttl = compute_jittered_ttl(100, jitter_ratio=0.15)
            assert 100 <= ttl <= 115

    def test_retry_budget_ratio_and_circuit_breaker_fsm(self):
        rb = RetryBudget(target="test_target", window_seconds=10.0, max_retry_ratio=0.20, min_retries_per_window=3)
        for _ in range(20):
            rb.record_request()
        # 20% of 20 = 4 allowed retries; 5th rejected
        assert [rb.allow_retry() for _ in range(5)] == [True, True, True, True, False]

        cb = CircuitBreaker(target="test_cb", failure_threshold=2, recovery_timeout=0.0)
        cb.record_failure()
        assert cb.state == "closed"
        cb.record_failure()
        # recovery_timeout=0.0 transitions immediately to half_open on state check
        assert cb.state == "half_open"
        assert cb.allow_request() is True
        assert cb.allow_request() is False  # Only 1 half-open probe allowed
        cb.record_success()
        assert cb.state == "closed"

    def test_pagination_cursor_roundtrip_and_tamper_rejection(self):
        uid = uuid.uuid4()
        ts = datetime(2026, 6, 1, 15, 30, 0, tzinfo=timezone.utc)
        cursor = encode_keyset_cursor(ts, uid)
        dec_ts, dec_uid = decode_keyset_cursor(cursor)
        assert dec_ts == ts and dec_uid == uid

        with pytest.raises(HTTPException) as exc:
            decode_keyset_cursor("not-valid-base64!!!")
        assert exc.value.status_code == 400

        with pytest.raises(HTTPException) as exc2:
            validate_legacy_offset(10_001)
        assert exc2.value.status_code == 400

    def test_rfi_sla_pause_delta_clamps_future_and_handles_naive(self):
        now = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        assert compute_sla_pause_delta_seconds(None, now) == 0
        # Naive timestamp interpreted as UTC
        assert compute_sla_pause_delta_seconds(datetime(2026, 6, 1, 11, 59, 0), now) == 60
        # Future timestamp (clock skew) clamped to 0
        assert compute_sla_pause_delta_seconds(now + timedelta(seconds=30), now) == 0

    def test_fsm_rejects_terminal_and_corrupted_states(self):
        with pytest.raises(DomainStateTransitionError):
            validate_alert_transition_pure("CLOSED_SAR", "OPEN")
        with pytest.raises(CorruptedDomainStateError):
            validate_case_transition_pure("UNKNOWN_GARBAGE", "CLOSED")


# ══════════════════════════════════════════════════════════════════════════════
# PART 2: EXECUTABLE PROOF OF CONFIRMED BACKEND AUDIT BUGS (STRICT XFAIL)
# ══════════════════════════════════════════════════════════════════════════════


class TestConfirmedAuditBugCounterexamples:
    @pytest.mark.xfail(strict=True, reason="BUG-01: domain/state_machine.py str(Enum) yields 'CaseStatus.OPEN' on Python 3.11+")
    def test_bug01_state_machine_enum_member_input_crashes_on_python_314(self):
        # Passing CaseStatus.OPEN directly instead of .value should succeed, not raise CorruptedDomainStateError
        result = validate_case_transition_pure(CaseStatus.OPEN, CaseStatus.CLOSED)
        assert result == CaseStatus.CLOSED

    @pytest.mark.xfail(strict=True, reason="BUG-02: services/ml_model.py ISO-4217/UPPERCASE feature skew & NaN crash")
    def test_bug02_ml_model_iso_currency_and_channel_encoding_skew(self):
        vec = AMLAnomalyModel._build_feature_vector(
            amount=5000.0,
            sender_risk=0.2,
            receiver_risk=0.2,
            velocity_count=1,
            hour=12,
            currency_paid="RUB",
            currency_recv="USD",
            pay_format="CASH",
        )
        # Feature 3 = high_risk_currency, Feature 7 = is_cash
        assert vec[0][3] == 1.0
        assert vec[0][7] == 1.0

    @pytest.mark.xfail(strict=True, reason="BUG-03: services/async_jobs.py imports nonexistent run_rule_backtest_simulation")
    def test_bug03_async_jobs_rule_backtest_broken_import(self):
        import services.rule_backtest as rb

        assert hasattr(rb, "run_rule_backtest_simulation")

    @pytest.mark.xfail(strict=True, reason="BUG-04: domain/rules_core.py CTR structuring false positive on two >$10k deposits")
    def test_bug04_ctr_structuring_false_positive_on_two_large_cash_deposits(self):
        # Two legitimate >$10k cash deposits ($15k prior + $12k current) are NOT structuring (<$10k evasion)
        decision = evaluate_ctr_and_structuring_pure(
            amount_base_usd=Decimal("12000.00"),
            channel="CASH",
            merchant=None,
            prior_24h_cash_usd=Decimal("15000.00"),
            prior_24h_cash_count=1,
        )
        assert decision.requires_ctr_filing is True
        assert decision.structuring_detected is False

    @pytest.mark.xfail(strict=True, reason="BUG-05: services/network_analysis.py multi-edge corrupts Brandes centrality >1.0 and Fan-In degrees")
    def test_bug05_network_analysis_multi_edge_corrupts_centrality_and_degrees(self):
        g: dict[str, list[str]] = {}
        for _ in range(3):
            _add_edge_to_graph(g, "A", "B")
            _add_edge_to_graph(g, "B", "C")
        cb = compute_betweenness_centrality(g)
        fan_in, fan_out = _compute_degree_fallback(g)
        # Normalized centrality must never exceed 1.0; 1 unique source must not trigger Fan-In (>=3 unique sources)
        assert cb["B"] <= 1.0
        assert fan_in == [] and fan_out == []

    @pytest.mark.xfail(strict=True, reason="BUG-06: domain/ubo_core.py duplicate edge double-counts UBO equity")
    def test_bug06_ubo_duplicate_edge_double_counts_equity(self):
        dup_edges = [
            {"child_company_name": "Target", "parent_entity_name": "Alice", "parent_entity_type": "PERSON", "ownership_pct": 30},
            {"child_company_name": "Target", "parent_entity_name": "Alice", "parent_entity_type": "PERSON", "ownership_pct": 30},
        ]
        res = resolve_ubo_ownership_tree_pure(dup_edges, "Target")
        alice = res["ultimate_beneficial_owners"][0]
        assert alice["effective_ownership_pct"] == 30.0

    @pytest.mark.xfail(strict=True, reason="BUG-07: services/sar_validator.py accepts <Amount>Infinity</Amount> and negative goAML <amount_local>")
    def test_bug07_sar_validator_accepts_infinity_and_negative_goaml_amount(self):
        xml = (
            "<SuspiciousActivityReport>"
            "<Narrative>Suspicious wire layering detected across shell accounts.</Narrative>"
            "<Amount>Infinity</Amount>"
            "</SuspiciousActivityReport>"
        )
        ok, _errors = validate_regulatory_xml(xml)
        assert ok is False

    @pytest.mark.xfail(strict=True, reason="BUG-11: domain/money.py quantize_amount('1e30') raises raw decimal.InvalidOperation instead of InvalidMoneyError")
    def test_bug11_money_quantize_extreme_exponent_raises_invalid_money_error(self):
        with pytest.raises(InvalidMoneyError):
            quantize_amount("1e30", "USD")

    @pytest.mark.xfail(strict=True, reason="BUG-12: services/pkyc_and_qa.py IEEE-754 float delta 0.95 - 0.80 == 0.1499999999999999 < 0.15 suppresses sanctions alert")
    def test_bug12_pkyc_float_subtraction_suppresses_sanctions_delta(self):
        prior_risk = 0.80
        new_risk = max(prior_risk, 0.95)
        # Exact line 77 condition in services/pkyc_and_qa.py when pkyc_material_change_flag is already True
        material_delta = (new_risk - prior_risk >= 0.15)
        assert material_delta is True

    @pytest.mark.xfail(strict=True, reason="BUG-13: services/adverse_media.py vacuous 1-char token match & substring country match ('in' in 'indicted')")
    def test_bug13_adverse_media_vacuous_short_name_and_country_substring(self):
        from services.adverse_media import disambiguate_adverse_hit

        res = disambiguate_adverse_hit(
            "A B",
            "Unrelated executive was indicted for fraud. A B had no involvement.",
            country="IN",
        )
        assert res["same_sentence_match"] is False

    @pytest.mark.xfail(strict=True, reason="BUG-08: services/str_batch_engine.py round-then-sum XML total disagrees with sum-then-round DB total")
    def test_bug08_str_batch_xml_vs_db_total_rounding_mismatch(self):
        alerts = [
            {"id": "a1", "amount": Decimal("100.0050"), "amount_base_usd": Decimal("100.0050"), "currency": "USD"},
            {"id": "a2", "amount": Decimal("100.0050"), "amount_base_usd": Decimal("100.0050"), "currency": "USD"},
        ]
        xml = STRBatchEngine.construct_batch_xml("BATCH-1", alerts)
        db_total = sum((Decimal(str(a["amount_base_usd"])) for a in alerts), Decimal("0.00")).quantize(
            Decimal("0.01"), rounding=ROUND_HALF_UP
        )
        assert f'total_batch_amount="{db_total:.2f}"' in xml

    @pytest.mark.xfail(strict=True, reason="BUG-09: services/whitelisting.py _is_entry_valid crashes on naive ISO expires_at")
    def test_bug09_whitelist_naive_expires_at_raises_typeerror(self):
        entry = {"expires_at": "2099-01-01T00:00:00"}
        assert _is_entry_valid(entry, datetime.now(timezone.utc)) is True

    @pytest.mark.xfail(strict=True, reason="BUG-10: services/cache_aside.py _decode_envelope crashes on malformed non-float exp")
    def test_bug10_cache_aside_decode_envelope_crashes_on_malformed_exp(self):
        valid, is_neg, val, exp, delta = _decode_envelope('{"v": 1, "exp": "corrupt", "delta": 0.1}')
        assert valid is False

    @pytest.mark.xfail(strict=True, reason="BUG-14: domain/rules_core.py check_tbml_pure omits abs() so under-invoicing (-60%) evades detection")
    def test_bug14_tbml_under_invoicing_evades_detection(self):
        from domain.rules_core import check_tbml_pure

        rules = check_tbml_pure(
            {},
            Decimal("40000"),
            {"goods_category": "PRECIOUS_METALS", "unit_price_variance_pct": -60.0},
        )
        assert "TRADE_BASED_ML_OVER_UNDER_INVOICING" in rules

    @pytest.mark.xfail(strict=True, reason="BUG-15: domain/rules_core.py _dec swallows NaN/Inf to $0.00 bypassing CTR reporting")
    def test_bug15_ctr_swallows_nan_and_inf_to_zero(self):
        with pytest.raises(InvalidMoneyError):
            evaluate_ctr_and_structuring_pure(float("inf"), "CASH", None)

    @pytest.mark.xfail(strict=True, reason="BUG-16: domain/scoring_core.py taint floor >= 0.70 is unreachable under default decay_factor=0.65 (max taint 0.65)")
    def test_bug16_transitive_taint_floor_unreachable_under_default_decay(self):
        # Default decay_factor=0.65 in services/network_analysis.py:531 => 1-hop max taint = 1.0 * 0.65 = 0.65
        base = compute_dynamic_risk_pure([], 0.1, 100.0, {}, 0.1, 0.1, 0.1, None, 0.1, taint_risk=0.0)
        tainted = compute_dynamic_risk_pure([], 0.1, 100.0, {}, 0.1, 0.1, 0.1, None, 0.1, taint_risk=0.65)
        assert tainted["dynamic_risk_score"] > base["dynamic_risk_score"]

    @pytest.mark.xfail(strict=True, reason="BUG-17: services/ml_model.py fallback attributes uninitialized in xgboost mode & _predict_fallback propagates NaN")
    def test_bug17_ml_model_fallback_crashes_on_inf_and_propagates_nan(self):
        from services.ml_model import AMLAnomalyModel

        model = AMLAnomalyModel()
        res_inf = model.predict_risk(float("inf"), 0.5, 0.5, 1)
        assert math.isfinite(res_inf["risk_score"])
        res_nan = model._predict_fallback(float("nan"), 0.5, 0.5, 1)
        assert math.isfinite(res_nan["risk_score"])

    @pytest.mark.xfail(strict=True, reason="BUG-18: services/fx_rates.py defaults valid ISO currency VND to 1:1 USD & convert_money mismatches fx_rate_applied")
    def test_bug18_fx_rates_vnd_defaults_1_to_1_and_convert_money_provenance(self):
        from domain.money import convert_money
        from services.fx_rates import get_fallback_fx_rate_decimal

        # 1 VND is ~$0.00004 USD, definitely not 1.0 USD
        vnd_rate = get_fallback_fx_rate_decimal("VND", "USD")
        assert vnd_rate < Decimal("0.01")
        conv = convert_money(Decimal("100000000"), "EUR", Decimal("1.000000004"), base_currency="USD")
        expected = (conv.amount_original * conv.fx_rate_applied).quantize(Decimal("0.01"))
        assert conv.amount_base == expected

    @pytest.mark.xfail(strict=True, reason="BUG-19: services/behavioral.py _compute_circular_hour_stats emits hour 24.0 (out of [0, 24))")
    def test_bug19_circular_hour_stats_returns_24_out_of_range(self):
        mean_h, _std_h = _compute_circular_hour_stats([0] * 1000 + [23])
        assert 0.0 <= mean_h < 24.0

    @pytest.mark.xfail(strict=True, reason="BUG-20: services/case_correlation.py higher_priority('LOW', 'NONE') returns invalid 'NONE'")
    def test_bug20_case_correlation_higher_priority_accepts_invalid_incoming(self):
        from services.case_correlation import higher_priority

        assert higher_priority("LOW", "NONE") == "LOW"
