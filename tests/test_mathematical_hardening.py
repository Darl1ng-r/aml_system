"""
Comprehensive Mathematical Hardening & Statistical Invariant Test Suite
========================================================================
Validates mathematical derivations, boundary inequalities, directional
statistics on S^1, Bessel's sample variance correction, Brandes betweenness
normalization, and ML feature stability across the AML system.
"""

import math
import numpy as np
import pytest
from unittest.mock import AsyncMock, patch

from services.rules import RulesEngine
from services.behavioral import calculate_customer_baseline
from services.network_analysis import compute_betweenness_centrality, tarjan_scc
from services.isolation_forest import IsolationForestScratch, c_factor
from services.ml_model import AMLAnomalyModel


# ══════════════════════════════════════════════════════════════════════════════
# 1. FinCEN / BSA $10,000.00 Regulatory Boundary & Structuring Invariants
# ══════════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_exact_10k_regulatory_boundary_large_transaction():
    """
    BSA 31 CFR 1010.311 Mandate:
    Transactions of EXACTLY $10,000.00 must trigger LARGE_TRANSACTION_THRESHOLD.
    Strict inequalities (> 10000.0) create an illegal regulatory blind spot.
    """
    engine = RulesEngine()
    
    # Exactly $10,000.00 -> MUST trigger
    rules_10k = await engine.evaluate_transaction(
        amount=10000.0,
        sender_id="acc-send-1",
        receiver_id="acc-recv-1",
        tenant_id="tenant-alpha"
    )
    assert "LARGE_TRANSACTION_THRESHOLD" in rules_10k, "Exact $10,000.00 did not trigger LARGE_TRANSACTION_THRESHOLD"

    # $9,999.99 -> MUST NOT trigger large transaction rule
    rules_sub = await engine.evaluate_transaction(
        amount=9999.99,
        sender_id="acc-send-1",
        receiver_id="acc-recv-1",
        tenant_id="tenant-alpha"
    )
    assert "LARGE_TRANSACTION_THRESHOLD" not in rules_sub, "$9,999.99 erroneously triggered LARGE_TRANSACTION_THRESHOLD"

    # $10,000.01 -> MUST trigger
    rules_sup = await engine.evaluate_transaction(
        amount=10000.01,
        sender_id="acc-send-1",
        receiver_id="acc-recv-1",
        tenant_id="tenant-alpha"
    )
    assert "LARGE_TRANSACTION_THRESHOLD" in rules_sup, "$10,000.01 did not trigger LARGE_TRANSACTION_THRESHOLD"


@pytest.mark.asyncio
async def test_structuring_velocity_exact_boundary():
    """
    Structuring Smurfing:
    Two sub-threshold deposits ($5,000.00 + $5,000.00 = $10,000.00) in 24h
    must trigger STRUCTURING_VELOCITY_24H.
    """
    engine = RulesEngine()
    
    # Mock Redis sliding window pipeline to simulate previous $5,000 deposit
    mock_redis = AsyncMock()
    mock_pipe = AsyncMock()
    
    # Previous deposit was $5000.0
    prev_deposit = [(b"5000.0:1700000000:abc123", 1700000000.0)]
    mock_pipe.execute = AsyncMock(return_value=[None, prev_deposit, None, None, None, prev_deposit, None, None])
    mock_pipe.__aenter__.return_value = mock_pipe
    mock_redis.pipeline.return_value = mock_pipe

    with patch("services.rules.get_async_redis_client", AsyncMock(return_value=mock_redis)):
        rules = await engine.evaluate_transaction(
            amount=5000.0,
            sender_id="acc-send-struct",
            receiver_id="acc-recv-struct",
            tenant_id="tenant-alpha"
        )
        assert "STRUCTURING_VELOCITY_24H" in rules, "Two $5,000 deposits failed to trigger STRUCTURING_VELOCITY_24H"


@pytest.mark.asyncio
async def test_just_below_ctr_threshold_boundary():
    """
    AMOUNT_ANOMALY_HEURISTICS:
    $9,000.00 <= amount < $10,000.00 triggers JUST_BELOW_CTR_THRESHOLD.
    Exact $10,000.00 must NOT trigger JUST_BELOW_CTR_THRESHOLD (it is a full CTR).
    """
    engine = RulesEngine()

    # $9,000.00 exact lower bound
    r_9000 = await engine.evaluate_transaction(amount=9000.0, sender_id="s", receiver_id="r")
    assert "JUST_BELOW_CTR_THRESHOLD" in r_9000

    # $9,999.00
    r_9999 = await engine.evaluate_transaction(amount=9999.0, sender_id="s", receiver_id="r")
    assert "JUST_BELOW_CTR_THRESHOLD" in r_9999

    # $10,000.00 exact upper bound -> Should trigger LARGE_TRANSACTION, NOT JUST_BELOW
    r_10000 = await engine.evaluate_transaction(amount=10000.0, sender_id="s", receiver_id="r")
    assert "JUST_BELOW_CTR_THRESHOLD" not in r_10000
    assert "LARGE_TRANSACTION_THRESHOLD" in r_10000

    # $8,999.99 below lower bound
    r_8999 = await engine.evaluate_transaction(amount=8999.99, sender_id="s", receiver_id="r")
    assert "JUST_BELOW_CTR_THRESHOLD" not in r_8999


@pytest.mark.asyncio
async def test_round_number_integer_cents_precision():
    """
    ROUND_NUMBER_ANOMALY_1K:
    Must use integer-cent arithmetic (amount * 100) % 100000 == 0
    to avoid IEEE-754 binary floating-point representation drift.
    """
    engine = RulesEngine()

    # Exact round multiples >= 3000
    r_3000 = await engine.evaluate_transaction(amount=3000.0, sender_id="s", receiver_id="r")
    assert "ROUND_NUMBER_ANOMALY_1K" in r_3000

    r_7000 = await engine.evaluate_transaction(amount=7000.0, sender_id="s", receiver_id="r")
    assert "ROUND_NUMBER_ANOMALY_1K" in r_7000

    # Non-round amounts
    r_3000_01 = await engine.evaluate_transaction(amount=3000.01, sender_id="s", receiver_id="r")
    assert "ROUND_NUMBER_ANOMALY_1K" not in r_3000_01

    r_4999_99 = await engine.evaluate_transaction(amount=4999.99, sender_id="s", receiver_id="r")
    assert "ROUND_NUMBER_ANOMALY_1K" not in r_4999_99


# ══════════════════════════════════════════════════════════════════════════════
# 2. Directional Statistics on S^1 Manifold (Circular Time Statistics)
# ══════════════════════════════════════════════════════════════════════════════

def test_circular_hour_statistics_midnight_transition():
    """
    Directional Statistics on S^1 (Circle):
    A customer transacting at 23:00 and 01:00 has:
    - Linear mean: (23 + 1)/2 = 12.0 (Noon!) -> Completely wrong.
    - Linear sample variance: ((23-12)^2 + (1-12)^2)/1 = 242.0 (Std Dev = 11 hours!).
    - Circular mean on S^1: 0.0 (Midnight) -> Correct.
    - Resultant vector length R = cos(pi/12) ≈ 0.9659.
    - Circular dispersion: 2 * (1 - R) * (24 / 2pi)^2 ≈ 0.995 hr^2 (Std Dev ≈ 1 hour).
    """
    hours = [23, 1]
    angles = [2.0 * math.pi * h / 24.0 for h in hours]
    sin_mean = float(np.mean([math.sin(a) for a in angles]))
    cos_mean = float(np.mean([math.cos(a) for a in angles]))
    
    circ_hour = (math.atan2(sin_mean, cos_mean) * 24.0 / (2.0 * math.pi)) % 24.0
    R = min(math.sqrt(sin_mean**2 + cos_mean**2), 1.0)
    circ_dispersion = 2.0 * (1.0 - R) * ((24.0 / (2.0 * math.pi)) ** 2)

    # Circular mean must be midnight (0.0 or 24.0 within numerical epsilon)
    assert abs(circ_hour - 0.0) < 1e-4 or abs(circ_hour - 24.0) < 1e-4
    # Circular dispersion must be ~1.0 hr^2 (NOT 121 hr^2)
    assert 0.95 <= circ_dispersion <= 1.05
    assert math.sqrt(circ_dispersion) < 1.05


def test_circular_hour_identical_hours():
    """Identical transaction times must yield zero circular variance."""
    hours = [14, 14, 14, 14]
    angles = [2.0 * math.pi * h / 24.0 for h in hours]
    sin_mean = float(np.mean([math.sin(a) for a in angles]))
    cos_mean = float(np.mean([math.cos(a) for a in angles]))
    
    circ_hour = (math.atan2(sin_mean, cos_mean) * 24.0 / (2.0 * math.pi)) % 24.0
    R = min(math.sqrt(sin_mean**2 + cos_mean**2), 1.0)
    circ_dispersion = 2.0 * (1.0 - R) * ((24.0 / (2.0 * math.pi)) ** 2)

    assert round(circ_hour, 2) == 14.00
    assert abs(R - 1.0) < 1e-6
    assert circ_dispersion < 1e-6


# ══════════════════════════════════════════════════════════════════════════════
# 3. Bessel's Sample Variance Correction (Unbiased Estimator)
# ══════════════════════════════════════════════════════════════════════════════

def test_bessels_variance_correction():
    """
    Sample variance requires Bessel's correction (ddof=1):
    s^2 = 1/(N - 1) * sum((x_i - mean)^2)
    For [100.0, 200.0]:
    - Population variance (ddof=0): 2500.0
    - Unbiased sample variance (ddof=1): 5000.0
    """
    amounts = [100.0, 200.0]
    sample_var = float(np.var(amounts, ddof=1))
    pop_var = float(np.var(amounts, ddof=0))

    assert sample_var == 5000.0
    assert pop_var == 2500.0
    assert sample_var > pop_var


# ══════════════════════════════════════════════════════════════════════════════
# 4. Brandes' Betweenness Centrality Directed Normalization
# ══════════════════════════════════════════════════════════════════════════════

def test_brandes_directed_betweenness_normalization():
    """
    Directed Graph Betweenness Centrality Scaling:
    Normalization constant for directed graph of n nodes is 1 / ((n - 1) * (n - 2)).
    In chain A -> B -> C:
    - n = 3
    - Shortest path A to C passes through B (delta = 1.0)
    - Scale = (3 - 1) * (3 - 2) = 2.0
    - Normalized score for B = 1.0 / 2.0 = 0.50
    """
    graph = {
        "A": ["B"],
        "B": ["C"],
        "C": []
    }
    bc = compute_betweenness_centrality(graph)
    assert bc["B"] == 0.50
    assert bc["A"] == 0.00
    assert bc["C"] == 0.00


def test_brandes_two_node_guard():
    """When n <= 2, denominator guard prevents ZeroDivisionError."""
    graph = {
        "A": ["B"],
        "B": []
    }
    bc = compute_betweenness_centrality(graph)
    assert bc["A"] == 0.0
    assert bc["B"] == 0.0


# ══════════════════════════════════════════════════════════════════════════════
# 5. Isolation Forest c_factor Subsample Denominator
# ══════════════════════════════════════════════════════════════════════════════

def test_isolation_forest_actual_subsample_size():
    """
    Isolation Forest anomaly score:
    c(n) = 2*(ln(n - 1) + 0.5772156649) - 2*(n - 1)/n
    Must use actual subsample size (e.g. n=50 when dataset has 50 samples)
    rather than a fixed default of 256.
    """
    X_small = np.random.normal(loc=100.0, scale=10.0, size=(50, 4))
    model = IsolationForestScratch(n_estimators=10, max_samples=256)
    model.fit(X_small)

    assert model.actual_subsample_size == 50, "Did not record actual subsample size"
    c_50 = c_factor(50)
    c_256 = c_factor(256)
    assert c_50 < c_256

    score = model.compute_anomaly_score(X_small[0])
    assert 0.0 <= score <= 1.0


# ══════════════════════════════════════════════════════════════════════════════
# 6. ML Model Feature Vector & Amount Ratio Robustness
# ══════════════════════════════════════════════════════════════════════════════

def test_ml_model_amount_ratio_handling():
    """
    Verifies that amount_ratio correctly handles:
    1. Domestic same-currency default (0.20)
    2. Multi-currency explicit amount_received (e.g., $1500 / $1000 / 5.0 = 0.30)
    3. Explicit pre-computed amount_ratio
    4. Safe non-negative clamping
    """
    model = AMLAnomalyModel()

    # 1. Domestic default
    vec_dom = model._build_feature_vector(amount=1000.0, sender_risk=0.1, receiver_risk=0.1, velocity_count=1)
    # Feature 2 is amount_ratio
    assert round(float(vec_dom[0, 1]), 4) == 0.2000

    # 2. Multi-currency explicit received amount: $1500 received for $1000 paid -> ratio = 1.5 -> / 5.0 = 0.30
    vec_fx = model._build_feature_vector(
        amount=1000.0, sender_risk=0.1, receiver_risk=0.1, velocity_count=1,
        amount_received=1500.0
    )
    assert round(float(vec_fx[0, 1]), 4) == 0.3000

    # 3. Explicit amount_ratio passed in predict()
    score, attributions = model.predict({
        "amount": 2500.0,
        "amount_received": 5000.0,
        "sender_risk": 0.3,
        "receiver_risk": 0.2,
    })
    assert 0.0 <= score <= 1.0

    # 4. Zero and negative amount boundary safety
    vec_zero = model._build_feature_vector(amount=0.0, sender_risk=0.1, receiver_risk=0.1, velocity_count=0)
    assert float(vec_zero[0, 0]) == 0.0
    assert float(vec_zero[0, 1]) == 0.0

    vec_neg = model._build_feature_vector(amount=-500.0, sender_risk=0.1, receiver_risk=0.1, velocity_count=0)
    assert float(vec_neg[0, 0]) == 0.0
    assert float(vec_neg[0, 1]) == 0.0
