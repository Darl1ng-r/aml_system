import pytest
import numpy as np
from services.isolation_forest import IsolationForestScratch, c_factor, Node


def test_c_factor_boundary_values():
    """Verify c_factor BST average path length calculations."""
    assert c_factor(0) == 0.0
    assert c_factor(1) == 0.0
    assert c_factor(2) == 1.0
    assert c_factor(10) > 1.0
    assert c_factor(256) > 5.0


def test_isolation_forest_fit_and_compute_score():
    """Verify IsolationForestScratch fit and score computation."""
    np.random.seed(42)
    # Generate 100 normal samples around (100, 0.1) and 5 outliers at (50000, 0.9)
    normal_data = np.random.normal(loc=[100, 0.1], scale=[10, 0.02], size=(100, 2))
    outlier_data = np.random.normal(loc=[50000, 0.9], scale=[10, 0.02], size=(5, 2))
    X_train = np.vstack([normal_data, outlier_data])

    model = IsolationForestScratch(n_estimators=50, max_samples=64)
    model.fit(X_train)

    assert model.fitted is True
    assert len(model.trees) == 50

    normal_point = np.array([100.0, 0.10])
    outlier_point = np.array([50000.0, 0.95])

    normal_score = model.compute_anomaly_score(normal_point)
    outlier_score = model.compute_anomaly_score(outlier_point)

    assert 0.0 <= normal_score <= 1.0
    assert 0.0 <= outlier_score <= 1.0
    # Outliers should have a significantly higher anomaly score than normal points
    assert outlier_score > normal_score


def test_isolation_forest_unfitted_returns_default():
    """Verify compute_anomaly_score on unfitted model returns default 0.5."""
    model = IsolationForestScratch()
    score = model.compute_anomaly_score(np.array([10.0, 0.5]))
    assert score == 0.5


def test_isolation_forest_empty_dataset_handles_gracefully():
    """Verify fit on empty dataset sets fitted state without raising exceptions."""
    model = IsolationForestScratch()
    model.fit(np.empty((0, 2)))
    assert model.fitted is True
