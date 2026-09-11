"""
AML Risk Inference Engine — XGBoost + SHAP
===========================================
Loads the trained XGBoost pipeline (StandardScaler + XGBClassifier) from
services/aml_model.joblib and exposes a predict_risk() method that:
  - Returns a calibrated risk score in [0, 1]
  - Returns true SHAP feature attributions for regulatory explainability

Falls back to the legacy logistic regression formula if the model file is
not present (e.g. before first training run).

Interface is backward-compatible — callers in transactions.py are unchanged.
"""

import os
import json
import math
import logging
import numpy as np

logger = logging.getLogger(__name__)

# ── Paths ──────────────────────────────────────────────────────────────────────
_SERVICE_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_SERVICE_DIR)
_MODELS_DIR = os.path.join(_PROJECT_ROOT, "models")
_MODEL_PATH = os.path.join(_MODELS_DIR, "aml_model.joblib")
_PARAMS_PATH = os.path.join(_MODELS_DIR, "model_params.json")
_REPORT_PATH = os.path.join(_MODELS_DIR, "model_report.json")

# Feature names must match the order used during training
FEATURE_NAMES = [
    "amount_log",
    "amount_ratio",
    "hour_of_day",
    "high_risk_currency",
    "currency_mismatch",
    "payment_format",
    "is_crypto",
    "is_cash",
    "is_reinvestment",
    "is_round_amount",
]

AMOUNT_NORM_CAP = 100_000.0

HIGH_RISK_CURRENCIES = {"Ruble", "Yuan", "Shekel", "Dinar", "Iranian Rial"}

PAYMENT_FORMATS = {
    "Cash": 0,
    "Cheque": 1,
    "Credit Card": 2,
    "ACH": 3,
    "Wire": 4,
    "Reinvestment": 5,
    "Bitcoin": 6,
    "Other": 7,
}


class AMLAnomalyModel:
    """
    Production AML risk inference engine.

    Primary path:  XGBoost pipeline loaded from aml_model.joblib.
                   SHAP TreeExplainer provides true feature attributions.

    Fallback path: Legacy logistic regression formula from model_params.json.
                   Used if the XGBoost model has not been trained yet.
    """

    def __init__(self):
        self._pipeline = None
        self._explainer = None
        self._recommended_threshold = 0.50
        self._mode = "fallback"

        # ── Try loading XGBoost pipeline ──────────────────────────────────────
        if os.path.exists(_MODEL_PATH):
            try:
                import joblib
                import shap
                self._pipeline = joblib.load(_MODEL_PATH)
                # Build SHAP explainer from the XGBoost classifier inside the pipeline
                xgb_model = self._pipeline.named_steps["classifier"]
                self._explainer = shap.TreeExplainer(xgb_model)
                self._mode = "xgboost"

                # Load recommended threshold from training report
                if os.path.exists(_REPORT_PATH):
                    with open(_REPORT_PATH) as f:
                        report = json.load(f)
                    self._recommended_threshold = report.get("recommended_threshold", 0.50)

                logger.info(
                    f"✅ XGBoost AML model loaded from {_MODEL_PATH}. "
                    f"Recommended threshold: {self._recommended_threshold}"
                )
            except Exception as e:
                logger.error(f"Failed to load XGBoost model: {e}. Falling back to legacy formula.")
                self._mode = "fallback"

        # ── Fallback: legacy logistic regression coefficients ─────────────────
        if self._mode == "fallback":
            self._intercept = -2.36
            self._coefficients = {
                "amount": 3.66, "sender_risk": 2.38,
                "receiver_risk": 1.84, "velocity": 1.58
            }
            self._feature_means = {
                "amount": 0.13, "sender_risk": 0.29,
                "receiver_risk": 0.29, "velocity": 0.16
            }
            if os.path.exists(_PARAMS_PATH):
                try:
                    with open(_PARAMS_PATH) as f:
                        params = json.load(f)
                    self._intercept = params.get("intercept", self._intercept)
                    self._coefficients = params.get("coefficients", self._coefficients)
                    self._feature_means = params.get("feature_means", self._feature_means)
                    logger.info("Legacy logistic regression parameters loaded from model_params.json.")
                except Exception as e:
                    logger.warning(f"Could not load model_params.json: {e}. Using hardcoded defaults.")
            else:
                logger.warning("No trained model found. Using hardcoded fallback heuristics. Run scripts/train_model.py to train.")

    # ── Feature construction ───────────────────────────────────────────────────
    @staticmethod
    def _build_feature_vector(
        amount: float,
        sender_risk: float,
        receiver_risk: float,
        velocity_count: int,
        hour: int = 12,
        currency_paid: str = "US Dollar",
        currency_recv: str = "US Dollar",
        pay_format: str = "Wire",
    ) -> np.ndarray:
        """
        Constructs the 10-feature vector used during training.
        Default values for optional args keep backward compatibility.
        """
        amount_log = math.log1p(amount) / math.log1p(AMOUNT_NORM_CAP)
        amount_log = min(max(amount_log, 0.0), 1.0)

        amount_ratio = min(amount / max(amount, 1.0), 5.0) / 5.0  # defaults to 1.0 for same-currency

        hour_norm = min(max(hour, 0), 23) / 23.0

        is_geo_risk = 1.0 if currency_paid in HIGH_RISK_CURRENCIES else 0.0
        currency_mismatch = 1.0 if currency_recv != currency_paid else 0.0

        pay_fmt_code = PAYMENT_FORMATS.get(pay_format, PAYMENT_FORMATS["Other"]) / 7.0
        is_crypto = 1.0 if pay_format == "Bitcoin" else 0.0
        is_cash = 1.0 if pay_format == "Cash" else 0.0
        is_reinvestment = 1.0 if pay_format == "Reinvestment" else 0.0
        is_round = 1.0 if (amount > 0 and amount % 1000 == 0) else 0.0

        return np.array([[
            amount_log, amount_ratio, hour_norm, is_geo_risk,
            currency_mismatch, pay_fmt_code, is_crypto, is_cash,
            is_reinvestment, is_round,
        ]], dtype=np.float32)

    # ── Primary inference method ───────────────────────────────────────────────
    def predict_risk(
        self,
        amount: float,
        sender_risk: float,
        receiver_risk: float,
        velocity_count: int,
        # Extended fields (optional — backward-compatible)
        hour: int = 12,
        currency_paid: str = "US Dollar",
        currency_recv: str = "US Dollar",
        pay_format: str = "Wire",
        explain: bool = False,
    ) -> dict:
        """
        Computes the AI risk score and returns SHAP feature attributions.

        Returns:
            {
                "risk_score": float,      # [0, 1] calibrated probability
                "model_mode": str,        # "xgboost" or "fallback"
                "recommended_threshold": float,
                "attributions": {
                    "<feature_name>": float, ...
                }
            }
        """
        if self._mode == "xgboost":
            return self._predict_xgboost(
                amount, sender_risk, receiver_risk, velocity_count,
                hour, currency_paid, currency_recv, pay_format, explain=explain
            )
        else:
            return self._predict_fallback(amount, sender_risk, receiver_risk, velocity_count)

    def _predict_xgboost(
        self, amount, sender_risk, receiver_risk, velocity_count,
        hour, currency_paid, currency_recv, pay_format, explain: bool = False
    ) -> dict:
        try:
            X = self._build_feature_vector(
                amount, sender_risk, receiver_risk, velocity_count,
                hour, currency_paid, currency_recv, pay_format
            )
            # Pipeline applies StandardScaler then XGBoost
            risk_score = float(self._pipeline.predict_proba(X)[0][1])

            # Performance optimization: only execute CPU-intensive SHAP tree traversal
            # for anomalous/borderline transactions or when explicitly requested
            should_compute_shap = explain or (risk_score >= self._recommended_threshold * 0.85)
            if should_compute_shap and self._explainer:
                scaler = self._pipeline.named_steps["scaler"]
                X_scaled = scaler.transform(X)
                shap_vals = self._explainer.shap_values(X_scaled)[0]
                attributions = {
                    name: round(float(val), 6)
                    for name, val in zip(FEATURE_NAMES, shap_vals)
                }
            else:
                attributions = {name: 0.0 for name in FEATURE_NAMES}

            return {
                "risk_score": round(risk_score, 4),
                "model_mode": "xgboost",
                "recommended_threshold": self._recommended_threshold,
                "attributions": attributions,
            }
        except Exception as e:
            logger.error(f"XGBoost inference failed: {e}. Falling back to legacy formula.")
            return self._predict_fallback(amount, sender_risk, receiver_risk, velocity_count)

    def _predict_fallback(self, amount, sender_risk, receiver_risk, velocity_count) -> dict:
        """Legacy logistic regression formula (used before model is trained)."""
        norm_amount = min(amount / 20000.0, 1.0)
        norm_sender = min(max(sender_risk, 0.0), 1.0)
        norm_receiver = min(max(receiver_risk, 0.0), 1.0)
        norm_velocity = min(velocity_count / 10.0, 1.0)

        z = (
            self._intercept
            + self._coefficients["amount"] * norm_amount
            + self._coefficients["sender_risk"] * norm_sender
            + self._coefficients["receiver_risk"] * norm_receiver
            + self._coefficients["velocity"] * norm_velocity
        )
        score = 1.0 / (1.0 + math.exp(-z))

        # Linear SHAP (exact for logistic regression in log-odds space)
        attributions = {
            "amount_log": round(self._coefficients["amount"] * (norm_amount - self._feature_means["amount"]), 4),
            "sender_risk": round(self._coefficients["sender_risk"] * (norm_sender - self._feature_means["sender_risk"]), 4),
            "receiver_risk": round(self._coefficients["receiver_risk"] * (norm_receiver - self._feature_means["receiver_risk"]), 4),
            "velocity": round(self._coefficients["velocity"] * (norm_velocity - self._feature_means["velocity"]), 4),
        }

        return {
            "risk_score": round(score, 4),
            "model_mode": "fallback",
            "recommended_threshold": 0.75,
            "attributions": attributions,
        }

    @property
    def mode(self) -> str:
        return self._mode

    @property
    def recommended_threshold(self) -> float:
        return self._recommended_threshold


# Module-level singleton instance for high-performance reuse
anomaly_model = AMLAnomalyModel()
