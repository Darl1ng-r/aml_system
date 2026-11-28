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
from decimal import Decimal
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

DEFAULT_CURRENCY = "US Dollar"
HIGH_RISK_CURRENCIES = {"Ruble", "Yuan", "Shekel", "Dinar", "Iranian Rial"}

# Canonicalizers bridging production ISO-4217 / uppercase channel codes to the IBM-AML training vocabulary
_CURRENCY_TO_TRAINING: dict[str, str] = {
    "USD": "US Dollar",
    "US DOLLAR": "US Dollar",
    "EUR": "Euro",
    "EURO": "Euro",
    "GBP": "UK Pound",
    "UK POUND": "UK Pound",
    "CHF": "Swiss Franc",
    "SWISS FRANC": "Swiss Franc",
    "CAD": "Canadian Dollar",
    "CANADIAN DOLLAR": "Canadian Dollar",
    "AUD": "Australian Dollar",
    "AUSTRALIAN DOLLAR": "Australian Dollar",
    "JPY": "Yen",
    "YEN": "Yen",
    "RUB": "Ruble",
    "RUBLE": "Ruble",
    "CNY": "Yuan",
    "CNH": "Yuan",
    "YUAN": "Yuan",
    "ILS": "Shekel",
    "SHEKEL": "Shekel",
    "IQD": "Dinar",
    "JOD": "Dinar",
    "KWD": "Dinar",
    "BHD": "Dinar",
    "LYD": "Dinar",
    "TND": "Dinar",
    "DINAR": "Dinar",
    "IRR": "Iranian Rial",
    "IRANIAN RIAL": "Iranian Rial",
    "SAR": "Saudi Riyal",
    "SAUDI RIYAL": "Saudi Riyal",
    "MXN": "Mexican Peso",
    "MEXICAN PESO": "Mexican Peso",
    "BRL": "Brazil Real",
    "BRAZIL REAL": "Brazil Real",
    "INR": "Rupee",
    "RUPEE": "Rupee",
    "BTC": "Bitcoin",
    "BITCOIN": "Bitcoin",
}

_CHANNEL_TO_TRAINING: dict[str, str] = {
    "CASH": "Cash",
    "CHEQUE": "Cheque",
    "CHECK": "Cheque",
    "CREDIT CARD": "Credit Card",
    "CREDIT_CARD": "Credit Card",
    "CARD": "Credit Card",
    "DEBIT_CARD": "Credit Card",
    "ACH": "ACH",
    "WIRE": "Wire",
    "SWIFT": "Wire",
    "CROSS_BORDER": "Wire",
    "SEPA": "Wire",
    "REINVESTMENT": "Reinvestment",
    "BITCOIN": "Bitcoin",
    "BTC": "Bitcoin",
    "CRYPTO": "Bitcoin",
    "VASP": "Bitcoin",
    "DIGITAL_ASSET": "Bitcoin",
    "OTHER": "Other",
}


def _finite_float(val: object, default: float = 0.0) -> float:
    try:
        f = float(val)  # type: ignore[arg-type]
        return f if math.isfinite(f) else default
    except (ValueError, TypeError):
        return default


def _canonicalize_currency(currency: str | None) -> str:
    if not currency:
        return DEFAULT_CURRENCY
    cleaned = str(currency).strip()
    if not cleaned:
        return DEFAULT_CURRENCY
    return _CURRENCY_TO_TRAINING.get(cleaned.upper(), cleaned)


def _canonicalize_channel(pay_format: str | None) -> str:
    if not pay_format:
        return "Wire"
    cleaned = str(pay_format).strip()
    if not cleaned:
        return "Wire"
    return _CHANNEL_TO_TRAINING.get(cleaned.upper(), cleaned if cleaned in PAYMENT_FORMATS else "Other")

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
        self._model_version = "fallback-logreg-v1"

        # ── Try loading XGBoost pipeline ──────────────────────────────────────
        if os.path.exists(_MODEL_PATH):
            try:
                import hashlib
                import joblib
                import shap
                with open(_MODEL_PATH, "rb") as mf:
                    digest = hashlib.sha256(mf.read()).hexdigest()[:12]
                self._pipeline = joblib.load(_MODEL_PATH)
                # Build SHAP explainer from the XGBoost classifier inside the pipeline
                xgb_model = self._pipeline.named_steps["classifier"]
                self._explainer = shap.TreeExplainer(xgb_model)
                self._mode = "xgboost"
                self._model_version = f"xgboost-{digest}"

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
                logger.exception(f"Failed to load XGBoost model: {e}. Falling back to legacy formula.")
                self._mode = "fallback"

        # ── Always initialize fallback logistic regression coefficients ───────
        # Ensures runtime fallback from XGBoost inference errors never raises AttributeError.
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
                if self._mode == "fallback":
                    logger.info("Legacy logistic regression parameters loaded from model_params.json.")
            except Exception as e:
                logger.warning(f"Could not load model_params.json: {e}. Using hardcoded defaults.")
        elif self._mode == "fallback":
            logger.warning("No trained model found. Using hardcoded fallback heuristics. Run scripts/train_model.py to train.")

    # ── Feature construction ───────────────────────────────────────────────────
    @staticmethod
    def _build_feature_vector(
        amount: float,
        sender_risk: float,
        receiver_risk: float,
        velocity_count: int,
        hour: int = 12,
        currency_paid: str = DEFAULT_CURRENCY,
        currency_recv: str = DEFAULT_CURRENCY,
        pay_format: str = "Wire",
        amount_received: float | None = None,
        amount_ratio: float | None = None,
    ) -> np.ndarray:
        """
        Constructs the 10-feature vector used during training.
        Canonicalizes ISO-4217 currency codes & uppercase channel names to training vocabulary
        and sanitizes all non-finite/negative values.
        """
        safe_amount = max(_finite_float(amount, 0.0), 0.0)
        amount_log = math.log1p(safe_amount) / math.log1p(AMOUNT_NORM_CAP)
        amount_log = min(max(amount_log, 0.0), 1.0)

        # Feature 2: Amount ratio (amt_received / amt_paid) / 5.0 from training data schema.
        # For domestic/same-currency (where amt_recv == amt_paid), this is exactly 1.0 / 5.0 = 0.20.
        if amount_ratio is not None:
            norm_amount_ratio = min(max(_finite_float(amount_ratio, 0.2), 0.0), 1.0)
        elif amount_received is not None and safe_amount > 0:
            safe_recv = max(_finite_float(amount_received, 0.0), 0.0)
            norm_amount_ratio = min(safe_recv / max(safe_amount, 1e-6), 5.0) / 5.0
        elif safe_amount > 0:
            norm_amount_ratio = 1.0 / 5.0
        else:
            norm_amount_ratio = 0.0

        safe_hour = int(min(max(_finite_float(hour, 12.0), 0.0), 23.0))
        hour_norm = safe_hour / 23.0

        canon_paid = _canonicalize_currency(currency_paid)
        canon_recv = _canonicalize_currency(currency_recv)
        canon_fmt = _canonicalize_channel(pay_format)

        is_geo_risk = 1.0 if canon_paid in HIGH_RISK_CURRENCIES else 0.0
        currency_mismatch = 1.0 if canon_recv != canon_paid else 0.0

        pay_fmt_code = PAYMENT_FORMATS.get(canon_fmt, PAYMENT_FORMATS["Other"]) / 7.0
        is_crypto = 1.0 if canon_fmt == "Bitcoin" else 0.0
        is_cash = 1.0 if canon_fmt == "Cash" else 0.0
        is_reinvestment = 1.0 if canon_fmt == "Reinvestment" else 0.0

        is_round = 0.0
        if 0.0 < safe_amount <= 1e15:
            try:
                amt_dec = Decimal(f"{safe_amount:.2f}")
                if amt_dec % Decimal("1000.00") == Decimal("0"):
                    is_round = 1.0
            except Exception:
                is_round = 0.0

        return np.array([[
            amount_log, norm_amount_ratio, hour_norm, is_geo_risk,
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
        currency_paid: str = DEFAULT_CURRENCY,
        currency_recv: str = DEFAULT_CURRENCY,
        pay_format: str = "Wire",
        explain: bool = False,
        amount_received: float | None = None,
        amount_ratio: float | None = None,
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
                hour, currency_paid, currency_recv, pay_format, explain=explain,
                amount_received=amount_received, amount_ratio=amount_ratio
            )
        else:
            return self._predict_fallback(amount, sender_risk, receiver_risk, velocity_count)

    def predict(self, features: dict) -> tuple[float, dict]:
        """Convenience method accepting a feature dict, returning (risk_score, attributions)."""
        amt_recv = features.get("amount_received", features.get("amt_received", None))
        amt_ratio_val = features.get("amount_ratio", None)
        currency_paid = features.get("currency", DEFAULT_CURRENCY)
        currency_recv = (
            features.get("currency_received")
            or features.get("currency_recv")
            or currency_paid
        )
        res = self.predict_risk(
            amount=_finite_float(features.get("amount", 0.0), 0.0),
            sender_risk=_finite_float(features.get("sender_risk", 0.2), 0.2),
            receiver_risk=_finite_float(features.get("receiver_risk", 0.2), 0.2),
            velocity_count=int(_finite_float(features.get("velocity_24h", features.get("velocity_count", 1)), 1.0)),
            hour=int(_finite_float(features.get("hour_of_day", features.get("hour", 12)), 12.0)),
            currency_paid=currency_paid,
            currency_recv=currency_recv,
            pay_format=features.get("channel", "Wire"),
            explain=True,
            amount_received=_finite_float(amt_recv) if amt_recv is not None else None,
            amount_ratio=_finite_float(amt_ratio_val) if amt_ratio_val is not None else None
        )
        return res["risk_score"], res["attributions"]

    def _predict_xgboost(
        self, amount, sender_risk, receiver_risk, velocity_count,
        hour, currency_paid, currency_recv, pay_format, explain: bool = False,
        amount_received: float | None = None, amount_ratio: float | None = None
    ) -> dict:
        try:
            X = self._build_feature_vector(
                amount, sender_risk, receiver_risk, velocity_count,
                hour, currency_paid, currency_recv, pay_format,
                amount_received=amount_received, amount_ratio=amount_ratio
            )
            # Pipeline applies StandardScaler then XGBoost
            risk_score = float(self._pipeline.predict_proba(X)[0][1])

            # Performance optimization: only execute CPU-intensive SHAP tree traversal
            # for anomalous/borderline transactions or when explicitly requested
            should_compute_shap = explain or (risk_score >= self._recommended_threshold * 0.85)
            if should_compute_shap and self._explainer:
                scaler = self._pipeline.named_steps["scaler"]
                x_scaled = scaler.transform(X)
                shap_vals = self._explainer.shap_values(x_scaled)[0]
                attributions = {
                    name: round(float(val), 6)
                    for name, val in zip(FEATURE_NAMES, shap_vals)
                }
            else:
                attributions = dict.fromkeys(FEATURE_NAMES, 0.0)

            return {
                "risk_score": round(risk_score, 4),
                "model_mode": "xgboost",
                "model_version": self._model_version,
                "recommended_threshold": self._recommended_threshold,
                "attributions": attributions,
            }
        except Exception as e:
            logger.exception(f"XGBoost inference failed: {e}. Falling back to legacy formula.")
            return self._predict_fallback(amount, sender_risk, receiver_risk, velocity_count)

    def _predict_fallback(self, amount, sender_risk, receiver_risk, velocity_count) -> dict:
        """Legacy logistic regression formula (used before model is trained or on runtime fallback)."""
        safe_amount = max(_finite_float(amount, 0.0), 0.0)
        safe_sender = _finite_float(sender_risk, 0.2)
        safe_receiver = _finite_float(receiver_risk, 0.2)
        safe_velocity = max(_finite_float(velocity_count, 0.0), 0.0)

        norm_amount = min(max(safe_amount / 20000.0, 0.0), 1.0)
        norm_sender = min(max(safe_sender, 0.0), 1.0)
        norm_receiver = min(max(safe_receiver, 0.0), 1.0)
        norm_velocity = min(max(safe_velocity / 10.0, 0.0), 1.0)

        z = (
            self._intercept
            + self._coefficients["amount"] * norm_amount
            + self._coefficients["sender_risk"] * norm_sender
            + self._coefficients["receiver_risk"] * norm_receiver
            + self._coefficients["velocity"] * norm_velocity
        )
        z_clamped = min(max(z, -50.0), 50.0)
        score = 1.0 / (1.0 + math.exp(-z_clamped))

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
            "model_version": "fallback-logreg-v1",
            "recommended_threshold": 0.75,
            "attributions": attributions,
        }

    @property
    def mode(self) -> str:
        return self._mode

    @property
    def model_version(self) -> str:
        return self._model_version

    @property
    def recommended_threshold(self) -> float:
        return self._recommended_threshold


# Module-level singleton instance for high-performance reuse
anomaly_model = AMLAnomalyModel()
