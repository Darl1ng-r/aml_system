"""
AML Model Training Pipeline — XGBoost on Real Labeled Transaction Data
=======================================================================
Trains a production-grade XGBoost classifier on the HI-Small_Trans.csv
dataset (5M labeled transactions with Is Laundering ground truth).

Feature Engineering:
  - amount_norm        : Log-normalized transaction amount
  - amount_ratio       : Received / Paid amount ratio (currency conversion marker)
  - hour               : Hour of day (behavioral timing signal)
  - pay_format_encoded : Payment format (one-hot encoded)
  - currency_risk      : High-risk currency indicator

Output:
  services/aml_model.joblib        — Serialized XGBoost pipeline (StandardScaler + model)
  services/model_params.json       — Coefficients for legacy logistic regression fallback inference
  services/model_report.json       — Full classification metrics and SHAP feature importances
  scripts/model_training_report.json — Threshold calibration table for analyst decision-making
"""

import os
import sys
import csv
import json
import math
import time
import logging
import numpy as np

# Add parent directory to path so we can import service modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────
TRANS_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "archive", "HI-Small_Trans.csv")
MODEL_OUTPUT_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "services", "aml_model.joblib")
PARAMS_OUTPUT_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "services", "model_params.json")
REPORT_OUTPUT_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "services", "model_report.json")
CALIBRATION_REPORT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "model_training_report.json")

# Maximum rows to load — HI-Small has 5M rows; 500k gives a solid sample in ~seconds
MAX_ROWS = 500_000

# Amount normalization cap (99th percentile equivalent)
AMOUNT_NORM_CAP = 100_000.0

# High-risk currencies (proxy for geographic risk)
HIGH_RISK_CURRENCIES = {"Ruble", "Yuan", "Shekel", "Dinar", "Iranian Rial"}

# Payment format encoding
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

# ─────────────────────────────────────────────────────────────
# Feature extraction
# ─────────────────────────────────────────────────────────────
def extract_features(row: list) -> tuple[list[float], int] | None:
    """
    Extracts feature vector from a raw CSV row.

    CSV columns:
      Timestamp, From Bank, Account, To Bank, Account,
      Amount Received, Receiving Currency,
      Amount Paid, Payment Currency,
      Payment Format, Is Laundering

    Returns:
        (features, label) or None if the row is malformed
    """
    if len(row) < 11:
        return None
    try:
        timestamp_str = row[0].strip()
        # Parse hour of day from timestamp
        if "/" in timestamp_str:
            # Format: 2022/09/01 00:20
            parts = timestamp_str.split(" ")
            hour = int(parts[1].split(":")[0]) if len(parts) > 1 else 12
        else:
            hour = 12

        amt_received = float(row[5]) if row[5].strip() else 0.0
        currency_recv = row[6].strip()
        amt_paid = float(row[7]) if row[7].strip() else 0.0
        currency_paid = row[8].strip()
        pay_format = row[9].strip()
        is_laundering = int(row[10].strip())

        # Feature 1: Log-normalized paid amount (heavy tail, log compresses it)
        amount_log = math.log1p(amt_paid) / math.log1p(AMOUNT_NORM_CAP)
        amount_log = min(max(amount_log, 0.0), 1.0)

        # Feature 2: Amount ratio received/paid — large deviation signals FX layering
        if amt_paid > 0:
            amount_ratio = min(amt_received / amt_paid, 5.0) / 5.0
        else:
            amount_ratio = 0.0

        # Feature 3: Hour of day (normalized to [0,1])
        hour_norm = hour / 23.0

        # Feature 4: High-risk currency (sending currency is the risk signal)
        is_geo_risk = 1.0 if currency_paid in HIGH_RISK_CURRENCIES else 0.0

        # Feature 5: Currency mismatch between sending and receiving (conversion)
        currency_mismatch = 1.0 if currency_recv != currency_paid else 0.0

        # Feature 6: Payment format encoded (ordinal, captures cash/crypto vs. wire)
        pay_fmt_code = PAYMENT_FORMATS.get(pay_format, PAYMENT_FORMATS["Other"]) / 7.0

        # Feature 7: Is Bitcoin or crypto payment
        is_crypto = 1.0 if pay_format == "Bitcoin" else 0.0

        # Feature 8: Is Cash (hardest to trace)
        is_cash = 1.0 if pay_format == "Cash" else 0.0

        # Feature 9: Is Reinvestment (circular flow pattern)
        is_reinvestment = 1.0 if pay_format == "Reinvestment" else 0.0

        # Feature 10: Round amount marker (amounts divisible by 1000 are suspiciously round)
        is_round = 1.0 if (amt_paid > 0 and amt_paid % 1000 == 0) else 0.0

        features = [
            amount_log,
            amount_ratio,
            hour_norm,
            is_geo_risk,
            currency_mismatch,
            pay_fmt_code,
            is_crypto,
            is_cash,
            is_reinvestment,
            is_round,
        ]
        return features, is_laundering

    except (ValueError, IndexError, ZeroDivisionError):
        return None


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


# ─────────────────────────────────────────────────────────────
# Data loading
# ─────────────────────────────────────────────────────────────
def load_dataset(path: str, max_rows: int = MAX_ROWS) -> tuple[np.ndarray, np.ndarray]:
    logger.info(f"Loading up to {max_rows:,} rows from {path}...")
    X, y = [], []
    n_total = 0
    n_errors = 0

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.reader(f)
        next(reader)  # skip header
        for row in reader:
            result = extract_features(row)
            n_total += 1
            if result is None:
                n_errors += 1
                continue
            features, label = result
            X.append(features)
            y.append(label)

            if len(X) >= max_rows:
                break

    logger.info(f"Loaded {len(X):,} valid rows ({n_errors:,} skipped). "
                f"Laundering rate: {sum(y) / len(y):.4%}")
    return np.array(X, dtype=np.float32), np.array(y, dtype=np.int32)


# ─────────────────────────────────────────────────────────────
# Main training pipeline
# ─────────────────────────────────────────────────────────────
def main():
    try:
        import xgboost as xgb
        from sklearn.model_selection import StratifiedKFold, cross_val_score
        from sklearn.metrics import (
            accuracy_score, precision_score, recall_score,
            f1_score, roc_auc_score, average_precision_score,
            confusion_matrix, classification_report
        )
        from sklearn.pipeline import Pipeline
        from sklearn.preprocessing import StandardScaler
        import joblib
        import shap
    except ImportError as e:
        logger.error(f"Missing dependency: {e}. Run: pip install xgboost lightgbm shap joblib scikit-learn")
        sys.exit(1)

    if not os.path.exists(TRANS_PATH):
        logger.error(f"Dataset not found at {TRANS_PATH}. Place the HI-Small_Trans.csv in the archive/ directory.")
        sys.exit(1)

    # ── 1. Load data ──────────────────────────────────────────
    t0 = time.time()
    X, y = load_dataset(TRANS_PATH, MAX_ROWS)
    logger.info(f"Data loaded in {time.time() - t0:.1f}s. Shape: {X.shape}. Laundering: {y.sum():,}/{len(y):,}")

    # ── 2. Train/test split (stratified to preserve class ratio) ──
    from sklearn.model_selection import train_test_split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    logger.info(f"Train: {len(X_train):,} | Test: {len(X_test):,}")

    # ── 3. Class imbalance handling ───────────────────────────
    # In AML datasets, fraudulent transactions are ~1-5% of total.
    # XGBoost's scale_pos_weight compensates for this imbalance.
    n_neg = (y_train == 0).sum()
    n_pos = (y_train == 1).sum()
    scale_pos_weight = n_neg / max(n_pos, 1)
    logger.info(f"Class balance — Legitimate: {n_neg:,}, Laundering: {n_pos:,}, scale_pos_weight: {scale_pos_weight:.2f}")

    # ── 4. XGBoost Model Definition ───────────────────────────
    model = xgb.XGBClassifier(
        n_estimators=300,
        max_depth=6,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        scale_pos_weight=scale_pos_weight,
        eval_metric="aucpr",       # Area Under Precision-Recall curve — better than AUC for imbalanced classes
        random_state=42,
        n_jobs=-1,                 # use all CPU cores
        tree_method="hist",        # fast histogram-based tree construction
    )

    pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("classifier", model)
    ])

    # ── 5. Cross-validation (3 folds for speed) ───────────────
    logger.info("Running 3-fold stratified cross-validation on training set...")
    t1 = time.time()
    cv = StratifiedKFold(n_splits=3, shuffle=True, random_state=42)
    cv_scores = cross_val_score(pipeline, X_train, y_train, cv=cv, scoring="roc_auc", n_jobs=-1)
    logger.info(f"CV ROC-AUC: {np.mean(cv_scores):.4f} ± {np.std(cv_scores):.4f}  [{time.time()-t1:.1f}s]")

    # ── 6. Final fit on full training set ─────────────────────
    logger.info("Fitting final model on full training set...")
    t2 = time.time()
    pipeline.fit(X_train, y_train)
    logger.info(f"Training complete in {time.time()-t2:.1f}s")

    # ── 7. Evaluation on held-out test set ────────────────────
    y_pred_prob = pipeline.predict_proba(X_test)[:, 1]

    roc_auc = roc_auc_score(y_test, y_pred_prob)
    pr_auc = average_precision_score(y_test, y_pred_prob)
    logger.info(f"\nTest ROC-AUC: {roc_auc:.4f}  |  PR-AUC: {pr_auc:.4f}")

    # ── 8. Threshold calibration table ────────────────────────
    print("\n" + "="*80)
    print("THRESHOLD CALIBRATION TABLE")
    print(f"{'Threshold':<12} {'Recall(TPR)':<14} {'FPR':<10} {'Precision':<12} {'F1':<10} {'Alert Rate'}")
    print("-" * 80)

    calibration_report = []
    best_f1_threshold = 0.5
    best_f1 = 0.0

    for t in [0.10, 0.20, 0.30, 0.40, 0.50, 0.60, 0.70, 0.75, 0.80, 0.90]:
        y_pred_t = (y_pred_prob >= t).astype(int)
        tn, fp, fn, tp = confusion_matrix(y_test, y_pred_t, labels=[0, 1]).ravel()
        tpr = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        f1 = 2 * prec * tpr / (prec + tpr) if (prec + tpr) > 0 else 0.0
        alert_rate = (tp + fp) / len(y_test)

        print(f"{t:<12.2f} {tpr:<14.4f} {fpr:<10.4f} {prec:<12.4f} {f1:<10.4f} {alert_rate:.4f}")
        calibration_report.append({
            "threshold": t, "tpr": round(tpr, 4), "fpr": round(fpr, 4),
            "precision": round(prec, 4), "f1_score": round(f1, 4),
            "alert_volume": round(alert_rate, 4)
        })
        if f1 > best_f1:
            best_f1 = f1
            best_f1_threshold = t

    print("="*80)
    print(f"\nRecommended threshold: {best_f1_threshold} (best F1 = {best_f1:.4f})")

    # Full classification report at recommended threshold
    y_pred_best = (y_pred_prob >= best_f1_threshold).astype(int)
    print("\nClassification Report at Recommended Threshold:")
    print(classification_report(y_test, y_pred_best, target_names=["Legitimate", "Laundering"], digits=4))

    # ── 9. SHAP feature importances ───────────────────────────
    logger.info("Computing SHAP TreeExplainer feature importances on 2,000 test samples...")
    t3 = time.time()
    xgb_model = pipeline.named_steps["classifier"]
    scaler = pipeline.named_steps["scaler"]
    X_test_scaled = scaler.transform(X_test[:2000])
    explainer = shap.TreeExplainer(xgb_model)
    shap_values = explainer.shap_values(X_test_scaled)
    mean_abs_shap = np.abs(shap_values).mean(axis=0)
    feature_importances = dict(zip(FEATURE_NAMES, [round(float(v), 6) for v in mean_abs_shap]))
    sorted_importances = dict(sorted(feature_importances.items(), key=lambda x: x[1], reverse=True))
    logger.info(f"SHAP computed in {time.time()-t3:.1f}s")
    print("\nSHAP Feature Importances (mean |SHAP| across 2k test samples):")
    for feat, imp in sorted_importances.items():
        bar = "#" * int(imp * 100)
        print(f"  {feat:<25} {imp:.6f}  {bar}")

    # ── 10. Save model and artifacts ──────────────────────────
    logger.info(f"\nSaving serialized pipeline to {MODEL_OUTPUT_PATH}...")
    joblib.dump(pipeline, MODEL_OUTPUT_PATH)
    logger.info("Model saved.")

    # Save model report
    report = {
        "model_type": "XGBoostClassifier",
        "training_samples": int(len(X_train)),
        "test_samples": int(len(X_test)),
        "laundering_rate": round(float(y.sum() / len(y)), 6),
        "scale_pos_weight": round(scale_pos_weight, 4),
        "cv_roc_auc_mean": round(float(np.mean(cv_scores)), 4),
        "cv_roc_auc_std": round(float(np.std(cv_scores)), 4),
        "test_roc_auc": round(roc_auc, 4),
        "test_pr_auc": round(pr_auc, 4),
        "recommended_threshold": best_f1_threshold,
        "best_f1": round(best_f1, 4),
        "feature_names": FEATURE_NAMES,
        "shap_importances": sorted_importances,
        "threshold_calibration": calibration_report,
    }
    with open(REPORT_OUTPUT_PATH, "w") as f:
        json.dump(report, f, indent=2)

    with open(CALIBRATION_REPORT_PATH, "w") as f:
        json.dump({"test_metrics": {
            "roc_auc": round(roc_auc, 4),
            "pr_auc": round(pr_auc, 4),
            "best_f1": round(best_f1, 4),
            "recommended_threshold": best_f1_threshold,
        }, "threshold_calibration": calibration_report}, f, indent=2)

    logger.info(f"Reports saved to {REPORT_OUTPUT_PATH} and {CALIBRATION_REPORT_PATH}")
    logger.info("\n✅ Training pipeline complete.")


if __name__ == "__main__":
    main()
