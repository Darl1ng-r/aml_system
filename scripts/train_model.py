import json
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, average_precision_score, confusion_matrix

def main():
    # Set random seed for reproducibility
    np.random.seed(42)

    # 1. Generate 2000 synthetic transaction records for training
    # Features: amount, sender_risk, receiver_risk, velocity
    n_samples = 2000

    # Exponential amounts representing standard low-value and occasional high-value transfers
    amounts = np.random.exponential(scale=3000, size=n_samples)
    amounts_norm = np.clip(amounts / 20000.0, 0, 1)

    # Beta distributions for risks (mostly low, with some high risk targets)
    sender_risks = np.random.beta(a=2, b=5, size=n_samples)
    receiver_risks = np.random.beta(a=2, b=5, size=n_samples)

    # Poisson distribution for transaction velocity count
    velocities = np.random.poisson(lam=1.5, size=n_samples)
    velocities_norm = np.clip(velocities / 10.0, 0, 1)

    # Label generation logic (anomaly label = 1)
    is_anomaly = []
    for i in range(n_samples):
        # Base threat score formulation
        threat_score = (
            amounts_norm[i] * 0.40 +
            sender_risks[i] * 0.25 +
            receiver_risks[i] * 0.20 +
            velocities_norm[i] * 0.15
        )
        # Probabilistic anomaly assignment
        prob = 1.0 / (1.0 + np.exp(-(threat_score * 5.0 - 2.5)))
        is_anomaly.append(1 if np.random.rand() < prob else 0)

    is_anomaly = np.array(is_anomaly)

    # Prepare features and target
    X = np.stack([amounts_norm, sender_risks, receiver_risks, velocities_norm], axis=1)
    y = is_anomaly

    # 2. Split dataset into train and test sets (80% train, 20% test)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # 3. Model Training with 5-Fold Cross-Validation on the training set
    clf = LogisticRegression()
    cv_scores = cross_val_score(clf, X_train, y_train, cv=5, scoring='roc_auc')
    print(f"5-Fold CV ROC-AUC: {np.mean(cv_scores):.4f} (+/- {np.std(cv_scores):.4f})")

    # Fit model on training set
    clf.fit(X_train, y_train)

    # 4. Evaluate on Test Set
    y_pred_prob = clf.predict_proba(X_test)[:, 1]
    y_pred = (y_pred_prob >= 0.75).astype(int)

    test_accuracy = accuracy_score(y_test, y_pred)
    test_precision = precision_score(y_test, y_pred, zero_division=0)
    test_recall = recall_score(y_test, y_pred, zero_division=0)
    test_f1 = f1_score(y_test, y_pred, zero_division=0)
    test_roc_auc = roc_auc_score(y_test, y_pred_prob)
    test_pr_auc = average_precision_score(y_test, y_pred_prob)

    print("\n--- Test Set Performance (Threshold = 0.75) ---")
    print(f"Accuracy: {test_accuracy:.4f}")
    print(f"Precision: {test_precision:.4f}")
    print(f"Recall (True Positive Rate): {test_recall:.4f}")
    print(f"F1-Score: {test_f1:.4f}")
    print(f"ROC-AUC: {test_roc_auc:.4f}")
    print(f"PR-AUC (Average Precision): {test_pr_auc:.4f}")

    # 5. Threshold Calibration & False Positive Rate (FPR) Analysis
    thresholds = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.75, 0.8, 0.9]
    calibration_report = []

    print("\n--- Decision Threshold Calibration Table ---")
    print(f"{'Threshold':<10} | {'TPR (Recall)':<12} | {'FPR':<10} | {'Precision':<10} | {'F1-Score':<10} | {'Alert Volume':<12}")
    print("-" * 75)
    
    for t in thresholds:
        y_pred_t = (y_pred_prob >= t).astype(int)
        tn, fp, fn, tp = confusion_matrix(y_test, y_pred_t).ravel()
        
        tpr = tp / (tp + fn) if (tp + fn) > 0 else 0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0
        f1 = 2 * (prec * tpr) / (prec + tpr) if (prec + tpr) > 0 else 0
        alert_vol = (tp + fp) / len(y_test)
        
        print(f"{t:<10.2f} | {tpr:<12.4f} | {fpr:<10.4f} | {prec:<10.4f} | {f1:<10.4f} | {alert_vol:<12.4f}")
        
        calibration_report.append({
            "threshold": t,
            "tpr": tpr,
            "fpr": fpr,
            "precision": prec,
            "f1_score": f1,
            "alert_volume": alert_vol
        })

    # Compute baseline feature means (E[x] population averages)
    feature_means = np.mean(X_train, axis=0)

    # 6. Compile and save parameters
    params = {
        "intercept": float(clf.intercept_[0]),
        "coefficients": {
            "amount": float(clf.coef_[0][0]),
            "sender_risk": float(clf.coef_[0][1]),
            "receiver_risk": float(clf.coef_[0][2]),
            "velocity": float(clf.coef_[0][3])
        },
        "feature_means": {
            "amount": float(feature_means[0]),
            "sender_risk": float(feature_means[1]),
            "receiver_risk": float(feature_means[2]),
            "velocity": float(feature_means[3])
        }
    }

    # Save parameters to file
    params_path = "services/model_params.json"
    with open(params_path, "w") as f:
        json.dump(params, f, indent=4)

    # Save metrics and calibration report
    report = {
        "test_metrics": {
            "accuracy": test_accuracy,
            "precision": test_precision,
            "recall": test_recall,
            "f1_score": test_f1,
            "roc_auc": test_roc_auc,
            "pr_auc": test_pr_auc
        },
        "threshold_calibration": calibration_report
    }
    
    report_path = "scripts/model_training_report.json"
    with open(report_path, "w") as f:
        json.dump(report, f, indent=4)

    print(f"\nModel parameters successfully saved to {params_path}")
    print(f"Model training report saved to {report_path}")

if __name__ == "__main__":
    main()
