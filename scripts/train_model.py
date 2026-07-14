import json
import numpy as np
from sklearn.linear_model import LogisticRegression

def main():
    # Set random seed for reproducibility
    np.random.seed(42)

    # Generate 1000 synthetic transaction records
    # Features: amount, sender_risk, receiver_risk, velocity
    n_samples = 1000

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

    # Train a real Logistic Regression Classifier
    clf = LogisticRegression()
    clf.fit(X, y)

    # Compute baseline feature means (E[x] population averages)
    feature_means = np.mean(X, axis=0)

    # Compile coefficients, intercept, and expectations
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

    # Save to file
    params_path = "services/model_params.json"
    with open(params_path, "w") as f:
        json.dump(params, f, indent=4)

    print(f"Model parameters successfully saved to {params_path}")
    print(f"Intercept: {params['intercept']:.4f}")
    print(f"Coefficients: {params['coefficients']}")
    print(f"Feature Means (E[x]): {params['feature_means']}")

if __name__ == "__main__":
    main()
