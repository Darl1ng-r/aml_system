import os
import json
import math
import logging

logger = logging.getLogger(__name__)

class AMLAnomalyModel:
    def __init__(self):
        # Load parameters from model_params.json
        params_path = os.path.join(os.path.dirname(__file__), "model_params.json")
        try:
            with open(params_path, "r") as f:
                params = json.load(f)
            self.intercept = params["intercept"]
            self.coefficients = params["coefficients"]
            self.feature_means = params["feature_means"]
            logger.info("Successfully loaded trained Logistic Regression model parameters.")
        except Exception as e:
            logger.error(f"Failed to load model parameters: {e}. Falling back to default heuristics.")
            # Fallback coefficients if file is missing
            self.intercept = -2.36
            self.coefficients = {
                "amount": 3.66,
                "sender_risk": 2.38,
                "receiver_risk": 1.84,
                "velocity": 1.58
            }
            self.feature_means = {
                "amount": 0.13,
                "sender_risk": 0.29,
                "receiver_risk": 0.29,
                "velocity": 0.16
            }

    def predict_risk(self, amount: float, sender_risk: float, receiver_risk: float, velocity_count: int) -> dict:
        """
        Computes the AI risk score using the trained Logistic Regression model
        and returns mathematically exact linear SHAP attributions in log-odds space.
        """
        # Normalize features in [0, 1] range (must match training normalization)
        norm_amount = min(amount / 20000.0, 1.0)
        norm_sender = min(max(sender_risk, 0.0), 1.0)
        norm_receiver = min(max(receiver_risk, 0.0), 1.0)
        norm_velocity = min(velocity_count / 10.0, 1.0)

        # Log-odds prediction: z = beta_0 + sum(beta_i * x_i)
        z = (
            self.intercept +
            self.coefficients["amount"] * norm_amount +
            self.coefficients["sender_risk"] * norm_sender +
            self.coefficients["receiver_risk"] * norm_receiver +
            self.coefficients["velocity"] * norm_velocity
        )

        # Risk score (probability) via logistic sigmoid function
        score = 1.0 / (1.0 + math.exp(-z))

        # Mathematically exact linear SHAP values: phi_i = beta_i * (x_i - E[x_i])
        shap_amount = self.coefficients["amount"] * (norm_amount - self.feature_means["amount"])
        shap_sender = self.coefficients["sender_risk"] * (norm_sender - self.feature_means["sender_risk"])
        shap_receiver = self.coefficients["receiver_risk"] * (norm_receiver - self.feature_means["receiver_risk"])
        shap_velocity = self.coefficients["velocity"] * (norm_velocity - self.feature_means["velocity"])

        return {
            "risk_score": round(score, 4),
            "attributions": {
                "amount": round(shap_amount, 4),
                "sender_risk": round(shap_sender, 4),
                "receiver_risk": round(shap_receiver, 4),
                "velocity": round(shap_velocity, 4)
            }
        }
