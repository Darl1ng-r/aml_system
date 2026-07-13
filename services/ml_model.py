import math

class AMLAnomalyModel:
    def __init__(self):
        # Heuristic weights for explaining model decisions (simulating SHAP value mapping)
        self.weights = {
            "amount": 0.40,
            "sender_risk": 0.25,
            "receiver_risk": 0.20,
            "velocity": 0.15
        }

    def predict_risk(self, amount: float, sender_risk: float, receiver_risk: float, velocity_count: int) -> dict:
        """
        Computes the AI risk score using a logistic sigmoid function over normalized features
        and returns the SHAP attributions for model explainability (XAI).
        """
        # Normalize features to [0, 1] range for the model input
        norm_amount = min(amount / 20000.0, 1.0) # Cap at $20k for normalization
        norm_sender = min(max(sender_risk, 0.0), 1.0)
        norm_receiver = min(max(receiver_risk, 0.0), 1.0)
        norm_velocity = min(velocity_count / 10.0, 1.0) # Cap at 10 transactions

        # Compute raw activation
        act_amount = norm_amount * self.weights["amount"]
        act_sender = norm_sender * self.weights["sender_risk"]
        act_receiver = norm_receiver * self.weights["receiver_risk"]
        act_velocity = norm_velocity * self.weights["velocity"]

        raw_score = act_amount + act_sender + act_receiver + act_velocity
        
        # Logistic sigmoid to get score in [0.0, 1.0]
        # Subtracting bias of 0.35 so baseline transactions are very low score (~0.05 - 0.15)
        bias = -1.8
        score = 1.0 / (1.0 + math.exp(-(raw_score * 4.0 + bias)))

        # Calculate attributions (simulated SHAP values)
        # Sum of attributions + base_value = score
        total_act = act_amount + act_sender + act_receiver + act_velocity
        if total_act > 0:
            shap_amount = round(act_amount / total_act * score, 4)
            shap_sender = round(act_sender / total_act * score, 4)
            shap_receiver = round(act_receiver / total_act * score, 4)
            shap_velocity = round(act_velocity / total_act * score, 4)
        else:
            shap_amount = shap_sender = shap_receiver = shap_velocity = 0.0

        return {
            "risk_score": round(score, 4),
            "attributions": {
                "amount": shap_amount,
                "sender_risk": shap_sender,
                "receiver_risk": shap_receiver,
                "velocity": shap_velocity
            }
        }
