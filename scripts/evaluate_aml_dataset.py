import os
import sys
import csv
from datetime import datetime, timedelta
import numpy as np
import math

# Add parent directory to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.isolation_forest import IsolationForestScratch
from services.dynamic_scorer import compute_dynamic_risk

# Data file path
TRANS_PATH = os.path.join("archive", "HI-Small_Trans.csv")

def parse_timestamp(ts_str):
    try:
        return datetime.strptime(ts_str.strip(), "%Y/%m/%d %H:%M")
    except Exception:
        # Fallback format
        try:
            return datetime.fromisoformat(ts_str.strip())
        except Exception:
            return datetime.now()

def run_evaluation(sample_rows=50000):
    if not os.path.exists(TRANS_PATH):
        print(f"Transaction file not found: {TRANS_PATH}")
        return
        
    print(f"Reading first {sample_rows} transactions from dataset...")
    
    transactions = []
    
    with open(TRANS_PATH, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.reader(f)
        header = next(reader)
        
        # Header: Timestamp,From Bank,Account,To Bank,Account,Amount Received,Receiving Currency,Amount Paid,Payment Currency,Payment Format,Is Laundering
        for row in reader:
            if len(row) < 11:
                continue
            try:
                ts = parse_timestamp(row[0])
                from_bank = row[1]
                from_acc = row[2]
                to_bank = row[3]
                to_acc = row[4]
                amt_received = float(row[5])
                currency_rec = row[6]
                amt_paid = float(row[7])
                currency_paid = row[8]
                pay_format = row[9]
                is_laundering = int(row[10])
                
                transactions.append({
                    "timestamp": ts,
                    "from_bank": from_bank,
                    "from_acc": from_acc,
                    "to_bank": to_bank,
                    "to_acc": to_acc,
                    "amount": amt_paid,
                    "currency": currency_paid,
                    "pay_format": pay_format,
                    "is_laundering": is_laundering
                })
                
                if len(transactions) >= sample_rows:
                    break
            except Exception as e:
                pass
                
    print(f"Loaded {len(transactions)} transactions.")
    
    # 1. Split data for Isolation Forest training (first 20% to train system-wide model)
    train_split = int(len(transactions) * 0.20)
    train_txs = transactions[:train_split]
    eval_txs = transactions[train_split:]
    
    print(f"Training custom Isolation Forest on {len(train_txs)} transactions...")
    features_list = []
    
    # High risk currencies as proxy for geographic risk
    high_risk_currencies = {"Ruble", "Yuan", "Shekel", "Dinar"}
    
    for tx in train_txs:
        amount = tx["amount"]
        sender_risk = 0.90 if tx["is_laundering"] else 0.10
        receiver_risk = 0.90 if tx["is_laundering"] else 0.10
        hour = tx["timestamp"].hour
        is_geo = 1 if tx["currency"] in high_risk_currencies else 0
        features_list.append([amount, sender_risk, receiver_risk, hour, is_geo])
        
    X_train = np.array(features_list)
    forest = IsolationForestScratch(n_estimators=30, max_samples=256)
    forest.fit(X_train)
    print("Isolation Forest trained successfully.")
    
    # 2. Simulate in-memory account history and baseline calculation
    # dict of account_id -> list of (amount, timestamp, is_incoming)
    history = {}
    
    def get_baseline_profile(acc):
        acc_txs = history.get(acc, [])
        outgoing_txs = [tx for tx in acc_txs if not tx["is_incoming"]]
        
        if not outgoing_txs:
            return {
                "avg_amount": 0.0,
                "variance_amount": 0.0
            }
            
        amounts = [tx["amount"] for tx in outgoing_txs]
        return {
            "avg_amount": float(np.mean(amounts)),
            "variance_amount": float(np.var(amounts)) if len(amounts) > 1 else 0.0
        }
        
    def add_to_history(acc, amount, ts, is_incoming):
        if acc not in history:
            history[acc] = []
        history[acc].append({"amount": amount, "timestamp": ts, "is_incoming": is_incoming})
        
    # Populate history with training transactions
    for tx in train_txs:
        add_to_history(tx["from_acc"], tx["amount"], tx["timestamp"], is_incoming=False)
        add_to_history(tx["to_acc"], tx["amount"], tx["timestamp"], is_incoming=True)
        
    # 3. Evaluate on eval_txs
    print(f"Evaluating remaining {len(eval_txs)} transactions...")
    
    y_true = []
    y_pred = []
    
    tp = fp = fn = tn = 0
    
    for tx in eval_txs:
        from_acc = tx["from_acc"]
        to_acc = tx["to_acc"]
        amount = tx["amount"]
        ts = tx["timestamp"]
        
        # Rules evaluation
        triggered_rules = []
        
        # Rule 1: Large Transaction (threshold 50,000 in this dataset scale)
        if amount >= 50000.0:
            triggered_rules.append("LARGE_TRANSACTION")
            
        # Rule 2: Structuring sliding window (24h)
        from_history = history.get(from_acc, [])
        window_ago = ts - timedelta(hours=24)
        recent_txs = [h for h in from_history if not h["is_incoming"] and h["timestamp"] >= window_ago]
        recent_amounts = [h["amount"] for h in recent_txs]
        
        # Sum of 24h + current
        tot_recent = sum(recent_amounts) + amount
        all_below_50k = all(amt < 50000.0 for amt in recent_amounts) and amount < 50000.0
        if tot_recent >= 50000.0 and all_below_50k and (len(recent_amounts) + 1) >= 2:
            triggered_rules.append("STRUCTURING")
            
        # Rule 3: Geographic Risk
        is_geo = 1 if tx["currency"] in high_risk_currencies else 0
        if is_geo:
            triggered_rules.append("GEOGRAPHIC_RISK")
            
        # Rule 4: Rapid Movement of Funds
        # Find last incoming completed transaction in last 10 minutes
        ten_mins_ago = ts - timedelta(minutes=10)
        recent_incoming = [h for h in from_history if h["is_incoming"] and h["timestamp"] >= ten_mins_ago]
        if recent_incoming:
            last_inc_amt = recent_incoming[-1]["amount"]
            if amount >= last_inc_amt * 0.90:
                triggered_rules.append("RAPID_MOVEMENT")
                
        # Z-score & Dynamic scoring
        baseline = get_baseline_profile(from_acc)
        
        # Run Isolation Forest
        # Mock sender/receiver risk parameters
        sender_risk = 0.50 if triggered_rules else 0.10
        receiver_risk = 0.10
        x = np.array([amount, sender_risk, receiver_risk, ts.hour, is_geo])
        iforest_score = forest.compute_anomaly_score(x)
        
        # Calculate dynamic risk score (simplified)
        ml_score = 0.80 if triggered_rules else 0.10
        dynamic_res = compute_dynamic_risk(
            rules_triggered=triggered_rules,
            ml_score=ml_score,
            amount=amount,
            baseline=baseline,
            iforest_score=iforest_score
        )
        dynamic_score = dynamic_res["dynamic_risk_score"]
        
        # Pred score >= 0.75 maps to laundering alert
        pred = 1 if dynamic_score >= 0.75 or triggered_rules else 0
        true = tx["is_laundering"]
        
        y_true.append(true)
        y_pred.append(pred)
        
        if pred == 1 and true == 1:
            tp += 1
        elif pred == 1 and true == 0:
            fp += 1
        elif pred == 0 and true == 1:
            fn += 1
        elif pred == 0 and true == 0:
            tn += 1
            
        # Update history
        add_to_history(from_acc, amount, ts, is_incoming=False)
        add_to_history(to_acc, amount, ts, is_incoming=True)

    # Output report
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    accuracy = (tp + tn) / len(eval_txs)
    alert_rate = (tp + fp) / len(eval_txs)
    
    print("\n================ Classification Performance Report ================")
    print(f"Total Evaluated Transactions: {len(eval_txs)}")
    print(f"True Positive (TP) Alerts  : {tp}")
    print(f"False Positive (FP) Alerts : {fp}")
    print(f"False Negative (FN) Missed : {fn}")
    print(f"True Negative (TN) Cleared : {tn}")
    print("-" * 50)
    print(f"Accuracy                  : {accuracy:.4%}")
    print(f"Precision (Detection Rate): {precision:.4%}")
    print(f"Recall (Recall/TPR)       : {recall:.4%}")
    print(f"F1-Score                  : {f1:.4%}")
    print(f"Alert / Escalation Rate   : {alert_rate:.4%}")
    print("===================================================================\n")

if __name__ == "__main__":
    run_evaluation(50000)
