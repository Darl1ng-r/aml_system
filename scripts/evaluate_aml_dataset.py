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

HIGH_RISK_CURRENCIES = {"Ruble", "Yuan", "Shekel", "Dinar"}


class _AccountHistoryTracker:
    """Simulates in-memory account history and baseline calculation."""

    def __init__(self):
        self.history = {}

    def get_baseline_profile(self, acc: str) -> dict:
        acc_txs = self.history.get(acc, [])
        outgoing_txs = [tx for tx in acc_txs if not tx["is_incoming"]]
        if not outgoing_txs:
            return {"avg_amount": 0.0, "variance_amount": 0.0}

        amounts = [tx["amount"] for tx in outgoing_txs]
        return {
            "avg_amount": float(np.mean(amounts)),
            "variance_amount": float(np.var(amounts)) if len(amounts) > 1 else 0.0,
        }

    def add_to_history(self, acc: str, amount: float, ts: datetime, is_incoming: bool):
        if acc not in self.history:
            self.history[acc] = []
        self.history[acc].append({"amount": amount, "timestamp": ts, "is_incoming": is_incoming})


def _parse_csv_row(row: list) -> dict | None:
    if len(row) < 11:
        return None
    try:
        return {
            "timestamp": parse_timestamp(row[0]),
            "from_bank": row[1],
            "from_acc": row[2],
            "to_bank": row[3],
            "to_acc": row[4],
            "amount": float(row[7]),
            "currency": row[8],
            "pay_format": row[9],
            "is_laundering": int(row[10]),
        }
    except Exception:
        return None


def _load_transactions(path: str, sample_rows: int) -> list[dict]:
    transactions = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.reader(f)
        next(reader, None)
        for row in reader:
            parsed = _parse_csv_row(row)
            if parsed:
                transactions.append(parsed)
                if len(transactions) >= sample_rows:
                    break
    return transactions


def _train_isolation_forest(train_txs: list[dict]) -> IsolationForestScratch:
    features_list = []
    for tx in train_txs:
        amount = tx["amount"]
        sender_risk = 0.90 if tx["is_laundering"] else 0.10
        receiver_risk = 0.90 if tx["is_laundering"] else 0.10
        hour = tx["timestamp"].hour
        is_geo = 1 if tx["currency"] in HIGH_RISK_CURRENCIES else 0
        features_list.append([amount, sender_risk, receiver_risk, hour, is_geo])

    X_train = np.array(features_list)
    forest = IsolationForestScratch(n_estimators=30, max_samples=256)
    forest.fit(X_train)
    return forest


def _evaluate_rules(tx: dict, from_history: list[dict]) -> list[str]:
    triggered = []
    amount = tx["amount"]
    ts = tx["timestamp"]

    # Rule 1: Large Transaction
    if amount >= 50000.0:
        triggered.append("LARGE_TRANSACTION")

    # Rule 2: Structuring sliding window (24h)
    window_ago = ts - timedelta(hours=24)
    recent_txs = [h for h in from_history if not h["is_incoming"] and h["timestamp"] >= window_ago]
    recent_amounts = [h["amount"] for h in recent_txs]
    tot_recent = sum(recent_amounts) + amount
    all_below_50k = all(amt < 50000.0 for amt in recent_amounts) and amount < 50000.0
    if tot_recent >= 50000.0 and all_below_50k and (len(recent_amounts) + 1) >= 2:
        triggered.append("STRUCTURING")

    # Rule 3: Geographic Risk
    if tx["currency"] in HIGH_RISK_CURRENCIES:
        triggered.append("GEOGRAPHIC_RISK")

    # Rule 4: Rapid Movement of Funds
    ten_mins_ago = ts - timedelta(minutes=10)
    recent_incoming = [h for h in from_history if h["is_incoming"] and h["timestamp"] >= ten_mins_ago]
    if recent_incoming and amount >= recent_incoming[-1]["amount"] * 0.90:
        triggered.append("RAPID_MOVEMENT")

    return triggered


def _evaluate_single_transaction(
    tx: dict, tracker: _AccountHistoryTracker, forest: IsolationForestScratch
) -> tuple[int, int]:
    from_acc = tx["from_acc"]
    amount = tx["amount"]
    ts = tx["timestamp"]
    from_history = tracker.history.get(from_acc, [])

    triggered_rules = _evaluate_rules(tx, from_history)
    baseline = tracker.get_baseline_profile(from_acc)

    sender_risk = 0.50 if triggered_rules else 0.10
    receiver_risk = 0.10
    is_geo = 1 if tx["currency"] in HIGH_RISK_CURRENCIES else 0
    x = np.array([amount, sender_risk, receiver_risk, ts.hour, is_geo])
    iforest_score = forest.compute_anomaly_score(x)

    ml_score = 0.80 if triggered_rules else 0.10
    dynamic_res = compute_dynamic_risk(
        rules_triggered=triggered_rules,
        ml_score=ml_score,
        amount=amount,
        baseline=baseline,
        iforest_score=iforest_score,
    )
    pred = 1 if dynamic_res["dynamic_risk_score"] >= 0.75 or triggered_rules else 0
    return pred, tx["is_laundering"]


def _print_evaluation_report(eval_count: int, tp: int, fp: int, fn: int, tn: int):
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    accuracy = (tp + tn) / eval_count if eval_count > 0 else 0.0
    alert_rate = (tp + fp) / eval_count if eval_count > 0 else 0.0

    print("\n================ Classification Performance Report ================")
    print(f"Total Evaluated Transactions: {eval_count}")
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


def run_evaluation(sample_rows: int = 50000):
    if not os.path.exists(TRANS_PATH):
        print(f"Transaction file not found: {TRANS_PATH}")
        return

    print(f"Reading first {sample_rows} transactions from dataset...")
    transactions = _load_transactions(TRANS_PATH, sample_rows)
    print(f"Loaded {len(transactions)} transactions.")

    train_split = int(len(transactions) * 0.20)
    train_txs = transactions[:train_split]
    eval_txs = transactions[train_split:]

    print(f"Training custom Isolation Forest on {len(train_txs)} transactions...")
    forest = _train_isolation_forest(train_txs)
    print("Isolation Forest trained successfully.")

    tracker = _AccountHistoryTracker()
    for tx in train_txs:
        tracker.add_to_history(tx["from_acc"], tx["amount"], tx["timestamp"], is_incoming=False)
        tracker.add_to_history(tx["to_acc"], tx["amount"], tx["timestamp"], is_incoming=True)

    print(f"Evaluating remaining {len(eval_txs)} transactions...")
    tp = fp = fn = tn = 0
    for tx in eval_txs:
        pred, true = _evaluate_single_transaction(tx, tracker, forest)
        if pred == 1 and true == 1:
            tp += 1
        elif pred == 1 and true == 0:
            fp += 1
        elif pred == 0 and true == 1:
            fn += 1
        else:
            tn += 1

        tracker.add_to_history(tx["from_acc"], tx["amount"], tx["timestamp"], is_incoming=False)
        tracker.add_to_history(tx["to_acc"], tx["amount"], tx["timestamp"], is_incoming=True)

    _print_evaluation_report(len(eval_txs), tp, fp, fn, tn)


if __name__ == "__main__":
    run_evaluation(50000)
