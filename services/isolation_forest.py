import numpy as np
import random
import math
import logging

logger = logging.getLogger(__name__)

class Node:
    def __init__(self, left=None, right=None, split_feature=None, split_value=None, size=0):
        self.left = left
        self.right = right
        self.split_feature = split_feature
        self.split_value = split_value
        self.size = size

def c_factor(n: int) -> float:
    """
    BST average path length calculation for unsuccessful searches.
    c(n) = 2 * (ln(n - 1) + Euler's constant) - 2 * (n - 1) / n
    """
    if n <= 1:
        return 0.0
    if n == 2:
        return 1.0
    euler_constant = 0.5772156649
    return 2.0 * (math.log(n - 1) + euler_constant) - (2.0 * (n - 1) / n)

class IsolationTree:
    def __init__(self, max_depth: int):
        self.max_depth = max_depth
        self.root = None

    def fit(self, X: np.ndarray, current_depth: int = 0) -> Node:
        n_samples, n_features = X.shape
        
        # Base case: max depth reached, subset too small, or all values identical
        if current_depth >= self.max_depth or n_samples <= 1:
            return Node(size=n_samples)
            
        if np.all(X == X[0]):
            return Node(size=n_samples)
            
        # Randomly select a feature that is not constant
        feature_indices = list(range(n_features))
        random.shuffle(feature_indices)
        
        split_feature = None
        split_value = None
        
        for feat in feature_indices:
            feat_min = X[:, feat].min()
            feat_max = X[:, feat].max()
            if feat_min < feat_max:
                split_feature = feat
                split_value = random.uniform(feat_min, feat_max)
                break
                
        if split_feature is None:
            return Node(size=n_samples)
            
        # Partition data below and above the split value
        left_mask = X[:, split_feature] < split_value
        X_left = X[left_mask]
        X_right = X[~left_mask]
        
        left_node = self.fit(X_left, current_depth + 1)
        right_node = self.fit(X_right, current_depth + 1)
        
        return Node(
            left=left_node,
            right=right_node,
            split_feature=split_feature,
            split_value=split_value,
            size=n_samples
        )

    def path_length(self, x: np.ndarray, node: Node, current_depth: int) -> float:
        """Traverse the tree to find path length of instance x."""
        if node.left is None and node.right is None:
            return current_depth + c_factor(node.size)
            
        feature = node.split_feature
        if x[feature] < node.split_value:
            return self.path_length(x, node.left, current_depth + 1)
        else:
            return self.path_length(x, node.right, current_depth + 1)

class IsolationForestScratch:
    def __init__(self, n_estimators: int = 100, max_samples: int = 256):
        self.n_estimators = n_estimators
        self.max_samples = max_samples
        self.trees = []
        self.fitted = False

    def fit(self, X: np.ndarray):
        n_samples = X.shape[0]
        if n_samples == 0:
            logger.warning("Attempted to fit empty dataset in Isolation Forest.")
            self.fitted = True
            return self
            
        subsample_size = min(self.max_samples, n_samples)
        max_depth = int(math.ceil(math.log2(max(subsample_size, 2))))
        
        self.trees = []
        for _ in range(self.n_estimators):
            # Select random subsample of indices without replacement
            indices = np.random.choice(n_samples, size=subsample_size, replace=False)
            X_sub = X[indices]
            
            tree = IsolationTree(max_depth=max_depth)
            tree.root = tree.fit(X_sub)
            self.trees.append(tree)
            
        self.fitted = True
        return self

    def compute_anomaly_score(self, x: np.ndarray) -> float:
        """
        Computes anomaly score: s(x, n) = 2 ** (- E(h(x)) / c(n)).
        Score > 0.6 is generally considered an anomaly.
        """
        if not self.fitted or not self.trees:
            return 0.5
            
        subsample_size = min(self.max_samples, 256)
        c_denom = c_factor(subsample_size)
        if c_denom == 0.0:
            return 0.5
            
        paths = [tree.path_length(x, tree.root, 0) for tree in self.trees]
        avg_path = np.mean(paths)
        
        score = 2.0 ** (- avg_path / c_denom)
        return float(score)

# System-wide Singleton model
_iforest_model = None

def _fit_isolation_forest_job(n_estimators: int, max_samples: int, X_train: np.ndarray) -> IsolationForestScratch:
    """Standalone worker function for process-isolated model fitting (unblocking the GIL)."""
    model = IsolationForestScratch(n_estimators=n_estimators, max_samples=max_samples)
    model.fit(X_train)
    return model


async def retrain_system_iforest():
    global _iforest_model
    logger.info("Retraining system-wide Isolation Forest...")
    try:
        from database.postgres import get_async_db_conn
        from services.rules import get_rules_config
        import asyncio
        from concurrent.futures import ProcessPoolExecutor
        
        config = get_rules_config()
        geo_config = config.get("rules", {}).get("GEOGRAPHIC_SANCTIONS", {})
        high_risk_countries = geo_config.get("high_risk_countries", ["RU", "IR", "KP", "SY"])
        
        # Load the last 2000 completed transactions to train
        query = """
            SELECT t.amount, s.risk_score as sender_risk, r.risk_score as receiver_risk, t.timestamp,
                   s.swift_bic as sender_bic, r.swift_bic as receiver_bic
            FROM transactions t
            LEFT JOIN accounts s ON t.sender_account_id = s.id
            LEFT JOIN accounts r ON t.receiver_account_id = r.id
            WHERE t.status = 'COMPLETED'
            ORDER BY t.timestamp DESC
            LIMIT 2000;
        """
        async with get_async_db_conn() as conn:
            rows = await conn.fetch(query)
            
        # If there are not enough transactions, seed synthetic samples
        if len(rows) < 10:
            logger.info("Not enough transactions in DB to train Isolation Forest. Seeding synthetic data for training.")
            np.random.seed(42)
            n_samples = 100
            amounts = np.random.exponential(scale=3000, size=n_samples)
            sender_risks = np.random.beta(a=2, b=5, size=n_samples)
            receiver_risks = np.random.beta(a=2, b=5, size=n_samples)
            hours = np.random.randint(0, 24, size=n_samples)
            is_geo_risks = np.random.choice([0, 1], size=n_samples, p=[0.95, 0.05])
            
            X_train = np.stack([amounts, sender_risks, receiver_risks, hours, is_geo_risks], axis=1)
        else:
            features = []
            for row in rows:
                amount = float(row["amount"])
                sender_risk = float(row["sender_risk"]) if row["sender_risk"] is not None else 0.1
                receiver_risk = float(row["receiver_risk"]) if row["receiver_risk"] is not None else 0.1
                hour = row["timestamp"].hour
                
                is_geo = 0
                for bic in [row["sender_bic"], row["receiver_bic"]]:
                    if bic and len(bic) >= 6:
                        if bic[4:6].upper() in high_risk_countries:
                            is_geo = 1
                            break
                            
                features.append([amount, sender_risk, receiver_risk, hour, is_geo])
                
            X_train = np.array(features)
            
        loop = asyncio.get_running_loop()
        try:
            with ProcessPoolExecutor(max_workers=1) as pool:
                model = await loop.run_in_executor(pool, _fit_isolation_forest_job, 50, 256, X_train)
        except Exception:
            model = await asyncio.to_thread(_fit_isolation_forest_job, 50, 256, X_train)

        _iforest_model = model
        logger.info(f"System-wide Isolation Forest trained successfully on {X_train.shape[0]} samples.")
    except Exception as e:
        logger.error(f"Failed to retrain Isolation Forest: {e}")

async def get_iforest_score(amount: float, sender_risk: float, receiver_risk: float, hour: int, is_geo: int) -> float:
    global _iforest_model
    if _iforest_model is None:
        await retrain_system_iforest()
        
    if _iforest_model is not None:
        x = np.array([amount, sender_risk, receiver_risk, hour, is_geo])
        return _iforest_model.compute_anomaly_score(x)
    return 0.5
