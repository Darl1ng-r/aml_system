import asyncio
import hashlib
import logging
import math
from concurrent.futures import ProcessPoolExecutor

import numpy as np

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

    def fit(self, X: np.ndarray, current_depth: int = 0, rng: np.random.Generator | None = None) -> Node:
        n_samples, n_features = X.shape

        # Base case: max depth reached, subset too small, or all values identical
        if current_depth >= self.max_depth or n_samples <= 1:
            return Node(size=n_samples)

        if np.all(X == X[0]):
            return Node(size=n_samples)

        local_rng = rng if rng is not None else np.random.default_rng(42)

        # Deterministically shuffle feature order using the seeded Generator (SR 11-7 reproducibility)
        feature_indices = list(range(n_features))
        local_rng.shuffle(feature_indices)

        split_feature = None
        split_value = None

        for feat in feature_indices:
            feat_min = float(X[:, feat].min())
            feat_max = float(X[:, feat].max())
            if feat_min < feat_max:
                split_feature = feat
                split_value = float(local_rng.uniform(feat_min, feat_max))
                break

        if split_feature is None:
            return Node(size=n_samples)

        # Partition data below and above the split value
        left_mask = X[:, split_feature] < split_value
        if not np.any(left_mask) or np.all(left_mask):
            # Guard against uniform() sampling the inclusive feat_min endpoint
            return Node(size=n_samples)
        x_left = X[left_mask]
        x_right = X[~left_mask]

        left_node = self.fit(x_left, current_depth + 1, rng=local_rng)
        right_node = self.fit(x_right, current_depth + 1, rng=local_rng)

        return Node(
            left=left_node,
            right=right_node,
            split_feature=split_feature,
            split_value=split_value,
            size=n_samples,
        )

    def path_length(self, x: np.ndarray, node: Node, current_depth: int) -> float:
        """Traverse the tree to find path length of instance x."""
        if node.left is None and node.right is None:
            return current_depth + c_factor(node.size)

        feature = node.split_feature
        if x[feature] < node.split_value:
            return self.path_length(x, node.left, current_depth + 1)
        return self.path_length(x, node.right, current_depth + 1)


class IsolationForestScratch:
    def __init__(self, n_estimators: int = 100, max_samples: int = 256, seed: int = 42):
        self.n_estimators = n_estimators
        self.max_samples = max_samples
        self.seed = seed
        self.actual_subsample_size = max_samples
        self.trees = []
        self.fitted = False
        self.model_version = f"iforest-unfitted-s{seed}"

    def fit(self, X: np.ndarray):
        X = np.nan_to_num(np.asarray(X, dtype=float), nan=0.0, posinf=1e12, neginf=0.0)
        n_samples = X.shape[0]
        if n_samples == 0:
            logger.warning("Attempted to fit empty dataset in Isolation Forest.")
            self.fitted = True
            self.model_version = f"iforest-empty-s{self.seed}"
            return self

        subsample_size = min(self.max_samples, n_samples)
        self.actual_subsample_size = subsample_size
        max_depth = int(math.ceil(math.log2(max(subsample_size, 2))))

        rng = np.random.default_rng(self.seed)
        self.trees = []
        for _ in range(self.n_estimators):
            indices = rng.choice(n_samples, size=subsample_size, replace=False)
            x_sub = X[indices]

            tree = IsolationTree(max_depth=max_depth)
            tree.root = tree.fit(x_sub, rng=rng)
            self.trees.append(tree)

        digest = hashlib.sha256(
            f"{self.n_estimators}:{subsample_size}:{self.seed}:{X.shape}".encode("utf-8")
            + np.ascontiguousarray(X, dtype=np.float64).tobytes()[:4096]
        ).hexdigest()[:12]
        self.model_version = f"iforest-v2-{digest}"
        self.fitted = True
        return self

    def compute_anomaly_score(self, x: np.ndarray) -> float:
        """
        Computes anomaly score: s(x, n) = 2 ** (- E(h(x)) / c(n)).
        Score > 0.6 is generally considered an anomaly.
        """
        if not self.fitted or not self.trees:
            return 0.5

        subsample_size = getattr(self, "actual_subsample_size", min(self.max_samples, 256))
        c_denom = c_factor(subsample_size)
        if abs(c_denom) < 1e-9:
            return 0.5

        x_safe = np.nan_to_num(np.asarray(x, dtype=float), nan=0.0, posinf=1e12, neginf=0.0)
        paths = [tree.path_length(x_safe, tree.root, 0) for tree in self.trees]
        avg_path = np.mean(paths)

        score = 2.0 ** (-avg_path / c_denom)
        return float(score)


# System-wide Singleton model & single-flight retrain lock (loop-aware)
_iforest_model: IsolationForestScratch | None = None
_retrain_lock: asyncio.Lock | None = None
_retrain_lock_loop = None


def _get_retrain_lock() -> asyncio.Lock:
    global _retrain_lock, _retrain_lock_loop
    current_loop = asyncio.get_running_loop()
    if _retrain_lock is None or _retrain_lock_loop is not current_loop:
        _retrain_lock = asyncio.Lock()
        _retrain_lock_loop = current_loop
    return _retrain_lock


def get_iforest_version() -> str:
    if _iforest_model is not None:
        return getattr(_iforest_model, "model_version", "iforest-v2")
    return "iforest-uninitialized"


def _fit_isolation_forest_job(n_estimators: int, max_samples: int, X_train: np.ndarray) -> IsolationForestScratch:
    """Standalone worker function for process-isolated deterministic model fitting."""
    model = IsolationForestScratch(n_estimators=n_estimators, max_samples=max_samples, seed=42)
    model.fit(X_train)
    return model


def _generate_synthetic_training_data() -> np.ndarray:
    rng = np.random.default_rng(42)
    n_samples = 100
    amounts = rng.exponential(scale=3000, size=n_samples)
    sender_risks = rng.beta(a=2, b=5, size=n_samples)
    receiver_risks = rng.beta(a=2, b=5, size=n_samples)
    hours = rng.integers(0, 24, size=n_samples)
    is_geo_risks = rng.choice([0, 1], size=n_samples, p=[0.95, 0.05])
    return np.stack([amounts, sender_risks, receiver_risks, hours, is_geo_risks], axis=1)


def _extract_training_features(rows: list, high_risk_countries: list) -> np.ndarray:
    features = []
    for row in rows:
        raw_base = row["amount_base_usd"] if "amount_base_usd" in row else row["amount"]
        amount = float(raw_base if raw_base is not None else row["amount"])
        sender_risk = float(row["sender_risk"]) if row["sender_risk"] is not None else 0.1
        receiver_risk = float(row["receiver_risk"]) if row["receiver_risk"] is not None else 0.1
        hour = row["timestamp"].hour

        is_geo = 0
        for bic in [row["sender_bic"], row["receiver_bic"]]:
            if bic and len(bic) >= 6 and bic[4:6].upper() in high_risk_countries:
                is_geo = 1
                break

        features.append([amount, sender_risk, receiver_risk, hour, is_geo])
    return np.array(features)


async def _fit_model_in_executor(X_train: np.ndarray) -> IsolationForestScratch:
    from services.compute_executor import run_analytics_compute

    loop = asyncio.get_running_loop()
    try:
        with ProcessPoolExecutor(max_workers=1) as pool:
            return await loop.run_in_executor(pool, _fit_isolation_forest_job, 50, 256, X_train)
    except Exception:
        return await run_analytics_compute(_fit_isolation_forest_job, 50, 256, X_train, timeout=15.0)


async def retrain_system_iforest(tenant_id: str | None = None):
    """Single-flight protected Isolation Forest retrain over USD-normalized transaction amounts."""
    global _iforest_model
    async with _get_retrain_lock():
        logger.info("Retraining system-wide Isolation Forest...")
        try:
            from database.postgres import get_async_db_read_conn
            from services.rules import get_rules_config

            config = get_rules_config()
            geo_config = config.get("rules", {}).get("GEOGRAPHIC_SANCTIONS", {})
            high_risk_countries = geo_config.get("high_risk_countries", ["RU", "IR", "KP", "SY"])

            query = """
                SELECT COALESCE(t.amount_base_usd, t.amount) AS amount_base_usd,
                       t.amount,
                       s.risk_score as sender_risk,
                       r.risk_score as receiver_risk,
                       t.timestamp,
                       s.swift_bic as sender_bic,
                       r.swift_bic as receiver_bic
                FROM transactions t
                LEFT JOIN accounts s ON t.sender_account_id = s.id
                LEFT JOIN accounts r ON t.receiver_account_id = r.id
                WHERE t.status = 'COMPLETED'
                ORDER BY t.timestamp DESC
                LIMIT 2000;
            """
            rows = []
            try:
                async with get_async_db_read_conn(tenant_id=tenant_id) as conn:
                    rows = await conn.fetch(query)
            except Exception as db_exc:
                logger.debug("Isolation Forest DB sample fetch skipped (%s); using synthetic seed.", db_exc)

            if len(rows) < 10:
                logger.info("Not enough transactions in DB to train Isolation Forest. Seeding synthetic data for training.")
                X_train = _generate_synthetic_training_data()
            else:
                X_train = _extract_training_features(rows, high_risk_countries)

            _iforest_model = await _fit_model_in_executor(X_train)
            logger.info(
                "System-wide Isolation Forest trained (%s) on %d samples.",
                _iforest_model.model_version,
                X_train.shape[0],
            )
        except Exception:
            logger.exception("Failed to retrain Isolation Forest")


async def get_iforest_score(
    amount: float,
    sender_risk: float,
    receiver_risk: float,
    hour: int,
    is_geo: int,
) -> float:
    """Offloads Isolation Forest tree traversal onto the bounded ML compute bulkhead."""
    global _iforest_model
    if _iforest_model is None:
        await retrain_system_iforest()

    model = _iforest_model
    if model is None:
        return 0.5

    from services.compute_executor import run_ml_compute
    from observability.prometheus import record_ml_inference_duration
    import time as _time

    t0 = _time.monotonic()
    x = np.array([float(amount), float(sender_risk), float(receiver_risk), int(hour), int(is_geo)])
    try:
        score = await run_ml_compute(model.compute_anomaly_score, x, timeout=1.5)
        record_ml_inference_duration("isolation_forest", "ok", _time.monotonic() - t0)
        return float(score)
    except asyncio.TimeoutError:
        record_ml_inference_duration("isolation_forest", "timeout", _time.monotonic() - t0)
        logger.warning("Isolation Forest inference timed out (1.5s); returning neutral 0.5 fallback.")
        return 0.5
    except Exception:
        record_ml_inference_duration("isolation_forest", "error", _time.monotonic() - t0)
        logger.exception("Isolation Forest inference failed; returning neutral 0.5 fallback.")
        return 0.5
