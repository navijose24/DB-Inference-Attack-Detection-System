import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import pickle
import os

SENSITIVE_COLUMNS = {'salary', 'ssn', 'designation', 'phone', 'address', 'dob'}


class MLDetector:
    def __init__(self, contamination=0.1):
        self.model = IsolationForest(
            contamination=contamination,
            n_estimators=100,
            random_state=42,
        )
        self.scaler = StandardScaler()
        self.is_trained = False
        self.model_path = os.path.join(os.path.dirname(__file__), 'model.pkl')
        self._load_model()

    # ------------------------------------------------------------------
    # Feature extraction
    # ------------------------------------------------------------------

    def extract_features(self, query_text, parsed_info, user_history=None):
        """
        Extract numerical feature vector from a query.

        Returns numpy array of 12 features:
            query_length, num_conditions, num_sensitive_columns, has_aggregate,
            has_group_by, has_having, num_tables, condition_specificity,
            limit_value, query_frequency, unique_tables_accessed,
            sensitive_access_ratio
        """
        p = parsed_info or {}
        columns = [c.lower() for c in p.get('columns', [])]
        conditions = p.get('where_conditions', [])
        tables = p.get('tables', [])

        query_length = len(query_text)
        num_conditions = len(conditions)
        num_sensitive = sum(1 for c in columns if c in SENSITIVE_COLUMNS)
        has_aggregate = int(p.get('has_aggregate', False))
        has_group_by = int(p.get('has_group_by', False))
        has_having = int(p.get('has_having', False))
        num_tables = max(len(tables), 1)

        eq_count = sum(1 for cond in conditions if cond.get('operator') == '=')
        condition_specificity = eq_count / max(num_conditions, 1)

        limit_value = p.get('limit_value') or 0

        # User-history-derived features
        query_frequency = 0
        unique_tables_accessed = 1
        sensitive_access_ratio = 0.0
        if user_history:
            query_frequency = len(user_history)
            hist_tables = set()
            sens_count = 0
            for _, _, hist_p in user_history:
                hist_tables.update(hist_p.get('tables', []))
                if any(c.lower() in SENSITIVE_COLUMNS for c in hist_p.get('columns', [])):
                    sens_count += 1
            unique_tables_accessed = max(len(hist_tables), 1)
            sensitive_access_ratio = sens_count / max(len(user_history), 1)

        return np.array([
            query_length, num_conditions, num_sensitive, has_aggregate,
            has_group_by, has_having, num_tables, condition_specificity,
            limit_value, query_frequency, unique_tables_accessed,
            sensitive_access_ratio,
        ], dtype=np.float64)

    # ------------------------------------------------------------------
    # Training
    # ------------------------------------------------------------------

    def train(self, feature_matrix):
        """Train/retrain on a matrix of historical query features."""
        feature_matrix = np.asarray(feature_matrix, dtype=np.float64)
        self.scaler.fit(feature_matrix)
        scaled = self.scaler.transform(feature_matrix)
        self.model.fit(scaled)
        self.is_trained = True
        self._save_model()

    # ------------------------------------------------------------------
    # Prediction
    # ------------------------------------------------------------------

    def predict_anomaly_score(self, features):
        """
        Returns anomaly score 0-1 (1 = most anomalous).
        If not trained, returns 0.5 (neutral).
        """
        if not self.is_trained:
            return 0.5

        features = np.asarray(features, dtype=np.float64).reshape(1, -1)
        scaled = self.scaler.transform(features)
        # decision_function: more negative = more anomalous
        raw = self.model.decision_function(scaled)[0]
        # Typical range roughly [-0.5, 0.5]; map to [0, 1] inverted
        score = max(0.0, min(1.0, 0.5 - raw))
        return score

    def score(self, query_text, parsed_info=None, user_history=None):
        """Convenience method to extract features and return anomaly score in [0, 1]."""
        if not self.is_trained:
            X, _ = self.generate_training_data(n_normal=200, n_attack=40)
            self.train(X)
        if parsed_info is None:
            from detection.analyzer import QueryAnalyzer
            analyzer = QueryAnalyzer()
            parsed_info = analyzer._parse_query(query_text)
        features = self.extract_features(query_text, parsed_info, user_history)
        return float(self.predict_anomaly_score(features))

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _save_model(self):
        """Pickle model + scaler."""
        with open(self.model_path, 'wb') as f:
            pickle.dump({'model': self.model, 'scaler': self.scaler}, f)

    def _load_model(self):
        """Load if exists."""
        if os.path.exists(self.model_path):
            try:
                with open(self.model_path, 'rb') as f:
                    data = pickle.load(f)
                self.model = data['model']
                self.scaler = data['scaler']
                self.is_trained = True
            except Exception:
                self.is_trained = False

    # ------------------------------------------------------------------
    # Synthetic data generation
    # ------------------------------------------------------------------

    def generate_training_data(self, n_normal=500, n_attack=50):
        """
        Generate synthetic training data.

        Normal queries: moderate length, few conditions, rarely access
        sensitive cols, varied tables.
        Attack queries: shorter with many conditions on sensitive cols,
        aggregates, narrow filters.

        Returns (feature_matrix, labels) — labels for reference only;
        IsolationForest is unsupervised.
        """
        rng = np.random.RandomState(42)

        # Normal patterns
        normal = np.column_stack([
            rng.randint(20, 200, n_normal),           # query_length
            rng.randint(0, 3, n_normal),              # num_conditions
            rng.choice([0, 0, 0, 0, 1], n_normal),    # num_sensitive_columns
            rng.choice([0, 1], n_normal, p=[0.6, 0.4]),  # has_aggregate
            rng.choice([0, 1], n_normal, p=[0.7, 0.3]),  # has_group_by
            rng.choice([0, 1], n_normal, p=[0.9, 0.1]),  # has_having
            rng.randint(1, 4, n_normal),              # num_tables
            rng.uniform(0.0, 0.5, n_normal),          # condition_specificity
            rng.choice([0, 0, 0, 10, 50, 100], n_normal),  # limit_value
            rng.randint(1, 10, n_normal),             # query_frequency
            rng.randint(1, 6, n_normal),              # unique_tables_accessed
            rng.uniform(0.0, 0.3, n_normal),          # sensitive_access_ratio
        ]).astype(np.float64)

        # Attack patterns
        attack = np.column_stack([
            rng.randint(30, 120, n_attack),            # query_length (shorter, targeted)
            rng.randint(3, 8, n_attack),               # num_conditions (many)
            rng.randint(1, 4, n_attack),               # num_sensitive_columns (high)
            np.ones(n_attack),                         # has_aggregate (always)
            rng.choice([0, 1], n_attack, p=[0.3, 0.7]),  # has_group_by
            rng.choice([0, 1], n_attack, p=[0.5, 0.5]),  # has_having
            rng.randint(1, 2, n_attack),               # num_tables (single)
            rng.uniform(0.7, 1.0, n_attack),           # condition_specificity (high)
            rng.choice([0, 1, 2], n_attack),           # limit_value (small or none)
            rng.randint(10, 30, n_attack),             # query_frequency (high)
            rng.randint(1, 3, n_attack),               # unique_tables_accessed (few)
            rng.uniform(0.6, 1.0, n_attack),           # sensitive_access_ratio (high)
        ]).astype(np.float64)

        feature_matrix = np.vstack([normal, attack])
        labels = np.array([0] * n_normal + [1] * n_attack)
        return feature_matrix, labels
