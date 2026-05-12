"""
Tests for the ML classification inference chain.

Covers: loading a serialised Random Forest with joblib, calling predict()
and predict_proba(), and verifying the prediction/confidence contract
used by the analysis pipeline.
"""

import numpy as np
import pandas as pd
import pytest
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def tmp_csv(tmp_path_factory):
    """Write a small synthetic CICMalMem-style CSV."""
    rng  = np.random.default_rng(1)
    n    = 200
    data = rng.random((n, 55))
    cols = [f"f{i}" for i in range(55)]
    df   = pd.DataFrame(data, columns=cols)
    df["Category"] = "benign"
    df["Class"]    = ["Benign"] * (n // 2) + ["Malware"] * (n // 2)
    p = tmp_path_factory.mktemp("data_ci") / "test.csv"
    df.to_csv(p, index=False)
    return p


@pytest.fixture(scope="module")
def pipeline(tmp_csv, tmp_path_factory):
    """Run train_and_evaluate on the small CSV and return the result dict."""
    from modules.classifier import train_and_evaluate
    save_dir = tmp_path_factory.mktemp("models_ci")
    return train_and_evaluate(csv_path=tmp_csv, save_dir=save_dir)


@pytest.fixture(scope="module")
def loaded_clf(pipeline):
    """Load the saved .joblib model back from disk."""
    import joblib
    return joblib.load(pipeline["model_path"])


@pytest.fixture(scope="module")
def sample_vec():
    """A single valid 55-feature row as a (1, 55) ndarray."""
    return np.zeros((1, 55), dtype=np.float64)


# ══════════════════════════════════════════════════════════════════════════════
# Serialisation round-trip
# ══════════════════════════════════════════════════════════════════════════════

class TestModelSerialisation:
    def test_loaded_clf_is_random_forest(self, loaded_clf):
        assert isinstance(loaded_clf, RandomForestClassifier)

    def test_loaded_clf_is_fitted(self, loaded_clf, sample_vec):
        # predict() raises NotFittedError if not fitted; should not raise here
        preds = loaded_clf.predict(sample_vec)
        assert preds is not None

    def test_loaded_clf_has_same_estimator_count(self, pipeline, loaded_clf):
        assert loaded_clf.n_estimators == pipeline["model"].n_estimators


# ══════════════════════════════════════════════════════════════════════════════
# predict() — binary label output
# ══════════════════════════════════════════════════════════════════════════════

class TestPredict:
    def test_predict_returns_array(self, loaded_clf, sample_vec):
        result = loaded_clf.predict(sample_vec)
        assert hasattr(result, "__len__")

    def test_predict_single_row_length_one(self, loaded_clf, sample_vec):
        result = loaded_clf.predict(sample_vec)
        assert len(result) == 1

    def test_predict_label_is_0_or_1(self, loaded_clf, sample_vec):
        label = int(loaded_clf.predict(sample_vec)[0])
        assert label in (0, 1)

    def test_predict_maps_to_string_label(self, loaded_clf, sample_vec):
        label      = int(loaded_clf.predict(sample_vec)[0])
        prediction = "Malware" if label == 1 else "Benign"
        assert prediction in ("Benign", "Malware")

    def test_predict_batch(self, loaded_clf):
        X_batch = np.zeros((10, 55), dtype=np.float64)
        labels  = loaded_clf.predict(X_batch)
        assert len(labels) == 10
        assert all(int(l) in (0, 1) for l in labels)


# ══════════════════════════════════════════════════════════════════════════════
# predict_proba() — confidence
# ══════════════════════════════════════════════════════════════════════════════

class TestPredictProba:
    def test_returns_2d_array(self, loaded_clf, sample_vec):
        proba = loaded_clf.predict_proba(sample_vec)
        assert proba.ndim == 2

    def test_shape_is_n_by_2(self, loaded_clf, sample_vec):
        proba = loaded_clf.predict_proba(sample_vec)
        assert proba.shape == (1, 2)

    def test_probabilities_sum_to_one(self, loaded_clf, sample_vec):
        proba = loaded_clf.predict_proba(sample_vec)
        assert abs(proba[0].sum() - 1.0) < 1e-6

    def test_probabilities_in_0_1(self, loaded_clf, sample_vec):
        proba = loaded_clf.predict_proba(sample_vec)
        assert np.all(proba >= 0.0) and np.all(proba <= 1.0)

    def test_confidence_as_max_proba(self, loaded_clf, sample_vec):
        proba      = loaded_clf.predict_proba(sample_vec)[0]
        confidence = float(max(proba))
        assert 0.0 <= confidence <= 1.0

    def test_confidence_is_float(self, loaded_clf, sample_vec):
        proba      = loaded_clf.predict_proba(sample_vec)[0]
        confidence = float(max(proba))
        assert isinstance(confidence, float)

    def test_confidence_above_50_percent(self, loaded_clf, sample_vec):
        # max(proba) must always be >= 0.5 for the winning class
        proba      = loaded_clf.predict_proba(sample_vec)[0]
        confidence = float(max(proba))
        assert confidence >= 0.5


# ══════════════════════════════════════════════════════════════════════════════
# Full inference chain (mirrors _analysis_worker logic)
# ══════════════════════════════════════════════════════════════════════════════

class TestFullInferenceChain:
    def test_inference_chain_returns_prediction_and_confidence(self, loaded_clf):
        """Mirrors the exact inference code in routes/analysis.py."""
        import joblib
        from pathlib import Path

        vec   = np.zeros((1, 55), dtype=np.float64)
        label = loaded_clf.predict(vec)[0]
        proba = loaded_clf.predict_proba(vec)[0]

        prediction = "Malware" if int(label) == 1 else "Benign"
        confidence = float(max(proba))

        assert prediction in ("Benign", "Malware")
        assert 0.0 <= confidence <= 1.0

    def test_feature_importance_list_length(self, pipeline):
        fi = pipeline["feature_importance"]
        assert len(fi) == 55

    def test_feature_importance_each_entry_has_keys(self, pipeline):
        for entry in pipeline["feature_importance"]:
            assert "feature" in entry and "importance" in entry

    def test_feature_importance_importances_sum_to_one(self, pipeline):
        total = sum(e["importance"] for e in pipeline["feature_importance"])
        assert abs(total - 1.0) < 1e-4
