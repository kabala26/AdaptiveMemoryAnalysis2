"""
Tests for modules/classifier.py

Covers: data loading, splitting, training, evaluation, feature importance,
model saving, and the full train_and_evaluate pipeline.
"""

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import numpy as np
import pandas as pd
import pytest
from sklearn.ensemble import RandomForestClassifier

# ── Helpers ────────────────────────────────────────────────────────────────────

def _make_csv(path: Path, n: int = 200):
    """Write a minimal valid CICMalMem-style CSV to *path*."""
    rng = np.random.default_rng(0)
    data = rng.random((n, 55))
    cols = [f"f{i}" for i in range(55)]
    df = pd.DataFrame(data, columns=cols)
    df["Category"] = "benign"
    df["Class"] = ["Benign"] * (n // 2) + ["Malware"] * (n // 2)
    df.to_csv(path, index=False)
    return path


@pytest.fixture(scope="module")
def tmp_csv(tmp_path_factory):
    p = tmp_path_factory.mktemp("data") / "test.csv"
    _make_csv(p, 200)
    return p


@pytest.fixture(scope="module")
def loaded(tmp_csv):
    from modules.classifier import load_data
    return load_data(tmp_csv)


@pytest.fixture(scope="module")
def trained(loaded):
    from modules.classifier import split_data, train_model
    X, y, names = loaded
    X_train, X_val, X_test, y_train, y_val, y_test = split_data(X, y)
    model = train_model(X_train, y_train)
    return model, X_train, X_val, X_test, y_train, y_val, y_test, names


# ══════════════════════════════════════════════════════════════════════════════
# load_data
# ══════════════════════════════════════════════════════════════════════════════

class TestLoadData:
    def test_returns_three_values(self, loaded):
        X, y, names = loaded
        assert X is not None
        assert y is not None
        assert names is not None

    def test_feature_matrix_shape(self, loaded):
        X, y, names = loaded
        assert X.ndim == 2
        assert X.shape[0] == 200
        assert X.shape[1] == 55

    def test_label_vector_binary(self, loaded):
        _, y, _ = loaded
        assert set(y.tolist()).issubset({0, 1})

    def test_feature_names_excludes_meta_cols(self, loaded):
        _, _, names = loaded
        assert "Category" not in names
        assert "Class" not in names

    def test_feature_count_matches_names(self, loaded):
        X, _, names = loaded
        assert X.shape[1] == len(names)

    def test_dtype_float64(self, loaded):
        X, _, _ = loaded
        assert X.dtype == np.float64

    def test_file_not_found_raises(self):
        from modules.classifier import load_data
        with pytest.raises(FileNotFoundError):
            load_data("/nonexistent/path.csv")

    def test_real_dataset_loads(self):
        """Smoke-test against the actual CICMalMem-2022 CSV if available."""
        from modules.classifier import DATASET_PATH, load_data
        if not DATASET_PATH.is_file():
            pytest.skip("Real dataset not present")
        X, y, names = load_data(DATASET_PATH)
        assert X.shape[1] == 55
        assert len(names) == 55


# ══════════════════════════════════════════════════════════════════════════════
# split_data
# ══════════════════════════════════════════════════════════════════════════════

class TestSplitData:
    def test_six_arrays_returned(self, loaded):
        from modules.classifier import split_data
        X, y, _ = loaded
        result = split_data(X, y)
        assert len(result) == 6

    def test_total_size_preserved(self, loaded):
        from modules.classifier import split_data
        X, y, _ = loaded
        X_tr, X_v, X_te, y_tr, y_v, y_te = split_data(X, y)
        assert len(y_tr) + len(y_v) + len(y_te) == len(y)

    def test_train_is_70_percent(self, loaded):
        from modules.classifier import split_data
        X, y, _ = loaded
        X_tr, X_v, X_te, y_tr, y_v, y_te = split_data(X, y)
        assert abs(len(y_tr) / len(y) - 0.70) < 0.05

    def test_val_and_test_equal_size(self, loaded):
        from modules.classifier import split_data
        X, y, _ = loaded
        _, _, _, _, y_v, y_te = split_data(X, y)
        # Allow ±1 rounding difference from stratified splitting
        assert abs(len(y_v) - len(y_te)) <= 1

    def test_stratified_both_classes_in_train(self, loaded):
        from modules.classifier import split_data
        X, y, _ = loaded
        _, _, _, y_tr, _, _ = split_data(X, y)
        assert 0 in y_tr and 1 in y_tr

    def test_unequal_val_test_raises(self, loaded):
        from modules.classifier import split_data
        X, y, _ = loaded
        with pytest.raises(ValueError):
            split_data(X, y, train_ratio=0.70, val_ratio=0.20)


# ══════════════════════════════════════════════════════════════════════════════
# train_model
# ══════════════════════════════════════════════════════════════════════════════

class TestTrainModel:
    def test_returns_rf_classifier(self, trained):
        model, *_ = trained
        assert isinstance(model, RandomForestClassifier)

    def test_n_estimators_100(self, trained):
        model, *_ = trained
        assert model.n_estimators == 100

    def test_class_weight_balanced(self, trained):
        model, *_ = trained
        assert model.class_weight == "balanced"

    def test_random_state_42(self, trained):
        model, *_ = trained
        assert model.random_state == 42

    def test_model_is_fitted(self, trained):
        model, X_tr, _, _, y_tr, *_ = trained
        # predict() would raise NotFittedError if not fitted
        preds = model.predict(X_tr)
        assert len(preds) == len(y_tr)

    def test_feature_importances_sum_to_one(self, trained):
        model, *_ = trained
        assert abs(model.feature_importances_.sum() - 1.0) < 1e-6


# ══════════════════════════════════════════════════════════════════════════════
# evaluate
# ══════════════════════════════════════════════════════════════════════════════

class TestEvaluate:
    def test_returns_dict(self, trained):
        from modules.classifier import evaluate
        model, _, X_v, _, _, y_v, *_ = trained
        result = evaluate(model, X_v, y_v, "validation")
        assert isinstance(result, dict)

    def test_required_keys(self, trained):
        from modules.classifier import evaluate
        model, _, X_v, _, _, y_v, *_ = trained
        result = evaluate(model, X_v, y_v, "validation")
        for key in ("accuracy", "precision_macro", "recall_macro", "f1_macro",
                    "confusion_matrix", "classification_report", "n_samples"):
            assert key in result, f"Missing key: {key}"

    def test_accuracy_in_range(self, trained):
        from modules.classifier import evaluate
        model, _, X_v, _, _, y_v, *_ = trained
        result = evaluate(model, X_v, y_v, "validation")
        assert 0.0 <= result["accuracy"] <= 1.0

    def test_confusion_matrix_shape(self, trained):
        from modules.classifier import evaluate
        model, _, X_v, _, _, y_v, *_ = trained
        result = evaluate(model, X_v, y_v, "validation")
        cm = result["confusion_matrix"]
        assert len(cm) == 2 and len(cm[0]) == 2

    def test_n_samples_matches(self, trained):
        from modules.classifier import evaluate
        model, _, X_v, _, _, y_v, *_ = trained
        result = evaluate(model, X_v, y_v, "validation")
        assert result["n_samples"] == len(y_v)


# ══════════════════════════════════════════════════════════════════════════════
# get_feature_importance
# ══════════════════════════════════════════════════════════════════════════════

class TestFeatureImportance:
    def test_returns_list(self, trained):
        from modules.classifier import get_feature_importance
        model, _, _, _, _, _, _, names = trained
        result = get_feature_importance(model, names)
        assert isinstance(result, list)

    def test_sorted_descending(self, trained):
        from modules.classifier import get_feature_importance
        model, _, _, _, _, _, _, names = trained
        result = get_feature_importance(model, names)
        scores = [r["importance"] for r in result]
        assert scores == sorted(scores, reverse=True)

    def test_all_features_present(self, trained):
        from modules.classifier import get_feature_importance
        model, _, _, _, _, _, _, names = trained
        result = get_feature_importance(model, names)
        assert len(result) == len(names)

    def test_each_entry_has_keys(self, trained):
        from modules.classifier import get_feature_importance
        model, _, _, _, _, _, _, names = trained
        result = get_feature_importance(model, names)
        for entry in result:
            assert "feature" in entry and "importance" in entry

    def test_top_n_param(self, trained):
        from modules.classifier import get_feature_importance
        model, _, _, _, _, _, _, names = trained
        result = get_feature_importance(model, names, top_n=5)
        assert len(result) == len(names)   # list has all; top_n only affects print


# ══════════════════════════════════════════════════════════════════════════════
# save_model
# ══════════════════════════════════════════════════════════════════════════════

class TestSaveModel:
    def test_creates_joblib_file(self, trained, tmp_path):
        from modules.classifier import evaluate, get_feature_importance, save_model
        model, _, X_v, X_te, _, y_v, y_te, names = trained
        val_m  = evaluate(model, X_v,  y_v,  "val")
        test_m = evaluate(model, X_te, y_te, "test")
        fi     = get_feature_importance(model, names)
        model_path, meta_path = save_model(model, names, val_m, test_m, fi, tmp_path)
        assert model_path.is_file()
        assert model_path.suffix == ".joblib"

    def test_creates_json_metadata(self, trained, tmp_path):
        from modules.classifier import evaluate, get_feature_importance, save_model
        model, _, X_v, X_te, _, y_v, y_te, names = trained
        val_m  = evaluate(model, X_v,  y_v,  "val")
        test_m = evaluate(model, X_te, y_te, "test")
        fi     = get_feature_importance(model, names)
        _, meta_path = save_model(model, names, val_m, test_m, fi, tmp_path)
        assert meta_path.is_file()
        meta = json.loads(meta_path.read_text())
        assert meta["model_type"] == "RandomForestClassifier"
        assert "validation_metrics" in meta
        assert "test_metrics" in meta

    def test_saved_model_loadable(self, trained, tmp_path):
        import joblib
        from modules.classifier import evaluate, get_feature_importance, save_model
        model, _, X_v, X_te, _, y_v, y_te, names = trained
        val_m  = evaluate(model, X_v,  y_v,  "val")
        test_m = evaluate(model, X_te, y_te, "test")
        fi     = get_feature_importance(model, names)
        model_path, _ = save_model(model, names, val_m, test_m, fi, tmp_path)
        loaded_model = joblib.load(model_path)
        assert isinstance(loaded_model, RandomForestClassifier)


# ══════════════════════════════════════════════════════════════════════════════
# train_and_evaluate (full pipeline)
# ══════════════════════════════════════════════════════════════════════════════

class TestTrainAndEvaluate:
    def test_returns_expected_keys(self, tmp_csv, tmp_path):
        from modules.classifier import train_and_evaluate
        result = train_and_evaluate(csv_path=tmp_csv, save_dir=tmp_path)
        for key in ("model", "model_path", "metadata_path",
                    "val_metrics", "test_metrics", "feature_importance"):
            assert key in result, f"Missing key: {key}"

    def test_model_is_rf(self, tmp_csv, tmp_path):
        from modules.classifier import train_and_evaluate
        result = train_and_evaluate(csv_path=tmp_csv, save_dir=tmp_path)
        assert isinstance(result["model"], RandomForestClassifier)

    def test_model_path_exists(self, tmp_csv, tmp_path):
        from modules.classifier import train_and_evaluate
        result = train_and_evaluate(csv_path=tmp_csv, save_dir=tmp_path)
        assert Path(result["model_path"]).is_file()

    def test_metadata_path_exists(self, tmp_csv, tmp_path):
        from modules.classifier import train_and_evaluate
        result = train_and_evaluate(csv_path=tmp_csv, save_dir=tmp_path)
        assert Path(result["metadata_path"]).is_file()

    def test_val_accuracy_sensible(self, tmp_csv, tmp_path):
        from modules.classifier import train_and_evaluate
        result = train_and_evaluate(csv_path=tmp_csv, save_dir=tmp_path)
        assert 0.0 <= result["val_metrics"]["accuracy"] <= 1.0

    def test_feature_importance_nonempty(self, tmp_csv, tmp_path):
        from modules.classifier import train_and_evaluate
        result = train_and_evaluate(csv_path=tmp_csv, save_dir=tmp_path)
        assert len(result["feature_importance"]) > 0
