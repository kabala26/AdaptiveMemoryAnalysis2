"""
Tests for modules/model_trainer.py — adaptive retraining workflow.

All expensive training calls are mocked out so the tests run fast.
What's verified: DB-level behaviour (MlModel rows, LabeledSample consumption,
AuditLog entries) and the accuracy-comparison activation gate.
"""

import os
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import numpy as np
import pytest

# ── Synthetic dataset shared across tests ─────────────────────────────────────

_N      = 100
_RNG    = np.random.default_rng(0)
_FAKE_X = _RNG.random((_N, 55))
_FAKE_Y = np.array([0] * (_N // 2) + [1] * (_N // 2))
_FAKE_NAMES = [f"f{i}" for i in range(55)]
_FAKE_FI    = [{"feature": f"f{i}", "importance": round(1 / 55, 8)} for i in range(55)]

_SPLIT = (
    _FAKE_X[:70], _FAKE_X[70:85], _FAKE_X[85:],
    _FAKE_Y[:70], _FAKE_Y[70:85], _FAKE_Y[85:],
)


def _fake_metrics(accuracy: float = 0.95) -> dict:
    return {
        "accuracy": accuracy, "precision_macro": accuracy,
        "recall_macro": accuracy, "f1_macro": accuracy,
        "n_samples": 15, "confusion_matrix": [[8, 0], [0, 7]],
        "classification_report": "",
    }


@contextmanager
def _mock_train(accuracy: float = 0.95,
                model_path: Path = Path("/tmp/rf_fake.joblib")):
    """Context manager that stubs out all slow classifier calls."""
    clf = MagicMock()
    clf.feature_importances_ = np.ones(55) / 55

    metrics = _fake_metrics(accuracy)

    with patch("modules.classifier.load_data",
               return_value=(_FAKE_X, _FAKE_Y, _FAKE_NAMES)), \
         patch("modules.classifier.split_data", return_value=_SPLIT), \
         patch("modules.classifier.train_model", return_value=clf), \
         patch("modules.classifier.evaluate", return_value=metrics), \
         patch("modules.classifier.get_feature_importance",
               return_value=_FAKE_FI), \
         patch("modules.classifier.save_model",
               return_value=(model_path, Path("/tmp/rf_fake_meta.json"))):
        yield clf


# ── App fixture ───────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def app(tmp_path_factory):
    upload_dir = tmp_path_factory.mktemp("uploads_mt")

    os.environ.setdefault("SECRET_KEY",           "test-secret-mt")
    os.environ.setdefault("DATABASE_URL",          "sqlite:///:memory:")
    os.environ.setdefault("JWT_SECRET_KEY",        "test-jwt-secret-key-at-least-32-chars!!")
    os.environ.setdefault("JWT_ACCESS_EXPIRES_SECONDS",  "900")
    os.environ.setdefault("JWT_REFRESH_EXPIRES_SECONDS", "604800")
    os.environ.setdefault("GOOGLE_CLIENT_ID",      "g-id")
    os.environ.setdefault("GOOGLE_CLIENT_SECRET",  "g-secret")
    os.environ.setdefault("GITHUB_CLIENT_ID",      "gh-id")
    os.environ.setdefault("GITHUB_CLIENT_SECRET",  "gh-secret")
    os.environ.setdefault("FRONTEND_URL",          "http://localhost:3000")
    os.environ.setdefault("BACKEND_URL",           "http://localhost:5000")
    os.environ["UPLOAD_FOLDER"] = str(upload_dir)

    from backend import create_app
    application = create_app()
    application.config["TESTING"] = True

    with application.app_context():
        from backend import db
        db.create_all()

    yield application


# ── Helpers ───────────────────────────────────────────────────────────────────

def _seed_existing_model(app, accuracy: float) -> str:
    """Insert an already-activated MlModel (simulates a production model)."""
    from backend import db
    from backend.models.analysis import MlModel
    model_id = str(uuid.uuid4())
    with app.app_context():
        m = MlModel(
            model_id     = model_id,
            model_name   = "Existing-RF",
            algorithm    = "RandomForestClassifier",
            accuracy     = accuracy,
            model_path   = "/tmp/existing.joblib",
            activated_at = datetime.now(timezone.utc),
        )
        db.session.add(m)
        db.session.commit()
    return model_id


def _seed_labeled_samples(app, n: int, label: str = "Benign") -> list[str]:
    """Insert *n* pending LabeledSample rows and return their IDs."""
    from backend import db
    from backend.models.analysis import LabeledSample
    ids = []
    with app.app_context():
        for _ in range(n):
            s = LabeledSample(
                feature_vector = [0.0] * 55,
                true_label     = label,
                source         = "manual",
            )
            db.session.add(s)
            db.session.flush()
            ids.append(s.sample_id)
        db.session.commit()
    return ids


# ══════════════════════════════════════════════════════════════════════════════
# Core workflow tests
# ══════════════════════════════════════════════════════════════════════════════

class TestAdaptiveRetrain:

    def _run(self, app, accuracy=0.95):
        from modules.model_trainer import retrain_in_context
        with app.app_context():
            with _mock_train(accuracy):
                return retrain_in_context()

    # ── Return value schema ───────────────────────────────────────────────────

    def test_returns_expected_keys(self, app):
        result = self._run(app)
        for key in ("model_id", "accuracy", "prev_accuracy",
                    "activated", "new_samples", "outcome"):
            assert key in result, f"Missing key: {key}"

    def test_accuracy_matches_mock(self, app):
        result = self._run(app, accuracy=0.88)
        assert abs(result["accuracy"] - 0.88) < 1e-6

    # ── DB: MlModel row ───────────────────────────────────────────────────────

    def test_creates_ml_model_row(self, app):
        result = self._run(app)
        from backend import db
        from backend.models.analysis import MlModel
        with app.app_context():
            m = db.session.get(MlModel, result["model_id"])
            assert m is not None
            assert m.algorithm == "RandomForestClassifier"

    def test_model_path_stored(self, app):
        from backend import db
        from backend.models.analysis import MlModel
        result = self._run(app)
        with app.app_context():
            m = db.session.get(MlModel, result["model_id"])
            assert m.model_path is not None

    def test_feature_importance_stored(self, app):
        from backend import db
        from backend.models.analysis import MlModel
        result = self._run(app)
        with app.app_context():
            m = db.session.get(MlModel, result["model_id"])
            assert isinstance(m.feature_importance, list)
            assert len(m.feature_importance) > 0

    # ── Activation gate ───────────────────────────────────────────────────────

    def test_activates_when_no_previous_model(self, app):
        # Run with a very high accuracy so we're sure it activates
        result = self._run(app, accuracy=0.999)
        assert result["activated"] is True
        assert result["outcome"] == "activated"

    def test_activates_when_accuracy_improves(self, app):
        _seed_existing_model(app, accuracy=0.80)
        result = self._run(app, accuracy=0.85)
        assert result["activated"] is True

    def test_activates_when_accuracy_ties(self, app):
        _seed_existing_model(app, accuracy=0.90)
        result = self._run(app, accuracy=0.90)
        assert result["activated"] is True

    def test_does_not_activate_when_accuracy_worse(self, app):
        _seed_existing_model(app, accuracy=0.99)
        result = self._run(app, accuracy=0.85)
        assert result["activated"] is False
        assert result["outcome"] == "no_improvement"

    def test_activated_at_set_when_activated(self, app):
        from backend import db
        from backend.models.analysis import MlModel
        _seed_existing_model(app, accuracy=0.50)
        result = self._run(app, accuracy=0.99)
        with app.app_context():
            m = db.session.get(MlModel, result["model_id"])
            assert m.activated_at is not None

    def test_activated_at_none_when_not_activated(self, app):
        from backend import db
        from backend.models.analysis import MlModel
        _seed_existing_model(app, accuracy=0.9999)
        result = self._run(app, accuracy=0.50)
        with app.app_context():
            m = db.session.get(MlModel, result["model_id"])
            assert m.activated_at is None

    # ── Labeled sample consumption ────────────────────────────────────────────

    def test_new_samples_count_in_result(self, app):
        _seed_labeled_samples(app, n=3)
        result = self._run(app)
        assert result["new_samples"] >= 3   # may include samples from prior tests

    def test_labeled_samples_consumed(self, app):
        from backend import db
        from backend.models.analysis import LabeledSample
        sample_ids = _seed_labeled_samples(app, n=2)
        result = self._run(app)
        with app.app_context():
            for sid in sample_ids:
                s = db.session.get(LabeledSample, sid)
                assert s.included_in_model_id == result["model_id"]

    def test_invalid_length_samples_skipped(self, app):
        """Samples with wrong vector length must not crash the pipeline."""
        from backend import db
        from backend.models.analysis import LabeledSample
        with app.app_context():
            bad = LabeledSample(
                feature_vector=[0.0] * 10,   # wrong length
                true_label="Benign",
                source="manual",
            )
            db.session.add(bad)
            db.session.commit()
            bad_id = bad.sample_id
        # Should complete without raising
        result = self._run(app)
        assert result is not None
        # Bad sample still gets consumed (included_in_model_id set)
        with app.app_context():
            bad = db.session.get(LabeledSample, bad_id)
            assert bad.included_in_model_id == result["model_id"]

    # ── Audit log ─────────────────────────────────────────────────────────────

    def test_audit_log_written(self, app):
        from backend import db
        from backend.models.analysis import AuditLog
        result = self._run(app)
        with app.app_context():
            log = (
                AuditLog.query
                .filter_by(action="retrain", resource_id=result["model_id"])
                .first()
            )
            assert log is not None

    def test_audit_log_details_contains_outcome(self, app):
        from backend import db
        from backend.models.analysis import AuditLog
        result = self._run(app)
        with app.app_context():
            log = (
                AuditLog.query
                .filter_by(action="retrain", resource_id=result["model_id"])
                .first()
            )
            assert log.details is not None
            assert "outcome" in log.details
            assert log.details["outcome"] == result["outcome"]
