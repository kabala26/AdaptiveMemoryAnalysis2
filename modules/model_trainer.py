"""
Adaptive retraining workflow for the memory malware classifier.

Pipeline
--------
1. Query the database for the current production model and its accuracy
2. Load the base CICMalMem-2022 dataset
3. Append any LabeledSample rows not yet consumed by a prior training run
4. Retrain RandomForest, evaluate on hold-out test split
5. If new accuracy >= production accuracy (or no production model exists):
      set activated_at, making it the live model
   Else:
      persist for record-keeping but leave production model unchanged
6. Mark all consumed LabeledSample rows with the new model_id
7. Write an AuditLog entry regardless of outcome

Entry points
------------
  adaptive_retrain(app)   — for background threads and APScheduler (no context)
  retrain_in_context()    — when an app context is already pushed by the caller
"""

import logging
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parent.parent


# ── Public entry points ───────────────────────────────────────────────────────

def adaptive_retrain(app) -> dict:
    """
    Run the full adaptive retraining pipeline.

    Pushes its own app context; safe to call from threads / APScheduler.

    Returns
    -------
    dict with keys:
      model_id, accuracy, prev_accuracy, activated, new_samples, outcome
    """
    with app.app_context():
        return _retrain()


def retrain_in_context() -> dict:
    """
    Same pipeline but expects an active app context from the caller.
    Used by _retrain_worker in routes/analysis.py to avoid nested contexts.
    """
    return _retrain()


# ── Core pipeline ─────────────────────────────────────────────────────────────

def _retrain() -> dict:
    from modules.classifier import (
        DATASET_PATH, MODELS_DIR,
        load_data, split_data, train_model,
        evaluate, get_feature_importance, save_model,
    )
    # Imported lazily — app context is guaranteed at call time
    from backend import db
    from backend.models.analysis import AuditLog, LabeledSample, MlModel

    # ── 1. Current production accuracy ────────────────────────────────────────
    current_model = MlModel.query.order_by(MlModel.activated_at.desc()).first()
    prev_accuracy = current_model.accuracy if current_model else None

    logger.info(
        "Adaptive retrain starting — current model: %s (acc %.4f)",
        current_model.model_id if current_model else "none",
        prev_accuracy if prev_accuracy is not None else 0.0,
    )

    # ── 2. Base dataset ───────────────────────────────────────────────────────
    X, y, feature_names = load_data(DATASET_PATH)
    n_features = len(feature_names)

    # ── 3. New labeled samples not yet included in any model ──────────────────
    pending = LabeledSample.query.filter_by(included_in_model_id=None).all()
    n_new   = len(pending)

    if n_new:
        label_map = {'Benign': 0, 'Malware': 1}
        valid_rows = [
            (s.feature_vector, label_map[s.true_label])
            for s in pending
            if isinstance(s.feature_vector, list)
            and len(s.feature_vector) == n_features
            and s.true_label in label_map
        ]
        if valid_rows:
            extra_X, extra_y = zip(*valid_rows)
            X = np.vstack([X, np.array(extra_X, dtype=np.float64)])
            y = np.concatenate([y, np.array(extra_y)])
            logger.info(
                "Appended %d new labeled sample(s) to training data (%d invalid skipped).",
                len(valid_rows), n_new - len(valid_rows),
            )

    # ── 4. Train and evaluate ─────────────────────────────────────────────────
    X_train, X_val, X_test, y_train, y_val, y_test = split_data(X, y)
    clf          = train_model(X_train, y_train)
    val_metrics  = evaluate(clf, X_val,  y_val,  "Validation")
    test_metrics = evaluate(clf, X_test, y_test, "Test")
    fi           = get_feature_importance(clf, feature_names)
    model_path, _= save_model(
        clf, feature_names, val_metrics, test_metrics, fi, MODELS_DIR
    )

    new_accuracy = test_metrics['accuracy']

    # ── 5. Accuracy gate ──────────────────────────────────────────────────────
    # Activate if there is no production model yet, or if we match / exceed it.
    activated    = (prev_accuracy is None) or (new_accuracy >= prev_accuracy)
    activated_at = datetime.now(timezone.utc) if activated else None

    model_row = MlModel(
        model_name         = 'RandomForest-CICMalMem2022',
        algorithm          = 'RandomForestClassifier',
        accuracy           = new_accuracy,
        model_path         = str(model_path),
        feature_importance = fi,
        activated_at       = activated_at,
    )
    db.session.add(model_row)
    db.session.flush()   # populate model_id before we reference it below

    # ── 6. Mark all consumed labeled samples ──────────────────────────────────
    for s in pending:
        s.included_in_model_id = model_row.model_id

    # ── 7. Audit log ──────────────────────────────────────────────────────────
    outcome = 'activated' if activated else 'no_improvement'
    db.session.add(AuditLog(
        user_id       = None,   # system-initiated — no JWT caller
        action        = 'retrain',
        resource_type = 'model',
        resource_id   = model_row.model_id,
        ip_address    = None,
        details       = {
            'outcome':       outcome,
            'new_accuracy':  round(new_accuracy, 6),
            'prev_accuracy': round(prev_accuracy, 6) if prev_accuracy is not None else None,
            'new_samples':   n_new,
            'activated':     activated,
            'trigger':       'adaptive',
            'val_accuracy':  round(val_metrics['accuracy'], 6),
        },
    ))
    db.session.commit()

    logger.info(
        "Retrain complete — new model %s | acc %.4f (prev %s) | %s",
        model_row.model_id,
        new_accuracy,
        f"{prev_accuracy:.4f}" if prev_accuracy is not None else "none",
        outcome,
    )

    return {
        'model_id':      model_row.model_id,
        'accuracy':      new_accuracy,
        'prev_accuracy': prev_accuracy,
        'activated':     activated,
        'new_samples':   n_new,
        'outcome':       outcome,
    }
