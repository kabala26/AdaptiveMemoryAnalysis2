"""
Adaptive retraining workflow for the memory malware classifier.

Pipeline
--------
1. Query the database for the current production model and its accuracy
2. Load the base CICMalMem-2022 dataset — split into train/val/test (70/15/15).
   The CICMEM test split is the NEUTRAL evaluation ground and is never touched
   by additional dataset data.
3. Load all approved + active AdditionalDatasets.  Each is split 80/20
   independently; the 80% goes into training, the 20% is held out for
   per-dataset evaluation after training.
4. Append any LabeledSample rows not yet consumed by a prior training run
5. Retrain RandomForest on combined training data
6. Evaluate on CICMEM test set (neutral) — this is the accuracy gate decision
7. Also evaluate per additional dataset on its 20% holdout
8. If new accuracy >= production accuracy → activate new model
   Else → keep previous model, log the attempt
9. Mark consumed LabeledSample rows, write AuditLog

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
    import pandas as pd
    from sklearn.model_selection import train_test_split
    from sklearn.preprocessing import LabelEncoder
    from modules.classifier import (
        DATASET_PATH, MODELS_DIR,
        load_data, split_data, train_model,
        evaluate, get_feature_importance, save_model,
    )
    from backend import db
    from backend.models.analysis import (
        AuditLog, LabeledSample, MlModel,
        AdditionalDataset,
    )

    # ── 1. Current production accuracy ────────────────────────────────────────
    current_model = MlModel.query.filter(
        MlModel.activated_at.isnot(None)
    ).order_by(MlModel.activated_at.desc()).first()
    prev_accuracy = current_model.accuracy if current_model else None

    logger.info(
        "Adaptive retrain starting — current model: %s (acc %.4f)",
        current_model.model_id if current_model else "none",
        prev_accuracy if prev_accuracy is not None else 0.0,
    )

    # ── 2. Base CICMEM dataset — fixed test split (neutral evaluation ground) ──
    X_base, y_base, feature_names = load_data(DATASET_PATH)
    n_features = len(feature_names)

    # The CICMEM test split is locked in — additional data NEVER touches it.
    X_train, X_val, X_test, y_train, y_val, y_test = split_data(X_base, y_base)

    # ── 3. Load approved + active additional datasets ─────────────────────────
    active_datasets = AdditionalDataset.query.filter_by(
        status='approved', is_active=True
    ).all()

    # For each additional dataset: 80% → training pool, 20% → per-dataset eval
    dataset_holdouts = []   # list of (dataset_id, file_name, X_test, y_test)
    n_additional     = 0

    label_enc = LabelEncoder().fit(['Benign', 'Malware'])

    for ds in active_datasets:
        try:
            df = pd.read_csv(ds.file_path)
            X_ds = df[feature_names].values.astype(np.float64)
            y_ds = label_enc.transform(df['Class'].values)

            X_ds_tr, X_ds_te, y_ds_tr, y_ds_te = train_test_split(
                X_ds, y_ds, test_size=0.20, random_state=42, stratify=y_ds,
            )
            X_train = np.vstack([X_train, X_ds_tr])
            y_train = np.concatenate([y_train, y_ds_tr])
            dataset_holdouts.append((ds.dataset_id, ds.file_name, X_ds_te, y_ds_te))
            n_additional += len(X_ds_tr)
            logger.info(
                "Added dataset '%s' — %d train / %d test samples.",
                ds.file_name, len(X_ds_tr), len(X_ds_te),
            )
        except Exception as exc:
            logger.warning("Skipped dataset '%s': %s", ds.file_name, exc)

    # ── 4. Pending pseudo-labels and confirmed labels ─────────────────────────
    pending = LabeledSample.query.filter_by(included_in_model_id=None).all()
    n_new   = len(pending)

    if n_new:
        label_map  = {'Benign': 0, 'Malware': 1}
        valid_rows = [
            (s.feature_vector, label_map[s.true_label])
            for s in pending
            if isinstance(s.feature_vector, list)
            and len(s.feature_vector) == n_features
            and s.true_label in label_map
        ]
        if valid_rows:
            extra_X, extra_y = zip(*valid_rows)
            X_train = np.vstack([X_train, np.array(extra_X, dtype=np.float64)])
            y_train = np.concatenate([y_train, np.array(extra_y)])
            logger.info(
                "Appended %d labeled sample(s) (%d invalid skipped).",
                len(valid_rows), n_new - len(valid_rows),
            )

    # ── 5. Train ──────────────────────────────────────────────────────────────
    clf         = train_model(X_train, y_train)
    val_metrics = evaluate(clf, X_val,  y_val,  "Validation")

    # ── 6. Evaluate on CICMEM test set — the ONLY accuracy gate ──────────────
    test_metrics = evaluate(clf, X_test, y_test, "Test (CICMEM — neutral)")
    new_accuracy = test_metrics['accuracy']

    # ── 7. Per-dataset evaluation (informational only) ────────────────────────
    per_dataset = {}
    for ds_id, ds_name, X_ds_te, y_ds_te in dataset_holdouts:
        try:
            m = evaluate(clf, X_ds_te, y_ds_te, f"Dataset {ds_name}")
            per_dataset[ds_id] = {
                'file_name':  ds_name,
                'accuracy':   round(m['accuracy'],       6),
                'f1_macro':   round(m['f1_macro'],       6),
                'precision':  round(m['precision_macro'], 6),
                'recall':     round(m['recall_macro'],    6),
                'n_samples':  m['n_samples'],
            }
        except Exception as exc:
            logger.warning("Per-dataset eval failed for '%s': %s", ds_name, exc)

    fi          = get_feature_importance(clf, feature_names)
    model_path, _ = save_model(
        clf, feature_names, val_metrics, test_metrics, fi, MODELS_DIR
    )

    # Also retrain secondary (category + family) classifiers
    try:
        from modules.family_classifier import train_secondary_models
        sec = train_secondary_models(DATASET_PATH, MODELS_DIR)
        logger.info(
            "Secondary models retrained — category acc %.4f | family acc %.4f",
            sec['category_accuracy'], sec['family_accuracy'],
        )
    except Exception as exc:
        logger.warning("Secondary model retraining failed: %s", exc)

    # ── 8. Accuracy gate — CICMEM test set decides ────────────────────────────
    activated    = (prev_accuracy is None) or (new_accuracy >= prev_accuracy)
    activated_at = datetime.now(timezone.utc) if activated else None

    if not activated:
        logger.info(
            "New model (acc %.4f) did not improve over current (acc %.4f) — "
            "keeping previous model.",
            new_accuracy, prev_accuracy,
        )

    model_row = MlModel(
        model_name         = 'RandomForest-CICMalMem2022',
        algorithm          = 'RandomForestClassifier',
        accuracy           = new_accuracy,
        model_path         = str(model_path) if activated else None,
        feature_importance = fi,
        activated_at       = activated_at,
    )
    db.session.add(model_row)
    db.session.flush()

    # ── 9. Mark consumed labeled samples ──────────────────────────────────────
    for s in pending:
        s.included_in_model_id = model_row.model_id

    # ── 10. Audit log ─────────────────────────────────────────────────────────
    outcome = 'activated' if activated else 'no_improvement'
    db.session.add(AuditLog(
        user_id       = None,
        action        = 'retrain',
        resource_type = 'model',
        resource_id   = model_row.model_id,
        ip_address    = None,
        details       = {
            'outcome':          outcome,
            'new_accuracy':     round(new_accuracy,  6),
            'prev_accuracy':    round(prev_accuracy, 6) if prev_accuracy is not None else None,
            'new_samples':      n_new,
            'additional_rows':  n_additional,
            'active_datasets':  len(active_datasets),
            'activated':        activated,
            'trigger':          'adaptive',
            'val_accuracy':     round(val_metrics['accuracy'], 6),
            'per_dataset':      per_dataset,
        },
    ))
    db.session.commit()

    logger.info(
        "Retrain complete — new model %s | acc %.4f (prev %s) | %s",
        model_row.model_id, new_accuracy,
        f"{prev_accuracy:.4f}" if prev_accuracy is not None else "none",
        outcome,
    )

    return {
        'model_id':        model_row.model_id,
        'accuracy':        new_accuracy,
        'prev_accuracy':   prev_accuracy,
        'activated':       activated,
        'new_samples':     n_new,
        'additional_rows': n_additional,
        'active_datasets': len(active_datasets),
        'per_dataset':     per_dataset,
        'outcome':         outcome,
    }
