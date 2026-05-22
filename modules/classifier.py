"""
Random Forest classifier for the CICMalMem-2022 (Obfuscated-MalMem2022) dataset.

Pipeline
--------
1. Load CSV from ../dataset/Obfuscated-MalMem2022.csv
2. Split  70% train / 15% validation / 15% test  (stratified)
3. Train  RandomForestClassifier(n_estimators=100, class_weight='balanced')
4. Report accuracy, precision, recall, F1 on validation and test splits
5. Save   trained model + metadata to ../models/rf_<timestamp>.joblib / .json

Usage
-----
    python modules/classifier.py               # run from project root
    python -m modules.classifier               # same

Programmatic:
    from modules.classifier import train_and_evaluate
    result = train_and_evaluate()
"""

import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.preprocessing import LabelEncoder

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

# ── Paths ─────────────────────────────────────────────────────────────────────
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATASET_PATH  = _PROJECT_ROOT / "dataset" / "Obfuscated-MalMem2022.csv"
MODELS_DIR    = _PROJECT_ROOT / "models"

# ── Columns that are not features ────────────────────────────────────────────
_NON_FEATURE_COLS = {"Category", "Class"}

# ── All tunable constants from central config ─────────────────────────────────
from modules.config import (
    TRAIN_RATIO, VAL_RATIO, CV_N_SPLITS,
    RF_N_ESTIMATORS, RF_MAX_DEPTH, RF_MIN_SAMPLES_LEAF,
    RF_MAX_FEATURES, RF_CLASS_WEIGHT, RF_RANDOM_STATE as RANDOM_STATE,
)


# ─────────────────────────────────────────────────────────────────────────────
# Data loading
# ─────────────────────────────────────────────────────────────────────────────

def load_data(csv_path: Path | str = DATASET_PATH) -> tuple[np.ndarray, np.ndarray, list[str]]:
    """
    Load the CICMalMem-2022 CSV and return feature matrix, label vector,
    and feature names.

    Returns
    -------
    X : ndarray of shape (n_samples, 55)
    y : ndarray of shape (n_samples,)  — 0 = Benign, 1 = Malware
    feature_names : list[str]
    """
    csv_path = Path(csv_path)
    if not csv_path.is_file():
        raise FileNotFoundError(f"Dataset not found: {csv_path}")

    logger.info("Loading dataset from %s", csv_path)
    df = pd.read_csv(csv_path)

    before = len(df)
    df = df.drop_duplicates()
    if len(df) < before:
        logger.info("Removed %d duplicate rows (%d → %d)", before - len(df), before, len(df))

    feature_cols = [c for c in df.columns if c not in _NON_FEATURE_COLS]
    X = df[feature_cols].values.astype(np.float64)

    le = LabelEncoder()
    y = le.fit_transform(df["Class"].values)   # Benign=0, Malware=1

    logger.info(
        "Loaded %d samples, %d features  |  classes: %s",
        X.shape[0], X.shape[1],
        dict(zip(le.classes_, np.bincount(y))),
    )
    return X, y, feature_cols


# ─────────────────────────────────────────────────────────────────────────────
# Splitting
# ─────────────────────────────────────────────────────────────────────────────

def split_data(
    X: np.ndarray,
    y: np.ndarray,
    train_ratio: float = TRAIN_RATIO,
    val_ratio: float   = VAL_RATIO,
) -> tuple[np.ndarray, ...]:
    """
    Stratified 70 / 15 / 15 split.

    Returns
    -------
    X_train, X_val, X_test, y_train, y_val, y_test
    """
    test_ratio = round(1.0 - train_ratio - val_ratio, 10)

    # First cut: train vs (val + test)
    X_train, X_temp, y_train, y_temp = train_test_split(
        X, y,
        test_size=(val_ratio + test_ratio),
        random_state=RANDOM_STATE,
        stratify=y,
    )

    # Second cut: val vs test (50 / 50 of the temp pool)
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp,
        test_size=0.5,
        random_state=RANDOM_STATE,
        stratify=y_temp,
    )

    logger.info(
        "Split  →  train: %d (70%%)  |  val: %d (15%%)  |  test: %d (15%%)",
        len(y_train), len(y_val), len(y_test),
    )
    return X_train, X_val, X_test, y_train, y_val, y_test


# ─────────────────────────────────────────────────────────────────────────────
# Training
# ─────────────────────────────────────────────────────────────────────────────

def train_model(
    X_train: np.ndarray,
    y_train: np.ndarray,
) -> RandomForestClassifier:
    """
    Train a Random Forest with mild regularisation.

    max_depth=20 and min_samples_leaf=2 prevent the trees from memorising
    dataset-specific noise, improving generalisation to out-of-distribution
    real-world memory dumps without meaningfully hurting CICMEM accuracy.
    """
    model = RandomForestClassifier(
        n_estimators=RF_N_ESTIMATORS,
        max_depth=RF_MAX_DEPTH,
        min_samples_leaf=RF_MIN_SAMPLES_LEAF,
        max_features=RF_MAX_FEATURES,
        class_weight=RF_CLASS_WEIGHT,
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )
    logger.info(
        "Training RandomForestClassifier("
        "n_estimators=%d, max_depth=%s, min_samples_leaf=%d, "
        "max_features=%s, class_weight=%s)",
        RF_N_ESTIMATORS, RF_MAX_DEPTH, RF_MIN_SAMPLES_LEAF,
        RF_MAX_FEATURES, RF_CLASS_WEIGHT,
    )
    t0 = time.perf_counter()
    model.fit(X_train, y_train)
    elapsed = time.perf_counter() - t0
    logger.info("Training complete in %.2f s", elapsed)
    return model


# ─────────────────────────────────────────────────────────────────────────────
# Evaluation
# ─────────────────────────────────────────────────────────────────────────────

def evaluate(
    model: RandomForestClassifier,
    X: np.ndarray,
    y: np.ndarray,
    split_name: str,
) -> dict:
    """
    Compute and return a metrics dict for one data split.
    Also prints a formatted report.
    """
    y_pred = model.predict(X)

    acc   = accuracy_score(y, y_pred)
    prec  = precision_score(y, y_pred, average="macro", zero_division=0)
    rec   = recall_score(y, y_pred, average="macro", zero_division=0)
    f1    = f1_score(y, y_pred, average="macro", zero_division=0)
    cm    = confusion_matrix(y, y_pred)
    report = classification_report(
        y, y_pred,
        target_names=["Benign", "Malware"],
        zero_division=0,
    )

    label = split_name.upper()
    sep   = "─" * 52
    print(f"\n{'═'*52}")
    print(f"  {label} SET RESULTS")
    print(f"{'═'*52}")
    print(f"  Accuracy  : {acc:.4f}  ({acc*100:.2f} %)")
    print(f"  Precision : {prec:.4f}  (macro avg)")
    print(f"  Recall    : {rec:.4f}  (macro avg)")
    print(f"  F1-Score  : {f1:.4f}  (macro avg)")
    print(f"\n  Confusion Matrix  (rows=actual, cols=predicted):")
    print(f"               Benign   Malware")
    print(f"    Benign   {cm[0,0]:>7}  {cm[0,1]:>7}")
    print(f"    Malware  {cm[1,0]:>7}  {cm[1,1]:>7}")
    print(f"\n  Per-Class Report:")
    for line in report.splitlines():
        print(f"    {line}")
    print(f"{'═'*52}")

    return {
        "split":          split_name,
        "n_samples":      int(len(y)),
        "accuracy":       round(float(acc),  6),
        "precision_macro": round(float(prec), 6),
        "recall_macro":   round(float(rec),  6),
        "f1_macro":       round(float(f1),   6),
        "confusion_matrix": cm.tolist(),
        "classification_report": report,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Feature importance
# ─────────────────────────────────────────────────────────────────────────────

def cross_validate_model(
    model: RandomForestClassifier,
    X: np.ndarray,
    y: np.ndarray,
    n_splits: int = 5,
) -> dict:
    """
    Run stratified k-fold cross-validation and return mean ± std accuracy.
    More statistically reliable than a single train/test split.
    """
    cv = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=RANDOM_STATE)
    scores = cross_val_score(model, X, y, cv=cv, scoring='accuracy', n_jobs=-1)

    mean_acc = float(scores.mean())
    std_acc  = float(scores.std())

    print(f"\n{'═'*52}")
    print(f"  {n_splits}-FOLD CROSS-VALIDATION")
    print(f"{'═'*52}")
    print(f"  Mean accuracy : {mean_acc:.4f}  ({mean_acc*100:.2f} %)")
    print(f"  Std deviation : {std_acc:.4f}")
    print(f"  Fold scores   : {[round(s, 4) for s in scores.tolist()]}")
    print(f"{'═'*52}")

    logger.info(
        "CV (%d-fold): %.4f ± %.4f", n_splits, mean_acc, std_acc
    )
    return {
        'cv_folds':        n_splits,
        'cv_mean_accuracy': round(mean_acc, 6),
        'cv_std_accuracy':  round(std_acc, 6),
        'cv_fold_scores':   [round(float(s), 6) for s in scores],
    }


def get_feature_importance(
    model: RandomForestClassifier,
    feature_names: list[str],
    top_n: int = 20,
) -> list[dict]:
    """
    Return feature importances sorted descending and print the top_n.
    """
    importances = model.feature_importances_
    ranked = sorted(
        zip(feature_names, importances.tolist()),
        key=lambda t: t[1],
        reverse=True,
    )

    print(f"\n{'═'*52}")
    print(f"  TOP {top_n} FEATURE IMPORTANCES")
    print(f"{'═'*52}")
    for rank, (name, score) in enumerate(ranked[:top_n], start=1):
        bar = "█" * int(score * 400)
        print(f"  {rank:>2}. {name:<42}  {score:.6f}  {bar}")
    print(f"{'═'*52}")

    return [{"feature": name, "importance": round(score, 8)}
            for name, score in ranked]


# ─────────────────────────────────────────────────────────────────────────────
# Model saving
# ─────────────────────────────────────────────────────────────────────────────

def save_model(
    model: RandomForestClassifier,
    feature_names: list[str],
    val_metrics: dict,
    test_metrics: dict,
    feature_importance: list[dict],
    save_dir: Path | str = MODELS_DIR,
) -> tuple[Path, Path]:
    """
    Persist the model and a JSON metadata file.

    Returns
    -------
    model_path, metadata_path
    """
    save_dir = Path(save_dir)
    save_dir.mkdir(parents=True, exist_ok=True)

    ts         = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    model_path = save_dir / f"rf_{ts}.joblib"
    meta_path  = save_dir / f"rf_{ts}_metadata.json"

    joblib.dump(model, model_path, compress=3)

    metadata = {
        "model_type":       "RandomForestClassifier",
        "saved_at":         datetime.now(timezone.utc).isoformat(),
        "hyperparameters": {
            "n_estimators":  model.n_estimators,
            "class_weight":  model.class_weight,
            "random_state":  model.random_state,
        },
        "n_features":       len(feature_names),
        "feature_names":    feature_names,
        "dataset":          "CICMalMem-2022 / Obfuscated-MalMem2022.csv",
        "validation_metrics": {
            k: v for k, v in val_metrics.items()
            if k not in ("classification_report", "confusion_matrix")
        },
        "test_metrics": {
            k: v for k, v in test_metrics.items()
            if k not in ("classification_report", "confusion_matrix")
        },
        "top_20_features":  feature_importance[:20],
    }

    with open(meta_path, "w") as f:
        json.dump(metadata, f, indent=2)

    logger.info("Model saved  →  %s", model_path.name)
    logger.info("Metadata     →  %s", meta_path.name)
    return model_path, meta_path


# ─────────────────────────────────────────────────────────────────────────────
# Full pipeline
# ─────────────────────────────────────────────────────────────────────────────

def train_and_evaluate(
    csv_path: Path | str = DATASET_PATH,
    save_dir: Path | str = MODELS_DIR,
) -> dict:
    """
    Run the complete training pipeline.

    Returns a dict with keys:
      model, model_path, metadata_path,
      val_metrics, test_metrics, feature_importance
    """
    print("\n" + "═" * 52)
    print("  ADAPTIVE ML — MEMORY MALWARE CLASSIFIER")
    print("  Random Forest on CICMalMem-2022")
    print("═" * 52)

    X, y, feature_names = load_data(csv_path)

    X_train, X_val, X_test, y_train, y_val, y_test = split_data(X, y)

    model = train_model(X_train, y_train)

    val_metrics  = evaluate(model, X_val,  y_val,  "Validation")
    test_metrics = evaluate(model, X_test, y_test, "Test")
    cv_metrics   = cross_validate_model(model, X, y)

    # Merge CV metrics into test_metrics so they're stored in metadata
    test_metrics.update(cv_metrics)

    feature_importance = get_feature_importance(model, feature_names)

    model_path, meta_path = save_model(
        model, feature_names,
        val_metrics, test_metrics, feature_importance,
        save_dir,
    )

    print(f"\n  Model : {model_path}")
    print(f"  Meta  : {meta_path}\n")

    return {
        "model":              model,
        "model_path":         model_path,
        "metadata_path":      meta_path,
        "feature_names":      feature_names,
        "val_metrics":        val_metrics,
        "test_metrics":       test_metrics,
        "feature_importance": feature_importance,
    }


# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    train_and_evaluate()
