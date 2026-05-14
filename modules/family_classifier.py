"""
Two-stage malware family classifier for CICMalMem-2022.

Stage 2a — Category classifier: Ransomware | Spyware | Trojan
Stage 2b — Family classifier: Ako, Conti, Zeus, Emotet, Gator, …

Both models are trained on malicious samples only (Benign rows excluded).
The Category column in the dataset encodes both type and family:
    <Type>-<Family>-<sha256>-<N>.raw
    e.g.  Ransomware-Conti-abc123-3.raw  →  type=Ransomware, family=Conti

Fixed output paths (overwritten on each retrain):
    models/category_classifier.joblib
    models/family_classifier.joblib

Usage
-----
    # Train (called during initial setup or adaptive retrain)
    from modules.family_classifier import train_secondary_models
    train_secondary_models()

    # Inference — only runs when binary prediction = Malicious
    from modules.family_classifier import predict_family
    result = predict_family(feature_vector_1x55)
    # {'category': 'Ransomware', 'category_confidence': 0.91,
    #  'family': 'Conti', 'family_confidence': 0.87}
"""

import logging
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATASET_PATH  = _PROJECT_ROOT / "dataset" / "Obfuscated-MalMem2022.csv"
MODELS_DIR    = _PROJECT_ROOT / "models"

CATEGORY_MODEL_PATH = MODELS_DIR / "category_classifier.joblib"
FAMILY_MODEL_PATH   = MODELS_DIR / "family_classifier.joblib"

RANDOM_STATE = 42
_NON_FEATURE_COLS = {"Category", "Class"}


def _load_malicious(csv_path: Path = DATASET_PATH) -> tuple:
    """
    Load CICMalMem-2022 and return only the malicious rows.

    Returns
    -------
    X            : ndarray (n_mal_samples, 55)
    feature_cols : list[str]
    df_mal       : DataFrame with extra 'mal_type' and 'mal_family' columns
    """
    df = pd.read_csv(csv_path)

    # Parse Category format: "<Type>-<Family>-<hash>-<N>.raw"
    parts = df["Category"].str.split("-")
    df["mal_type"]   = parts.str[0]
    df["mal_family"] = parts.str[1]

    df_mal = df[df["Class"] != "Benign"].copy()

    feature_cols = [
        c for c in df.columns
        if c not in _NON_FEATURE_COLS and c not in ("mal_type", "mal_family", "Class")
    ]
    X = df_mal[feature_cols].values.astype(np.float64)

    logger.info(
        "Loaded %d malicious samples  |  types: %s  |  families: %d",
        len(df_mal),
        df_mal["mal_type"].value_counts().to_dict(),
        df_mal["mal_family"].nunique(),
    )
    return X, feature_cols, df_mal


def train_category_model(
    csv_path: Path = DATASET_PATH,
    save_dir: Path = MODELS_DIR,
) -> dict:
    """Train RF to classify Ransomware | Spyware | Trojan."""
    X, feature_cols, df_mal = _load_malicious(csv_path)

    le = LabelEncoder()
    y  = le.fit_transform(df_mal["mal_type"].values)

    logger.info(
        "Training category classifier  |  classes: %s",
        dict(zip(le.classes_, np.bincount(y))),
    )

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=RANDOM_STATE, stratify=y,
    )

    clf = RandomForestClassifier(
        n_estimators=100, class_weight="balanced",
        random_state=RANDOM_STATE, n_jobs=-1,
    )
    clf.fit(X_train, y_train)

    acc = accuracy_score(y_test, clf.predict(X_test))
    logger.info("Category classifier test accuracy: %.4f", acc)

    save_dir = Path(save_dir)
    save_dir.mkdir(parents=True, exist_ok=True)
    out_path = save_dir / "category_classifier.joblib"
    joblib.dump(
        {"model": clf, "label_encoder": le, "feature_cols": feature_cols},
        out_path, compress=3,
    )
    logger.info("Saved category classifier → %s", out_path)
    return {"model": clf, "label_encoder": le, "accuracy": acc, "path": out_path}


def train_family_model(
    csv_path: Path = DATASET_PATH,
    save_dir: Path = MODELS_DIR,
) -> dict:
    """Train RF to classify specific malware families (Ako, Conti, Zeus, …)."""
    X, feature_cols, df_mal = _load_malicious(csv_path)

    le = LabelEncoder()
    y  = le.fit_transform(df_mal["mal_family"].values)

    logger.info(
        "Training family classifier  |  %d families: %s",
        len(le.classes_), le.classes_.tolist(),
    )

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=RANDOM_STATE, stratify=y,
    )

    clf = RandomForestClassifier(
        n_estimators=100, class_weight="balanced",
        random_state=RANDOM_STATE, n_jobs=-1,
    )
    clf.fit(X_train, y_train)

    acc = accuracy_score(y_test, clf.predict(X_test))
    logger.info("Family classifier test accuracy: %.4f", acc)

    save_dir = Path(save_dir)
    save_dir.mkdir(parents=True, exist_ok=True)
    out_path = save_dir / "family_classifier.joblib"
    joblib.dump(
        {"model": clf, "label_encoder": le, "feature_cols": feature_cols},
        out_path, compress=3,
    )
    logger.info("Saved family classifier → %s", out_path)
    return {"model": clf, "label_encoder": le, "accuracy": acc, "path": out_path}


def train_secondary_models(
    csv_path: Path = DATASET_PATH,
    save_dir: Path = MODELS_DIR,
) -> dict:
    """Train both the category and family classifiers and persist them."""
    logger.info("Training secondary models (category + family) ...")
    cat = train_category_model(csv_path, save_dir)
    fam = train_family_model(csv_path, save_dir)
    return {
        "category_accuracy": round(cat["accuracy"], 6),
        "family_accuracy":   round(fam["accuracy"], 6),
        "category_path":     str(cat["path"]),
        "family_path":       str(fam["path"]),
    }


def predict_family(vec: np.ndarray, top_n: int = 5) -> dict | None:
    """
    Run Stage 2 classification on a (1, 55) feature vector.

    Called only when the binary classifier returns 'Malware'.
    Returns None if the secondary models have not been trained yet.

    Returns
    -------
    {
        'category':            'Ransomware',
        'category_confidence': 0.91,
        'family':              'Conti',
        'family_confidence':   0.87,

        # Full ranked lists (probability > 0.01 cut-off, sorted descending)
        'category_rankings': [
            {'category': 'Ransomware', 'confidence': 0.91},
            {'category': 'Trojan',     'confidence': 0.06},
            ...
        ],
        'family_rankings': [
            {'family': 'Conti',  'confidence': 0.87},
            {'family': 'MAZE',   'confidence': 0.07},
            ...
        ],
    }
    """
    if not CATEGORY_MODEL_PATH.is_file() or not FAMILY_MODEL_PATH.is_file():
        logger.warning(
            "Secondary models not found — run train_secondary_models() first. "
            "Skipping family classification."
        )
        return None

    try:
        cat_bundle = joblib.load(CATEGORY_MODEL_PATH)
        fam_bundle = joblib.load(FAMILY_MODEL_PATH)

        cat_clf = cat_bundle["model"]
        cat_le  = cat_bundle["label_encoder"]
        fam_clf = fam_bundle["model"]
        fam_le  = fam_bundle["label_encoder"]

        # ── Category rankings ─────────────────────────────────────────────────
        cat_proba = cat_clf.predict_proba(vec)[0]
        cat_ranked = sorted(
            zip(cat_le.classes_, cat_proba.tolist()),
            key=lambda t: t[1], reverse=True,
        )
        cat_label = cat_ranked[0][0]
        cat_conf  = float(cat_ranked[0][1])
        category_rankings = [
            {"category": c, "confidence": round(float(p), 4)}
            for c, p in cat_ranked[:top_n]
            if p > 0.01
        ]

        # ── Family rankings ───────────────────────────────────────────────────
        fam_proba = fam_clf.predict_proba(vec)[0]
        fam_ranked = sorted(
            zip(fam_le.classes_, fam_proba.tolist()),
            key=lambda t: t[1], reverse=True,
        )
        fam_label = fam_ranked[0][0]
        fam_conf  = float(fam_ranked[0][1])
        family_rankings = [
            {"family": f, "confidence": round(float(p), 4)}
            for f, p in fam_ranked[:top_n]
            if p > 0.01
        ]

        return {
            "category":            cat_label,
            "category_confidence": round(cat_conf, 4),
            "family":              fam_label,
            "family_confidence":   round(fam_conf, 4),
            "category_rankings":   category_rankings,
            "family_rankings":     family_rankings,
        }
    except Exception as exc:
        logger.warning("Family classification failed: %s", exc)
        return None


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s  %(levelname)-7s  %(message)s",
        datefmt="%H:%M:%S",
    )
    result = train_secondary_models()
    print("\nSecondary model training complete:")
    for k, v in result.items():
        print(f"  {k}: {v}")
