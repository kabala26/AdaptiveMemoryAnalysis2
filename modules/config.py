"""
Central configuration for all tunable constants in the analysis pipeline.

Every numeric threshold, model hyperparameter, and pipeline limit lives here.
Import from this module instead of scattering magic numbers across files.
"""

import os

# ── Upload validation ─────────────────────────────────────────────────────────
ALLOWED_EXTENSIONS  = {'.raw', '.mem', '.dmp', '.vmem', '.csv'}
MAX_UPLOAD_BYTES    = int(os.getenv('MAX_UPLOAD_BYTES', 8 * 1024 * 1024 * 1024))  # 8 GB

# ── Pipeline timeouts ─────────────────────────────────────────────────────────
FAST_TIMEOUT_SECONDS     = int(os.getenv('FAST_TIMEOUT_SECONDS',     86400))
ANALYSIS_TIMEOUT_SECONDS = int(os.getenv('ANALYSIS_TIMEOUT_SECONDS', 86400))
PLUGIN_TIMEOUT_SECONDS   = int(os.getenv('PLUGIN_TIMEOUT_SECONDS',   86400))

# ── Classification thresholds ─────────────────────────────────────────────────
# Minimum Benign confidence at the fast phase to skip Malfind/SvcScan entirely.
BENIGN_EARLY_EXIT_THRESHOLD = float(os.getenv('BENIGN_EARLY_EXIT_THRESHOLD', 0.80))

# Number of top family/category candidates returned in result rankings.
FAMILY_TOP_N   = int(os.getenv('FAMILY_TOP_N',   15))
CATEGORY_TOP_N = int(os.getenv('CATEGORY_TOP_N', 15))

# ── Random Forest — primary classifier ───────────────────────────────────────
RF_N_ESTIMATORS    = int(os.getenv('RF_N_ESTIMATORS',    200))
RF_MAX_DEPTH       = int(os.getenv('RF_MAX_DEPTH',        20))  # None = unlimited
RF_MIN_SAMPLES_LEAF= int(os.getenv('RF_MIN_SAMPLES_LEAF',  2))
RF_MAX_FEATURES    = os.getenv('RF_MAX_FEATURES', 'sqrt')
RF_CLASS_WEIGHT    = os.getenv('RF_CLASS_WEIGHT', 'balanced')
RF_RANDOM_STATE    = int(os.getenv('RF_RANDOM_STATE', 42))

# ── Random Forest — secondary classifiers (family / category) ─────────────────
SEC_N_ESTIMATORS    = int(os.getenv('SEC_N_ESTIMATORS',    100))
SEC_MAX_DEPTH       = int(os.getenv('SEC_MAX_DEPTH',        20))
SEC_MIN_SAMPLES_LEAF= int(os.getenv('SEC_MIN_SAMPLES_LEAF',  2))
SEC_RANDOM_STATE    = int(os.getenv('SEC_RANDOM_STATE', 42))
TRAIN_RATIO_SEC     = float(os.getenv('TRAIN_RATIO_SEC', 0.80))  # secondary classifiers use 80/20

# ── Data splitting ────────────────────────────────────────────────────────────
TRAIN_RATIO = float(os.getenv('TRAIN_RATIO', 0.70))
VAL_RATIO   = float(os.getenv('VAL_RATIO',   0.15))
# TEST_RATIO  = 1 - TRAIN_RATIO - VAL_RATIO  (computed at runtime)

CV_N_SPLITS = int(os.getenv('CV_N_SPLITS', 5))
