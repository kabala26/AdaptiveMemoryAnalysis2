-- ============================================================
-- Analysis pipeline tables
-- Safe to run multiple times (all statements are idempotent).
-- Does NOT alter or drop the existing users table.
-- ============================================================

-- ── memory_dumps ─────────────────────────────────────────────────────────────
-- One row per uploaded memory dump file.
-- user_id references users.id (VARCHAR(36) UUID stored as text).
-- status lifecycle: pending → processing → complete | failed

CREATE TABLE IF NOT EXISTS memory_dumps (
    dump_id      VARCHAR(36)   PRIMARY KEY,
    user_id      VARCHAR(36)   NOT NULL
                               REFERENCES users(id) ON DELETE CASCADE,
    file_path    TEXT          NOT NULL,
    file_name    VARCHAR(255)  NOT NULL,
    file_size    BIGINT        NOT NULL,           -- bytes
    upload_date  TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    status       VARCHAR(32)   NOT NULL DEFAULT 'pending'
                               CHECK (status IN ('pending', 'processing', 'complete', 'failed')),
    hash_value   VARCHAR(64)                       -- SHA-256 hex digest
);

CREATE INDEX IF NOT EXISTS idx_memory_dumps_user_id
    ON memory_dumps (user_id);

CREATE INDEX IF NOT EXISTS idx_memory_dumps_status
    ON memory_dumps (status);


-- ── features ─────────────────────────────────────────────────────────────────
-- Volatility-extracted feature vector for one memory dump.
-- feature_data holds the full plugin output as structured JSON.

CREATE TABLE IF NOT EXISTS features (
    feature_id     VARCHAR(36)  PRIMARY KEY,
    dump_id        VARCHAR(36)  NOT NULL UNIQUE
                                REFERENCES memory_dumps(dump_id) ON DELETE CASCADE,
    process_count  INTEGER,
    dll_count      INTEGER,
    feature_data   JSONB                          -- full Volatility plugin output
);

CREATE INDEX IF NOT EXISTS idx_features_dump_id
    ON features (dump_id);

CREATE INDEX IF NOT EXISTS idx_features_feature_data
    ON features USING GIN (feature_data);         -- enables fast JSONB key queries


-- ── ml_models ────────────────────────────────────────────────────────────────
-- Registry of trained classifier versions.

CREATE TABLE IF NOT EXISTS ml_models (
    model_id       VARCHAR(36)   PRIMARY KEY,
    model_name     VARCHAR(255)  NOT NULL,
    algorithm      VARCHAR(128)  NOT NULL,         -- e.g. 'RandomForest', 'XGBoost'
    accuracy       FLOAT         CHECK (accuracy >= 0.0 AND accuracy <= 1.0),
    training_date  TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);


-- ── results ──────────────────────────────────────────────────────────────────
-- One classification result per (dump, model) pair.

CREATE TABLE IF NOT EXISTS results (
    result_id           VARCHAR(36)  PRIMARY KEY,
    dump_id             VARCHAR(36)  NOT NULL
                                     REFERENCES memory_dumps(dump_id) ON DELETE CASCADE,
    model_id            VARCHAR(36)  NOT NULL
                                     REFERENCES ml_models(model_id)   ON DELETE RESTRICT,
    prediction          VARCHAR(32)  NOT NULL
                                     CHECK (prediction IN ('Benign', 'Malware')),
    confidence          FLOAT        NOT NULL
                                     CHECK (confidence >= 0.0 AND confidence <= 1.0),
    classification_date TIMESTAMPTZ  NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_result_dump_model UNIQUE (dump_id, model_id)
);

CREATE INDEX IF NOT EXISTS idx_results_dump_id
    ON results (dump_id);

CREATE INDEX IF NOT EXISTS idx_results_model_id
    ON results (model_id);
