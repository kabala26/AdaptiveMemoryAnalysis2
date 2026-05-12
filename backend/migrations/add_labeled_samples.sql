-- Migration: create labeled_samples table for adaptive retraining
-- Run once against the PostgreSQL auth database.

CREATE TABLE IF NOT EXISTS labeled_samples (
    sample_id            VARCHAR(36)  PRIMARY KEY,
    dump_id              VARCHAR(36)  REFERENCES memory_dumps(dump_id) ON DELETE SET NULL,
    feature_vector       JSON         NOT NULL,
    true_label           VARCHAR(32)  NOT NULL CHECK (true_label IN ('Benign', 'Malware')),
    source               VARCHAR(64)  NOT NULL DEFAULT 'manual',
    added_by             VARCHAR(36)  REFERENCES users(id) ON DELETE SET NULL,
    added_at             TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    included_in_model_id VARCHAR(36)  REFERENCES ml_models(model_id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS ix_labeled_samples_added_at ON labeled_samples(added_at);
CREATE INDEX IF NOT EXISTS ix_labeled_samples_included  ON labeled_samples(included_in_model_id);
CREATE INDEX IF NOT EXISTS ix_labeled_samples_dump_id   ON labeled_samples(dump_id);
