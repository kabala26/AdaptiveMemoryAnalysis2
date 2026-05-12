-- Migration: add activated_at, model_path, feature_importance to ml_models
-- Run once against the PostgreSQL auth database.

ALTER TABLE ml_models
  ADD COLUMN IF NOT EXISTS model_path         VARCHAR(512),
  ADD COLUMN IF NOT EXISTS activated_at       TIMESTAMPTZ DEFAULT NOW(),
  ADD COLUMN IF NOT EXISTS feature_importance JSON;

-- Backfill activated_at from training_date for any existing rows
UPDATE ml_models SET activated_at = training_date WHERE activated_at IS NULL;
