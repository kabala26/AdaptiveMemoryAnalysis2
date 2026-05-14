-- Add malware family classification columns to the results table.
-- Safe to run multiple times (IF NOT EXISTS guards each column).

ALTER TABLE results ADD COLUMN IF NOT EXISTS malware_category    VARCHAR(64);
ALTER TABLE results ADD COLUMN IF NOT EXISTS category_confidence DOUBLE PRECISION;
ALTER TABLE results ADD COLUMN IF NOT EXISTS malware_family      VARCHAR(64);
ALTER TABLE results ADD COLUMN IF NOT EXISTS family_confidence   DOUBLE PRECISION;
