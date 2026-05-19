-- Migration: add 'no_symbols' to memory_dumps status CHECK constraint.
-- Safe to run multiple times — the IF NOT EXISTS guard on the new constraint
-- prevents duplicate-constraint errors on re-run.

DO $$
BEGIN
    -- Drop the old constraint (ignore if it doesn't exist)
    IF EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE table_name = 'memory_dumps'
          AND constraint_name = 'memory_dumps_status_check'
          AND constraint_type = 'CHECK'
    ) THEN
        ALTER TABLE memory_dumps DROP CONSTRAINT memory_dumps_status_check;
    END IF;

    -- Add the updated constraint
    ALTER TABLE memory_dumps
        ADD CONSTRAINT memory_dumps_status_check
        CHECK (status IN ('pending', 'processing', 'complete', 'failed', 'no_symbols'));
END $$;
