-- Fix results.prediction check constraint to match pipeline output values.
-- Pipeline produces 'Benign' / 'Malware'; original constraint used 'benign' / 'malicious'.

ALTER TABLE results DROP CONSTRAINT IF EXISTS results_prediction_check;

ALTER TABLE results
    ADD CONSTRAINT results_prediction_check
    CHECK (prediction IN ('Benign', 'Malware'));
