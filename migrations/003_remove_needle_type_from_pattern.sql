-- Remove needle_type column from pattern table
-- Notions (stored in pattern_element via element type='notion') replace this field.
-- Run once against the PCP database (dev, staging, prod)

ALTER TABLE pattern
    DROP COLUMN IF EXISTS needle_type;
