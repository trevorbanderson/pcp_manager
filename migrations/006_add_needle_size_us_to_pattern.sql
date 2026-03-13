-- Add needle_size_us column to pattern table
-- Stores the selected US needle size for the pattern based on the chosen yarn weight
-- Run once against the PCP database (dev, staging, prod)

ALTER TABLE pattern
    ADD COLUMN IF NOT EXISTS needle_size_us INTEGER;
