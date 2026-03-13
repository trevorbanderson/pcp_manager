-- Add yarn_used_url column to pattern table
-- Stores a hyperlink to the yarn product page used in the pattern
-- Run once against the PCP database (dev, staging, prod)

ALTER TABLE pattern
    ADD COLUMN IF NOT EXISTS yarn_used_url VARCHAR(500);
