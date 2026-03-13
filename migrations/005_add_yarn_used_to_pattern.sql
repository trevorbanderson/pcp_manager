-- Add yarn_used display name column to pattern table
-- yarn_used: required text field for the name of the yarn used
-- yarn_used_url (added in 004) remains as the optional product link
-- Run once against the PCP database (dev, staging, prod)

ALTER TABLE pattern
    ADD COLUMN IF NOT EXISTS yarn_used VARCHAR(200);
