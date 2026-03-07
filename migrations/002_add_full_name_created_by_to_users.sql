-- Add full_name and created_by columns to users table
-- Run once against the PCP database (dev, staging, prod)

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS full_name  VARCHAR(100),
    ADD COLUMN IF NOT EXISTS created_by INTEGER;

-- Back-fill full_name from username for existing rows
UPDATE users SET full_name = username WHERE full_name IS NULL;

-- Make full_name NOT NULL now that every row has a value
ALTER TABLE users ALTER COLUMN full_name SET NOT NULL;

-- Fix the id sequence if it drifted out of sync with existing rows
SELECT setval('users_id_seq', GREATEST((SELECT MAX(id) FROM users), 1));
