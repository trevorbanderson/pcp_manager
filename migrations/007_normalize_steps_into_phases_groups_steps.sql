-- Normalize legacy flat step table into phase / step_group / step tables
-- Existing data is preserved by renaming the old step table to step_legacy
-- and seeding the new normalized tables from it.

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'step'
    )
    AND EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'step' AND column_name = 'phase_seq'
    )
    AND NOT EXISTS (
        SELECT 1
        FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'step_legacy'
    ) THEN
        ALTER TABLE step RENAME TO step_legacy;
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS phase (
    id          INTEGER PRIMARY KEY,
    seq         INTEGER NOT NULL,
    description VARCHAR(200) NOT NULL,
    is_active   BOOLEAN NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by  VARCHAR(50)
);

CREATE TABLE IF NOT EXISTS step_group (
    id          INTEGER PRIMARY KEY,
    phase_id    INTEGER NOT NULL REFERENCES phase(id) ON DELETE CASCADE,
    seq         INTEGER NOT NULL,
    description VARCHAR(200) NOT NULL,
    is_active   BOOLEAN NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by  VARCHAR(50)
);

CREATE TABLE IF NOT EXISTS step (
    id            INTEGER PRIMARY KEY,
    step_group_id INTEGER NOT NULL REFERENCES step_group(id) ON DELETE CASCADE,
    seq           INTEGER NOT NULL,
    description   VARCHAR(200),
    step_sql      TEXT,
    is_active     BOOLEAN NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by    VARCHAR(50)
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_phase_seq_description
    ON phase (seq, description);

CREATE UNIQUE INDEX IF NOT EXISTS ux_step_group_phase_seq_description
    ON step_group (phase_id, seq, description);

CREATE UNIQUE INDEX IF NOT EXISTS ux_step_group_seq_description
    ON step (step_group_id, seq, description);

INSERT INTO phase (id, seq, description, is_active, created_at, created_by)
SELECT
    ROW_NUMBER() OVER (ORDER BY src.phase_seq, src.phase_desc) AS id,
    src.phase_seq,
    src.phase_desc,
    src.is_active,
    src.created_at,
    src.created_by
FROM (
    SELECT
        phase_seq,
        COALESCE(NULLIF(BTRIM(phase_desc), ''), 'Unnamed Phase') AS phase_desc,
        BOOL_OR(is_active) AS is_active,
        MIN(created_at) AS created_at,
        MIN(created_by) AS created_by
    FROM step_legacy
    GROUP BY phase_seq, COALESCE(NULLIF(BTRIM(phase_desc), ''), 'Unnamed Phase')
) AS src
WHERE EXISTS (
    SELECT 1 FROM information_schema.tables
    WHERE table_schema = 'public' AND table_name = 'step_legacy'
)
AND NOT EXISTS (SELECT 1 FROM phase);

INSERT INTO step_group (id, phase_id, seq, description, is_active, created_at, created_by)
SELECT
    ROW_NUMBER() OVER (ORDER BY p.seq, src.group_seq, src.group_desc) AS id,
    p.id,
    src.group_seq,
    src.group_desc,
    src.is_active,
    src.created_at,
    src.created_by
FROM (
    SELECT
        phase_seq,
        COALESCE(NULLIF(BTRIM(phase_desc), ''), 'Unnamed Phase') AS phase_desc,
        COALESCE(group_seq, 0) AS group_seq,
        COALESCE(NULLIF(BTRIM(group_desc), ''), 'Ungrouped') AS group_desc,
        BOOL_OR(is_active) AS is_active,
        MIN(created_at) AS created_at,
        MIN(created_by) AS created_by
    FROM step_legacy
    GROUP BY
        phase_seq,
        COALESCE(NULLIF(BTRIM(phase_desc), ''), 'Unnamed Phase'),
        COALESCE(group_seq, 0),
        COALESCE(NULLIF(BTRIM(group_desc), ''), 'Ungrouped')
) AS src
JOIN phase p
  ON p.seq = src.phase_seq
 AND p.description = src.phase_desc
WHERE EXISTS (
    SELECT 1 FROM information_schema.tables
    WHERE table_schema = 'public' AND table_name = 'step_legacy'
)
AND NOT EXISTS (SELECT 1 FROM step_group);

INSERT INTO step (id, step_group_id, seq, description, step_sql, is_active, created_at, created_by)
SELECT
    sl.id,
    sg.id,
    sl.step_seq,
    sl.step_desc,
    sl.step_sql,
    sl.is_active,
    sl.created_at,
    sl.created_by
FROM step_legacy sl
JOIN phase p
  ON p.seq = sl.phase_seq
 AND p.description = COALESCE(NULLIF(BTRIM(sl.phase_desc), ''), 'Unnamed Phase')
JOIN step_group sg
  ON sg.phase_id = p.id
 AND sg.seq = COALESCE(sl.group_seq, 0)
 AND sg.description = COALESCE(NULLIF(BTRIM(sl.group_desc), ''), 'Ungrouped')
WHERE EXISTS (
    SELECT 1 FROM information_schema.tables
    WHERE table_schema = 'public' AND table_name = 'step_legacy'
)
AND NOT EXISTS (SELECT 1 FROM step);
