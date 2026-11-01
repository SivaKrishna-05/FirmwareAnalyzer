-- Adds the columns required by the real extraction and static-analysis
-- pipeline (recursive extraction, ELF metadata, entropy, ownership,
-- archive-declared permission bits).
--
-- This project normally applies schema changes with `pnpm --filter @workspace/db push`
-- (drizzle-kit push). That is fine on an empty database, but `push` can prompt
-- or drop data when a populated table changes. This script is the safe path for
-- an environment that already has scans in it: every statement is idempotent,
-- so it can be run more than once without error.
--
--   psql "$DATABASE_URL" -f lib/db/migrations/0001_real_extraction.sql
--
-- Existing rows are backfilled with values that are truthful about the fact
-- that they were produced by the previous, shallower pipeline, rather than
-- with defaults that would imply an extraction depth they never had.

BEGIN;

-- --------------------------------------------------------------------------
-- scans: record what extraction actually achieved, not just a free-text status
-- --------------------------------------------------------------------------
ALTER TABLE scans ADD COLUMN IF NOT EXISTS extraction_method      text;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS extracted_file_count   integer NOT NULL DEFAULT 0;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS extraction_depth       integer NOT NULL DEFAULT 0;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS extraction_notes       text;

-- --------------------------------------------------------------------------
-- scan_files: per-file static analysis results
-- --------------------------------------------------------------------------
ALTER TABLE scan_files ADD COLUMN IF NOT EXISTS owner             text;
ALTER TABLE scan_files ADD COLUMN IF NOT EXISTS "group"           text;
ALTER TABLE scan_files ADD COLUMN IF NOT EXISTS md5               text;
ALTER TABLE scan_files ADD COLUMN IF NOT EXISTS sha1              text;
ALTER TABLE scan_files ADD COLUMN IF NOT EXISTS suspicious        integer NOT NULL DEFAULT 0;
ALTER TABLE scan_files ADD COLUMN IF NOT EXISTS suspicious_reason text;
-- Shannon entropy x1000, stored as an integer so the value does not drift
-- across pg driver float handling. Divided back down at the API edge.
ALTER TABLE scan_files ADD COLUMN IF NOT EXISTS entropy_milli     integer;
ALTER TABLE scan_files ADD COLUMN IF NOT EXISTS binary_info       jsonb;

-- --------------------------------------------------------------------------
-- Backfill: be explicit that pre-existing scans predate this pipeline.
-- Silently leaving them at "none"/0 would read as "we looked and found
-- nothing", which is not what happened.
-- --------------------------------------------------------------------------
UPDATE scans
SET extraction_notes = COALESCE(
      extraction_notes,
      'This scan was produced by the previous extraction pipeline, which did not '
      || 'unpack SquashFS/UBI filesystems or carve embedded containers. '
      || 'Re-scan the image to obtain a full inventory.'
    )
WHERE extraction_method IS NULL;

-- Filter indexes to the access patterns the analyst views actually use.
CREATE INDEX IF NOT EXISTS scan_files_scan_id_idx     ON scan_files (scan_id);
CREATE INDEX IF NOT EXISTS scan_files_suspicious_idx  ON scan_files (scan_id) WHERE suspicious = 1;
CREATE INDEX IF NOT EXISTS scans_created_at_idx       ON scans (created_at DESC);

COMMIT;
