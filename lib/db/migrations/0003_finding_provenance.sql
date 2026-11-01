-- Adds the columns the rewritten per-file security-finding engine populates
-- (lib/analysis/security-findings.ts), and relaxes risk_score to nullable so
-- an incompletely-analyzed scan can report "not assessed" instead of a
-- misleading 0.
--
-- Idempotent: safe to run more than once, and safe on a database that
-- already has findings in it.
--
--   psql "$DATABASE_URL" -f lib/db/migrations/0003_finding_provenance.sql

BEGIN;

-- component/component_version let a finding point at the specific piece of
-- software it concerns (e.g. "dropbear", detected version). Most findings
-- are not about a specific component (a weak permission, a plaintext telnet
-- config) and leave these null; this is the join point a future CVE-matching
-- stage would use.
ALTER TABLE vulnerability_findings ADD COLUMN IF NOT EXISTS component         text;
ALTER TABLE vulnerability_findings ADD COLUMN IF NOT EXISTS component_version text;

-- Records which specific check or pattern produced the finding (e.g.
-- "/etc/shadow empty-hash check", "reverse-shell pattern scan"), so an
-- analyst auditing a result can see the exact rule rather than trusting a
-- category label alone.
ALTER TABLE vulnerability_findings ADD COLUMN IF NOT EXISTS detection_source  text;

-- Already applied by migration 0001 for most deployments, but included here
-- as well since it is required for this engine's "not assessed" reporting
-- and the two migrations may be applied out of order in a fresh environment.
ALTER TABLE scans ALTER COLUMN risk_score DROP NOT NULL;

CREATE INDEX IF NOT EXISTS vulnerability_findings_component_idx
  ON vulnerability_findings (component) WHERE component IS NOT NULL;

COMMIT;
