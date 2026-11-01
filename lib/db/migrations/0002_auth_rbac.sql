-- Authentication, RBAC, scan ownership and audit logging.
--
-- Idempotent: safe to run more than once, and safe on a database that already
-- contains scans.
--
--   psql "$DATABASE_URL" -f lib/db/migrations/0002_auth_rbac.sql
--
-- NOTE ON EXISTING SCANS
-- ----------------------
-- scans.user_id is added as NULLABLE and existing rows are left NULL on
-- purpose. The access layer treats a NULL owner as admin-only. Backfilling
-- those rows to some arbitrary user would hand one account ownership of
-- everyone's historical scans, and defaulting them to "public" would expose
-- every prior scan the moment authentication was switched on.

BEGIN;

-- --------------------------------------------------------------------------
-- users
-- --------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
  id                  text PRIMARY KEY,
  email               text        NOT NULL,
  email_normalized    text        NOT NULL,
  name                text        NOT NULL,
  role                text        NOT NULL DEFAULT 'user',
  password_hash       text        NOT NULL,
  password_salt       text        NOT NULL,
  -- scrypt cost parameters, stored per user so the cost can be raised later
  -- without invalidating existing credentials.
  password_params     jsonb       NOT NULL,
  failed_login_count  integer     NOT NULL DEFAULT 0,
  locked_until        timestamptz,
  disabled            integer     NOT NULL DEFAULT 0,
  created_at          timestamptz NOT NULL DEFAULT now(),
  last_login_at       timestamptz
);

-- Case-insensitive uniqueness: "Admin@x.com" must not coexist with
-- "admin@x.com", or one could be used to impersonate the other.
CREATE UNIQUE INDEX IF NOT EXISTS users_email_normalized_idx ON users (email_normalized);

-- Roles are validated in the application, but this keeps a bad direct INSERT
-- from creating an account with an unrecognised role.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'users_role_check') THEN
    ALTER TABLE users ADD CONSTRAINT users_role_check
      CHECK (role IN ('admin', 'analyst', 'user'));
  END IF;
END $$;

-- --------------------------------------------------------------------------
-- sessions
--
-- Only a SHA-256 of the session token is stored, so a database disclosure
-- does not yield usable session cookies.
-- --------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sessions (
  id           text PRIMARY KEY,
  token_hash   text        NOT NULL,
  user_id      text        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  created_at   timestamptz NOT NULL DEFAULT now(),
  expires_at   timestamptz NOT NULL,
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  ip_address   text,
  user_agent   text,
  revoked_at   timestamptz
);

CREATE UNIQUE INDEX IF NOT EXISTS sessions_token_hash_idx ON sessions (token_hash);
CREATE INDEX IF NOT EXISTS sessions_user_id_idx ON sessions (user_id);
-- Supports the expiry sweep without scanning the whole table.
CREATE INDEX IF NOT EXISTS sessions_expires_at_idx ON sessions (expires_at);

-- --------------------------------------------------------------------------
-- audit_logs (append-only by convention; application code never updates it)
--
-- user_id is intentionally NOT a foreign key: failed logins are recorded
-- before a user is established, and deleting a user must not erase the
-- record of what that account did.
-- --------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_logs (
  id         text PRIMARY KEY,
  user_id    text,
  user_email text,
  action     text        NOT NULL,
  resource   text,
  outcome    text        NOT NULL DEFAULT 'success',
  detail     text,
  ip_address text,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS audit_logs_created_at_idx ON audit_logs (created_at DESC);
CREATE INDEX IF NOT EXISTS audit_logs_user_id_idx    ON audit_logs (user_id);
CREATE INDEX IF NOT EXISTS audit_logs_action_idx     ON audit_logs (action);

-- --------------------------------------------------------------------------
-- scan ownership
-- --------------------------------------------------------------------------
ALTER TABLE scans ADD COLUMN IF NOT EXISTS user_id text;

-- ON DELETE SET NULL rather than CASCADE: removing a user must not silently
-- destroy the scan history and its audit value. The scans become admin-only.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'scans_user_id_fkey') THEN
    ALTER TABLE scans ADD CONSTRAINT scans_user_id_fkey
      FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL;
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS scans_user_id_idx ON scans (user_id);

-- Risk score must be nullable so an incompletely analyzed image can report
-- "not assessed" instead of a misleading 0/100.
ALTER TABLE scans ALTER COLUMN risk_score DROP NOT NULL;

COMMIT;

-- --------------------------------------------------------------------------
-- FIRST RUN
-- --------------------------------------------------------------------------
-- No default account is created on purpose: a shipped default credential is
-- the most common way a project like this gets compromised.
--
-- Create the first administrator by POSTing to /api/auth/register. That
-- endpoint only works while the users table is empty; the first account
-- becomes the admin, and every later account is created by an admin through
-- /api/admin/users.
--
--   curl -X POST http://localhost:5000/api/auth/register \
--     -H 'Content-Type: application/json' \
--     -d '{"email":"you@example.com","name":"Your Name","password":"<12+ chars, mixed case, digit>"}'
