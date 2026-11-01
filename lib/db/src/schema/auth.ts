import {
  index,
  integer,
  jsonb,
  pgTable,
  text,
  timestamp,
  uniqueIndex,
} from "drizzle-orm/pg-core";

/**
 * Roles are a closed set, enforced in the application layer rather than by a
 * Postgres enum so that adding a role does not require a migration on a
 * populated table. `assertRole` in lib/auth/rbac.ts is the single validator.
 */
export const ROLES = ["admin", "analyst", "user"] as const;
export type Role = (typeof ROLES)[number];

export const usersTable = pgTable(
  "users",
  {
    id: text("id").primaryKey(),
    email: text("email").notNull(),
    // Stored lowercased and trimmed; uniqueness is enforced on this column so
    // "Admin@x.com" and "admin@x.com" cannot both register.
    emailNormalized: text("email_normalized").notNull(),
    name: text("name").notNull(),
    role: text("role").notNull().default("user"),

    // scrypt parameters and output are stored alongside the hash so the cost
    // can be raised later without invalidating existing credentials: an old
    // hash is verified with the parameters it was created under, then
    // transparently re-hashed on the next successful login.
    passwordHash: text("password_hash").notNull(),
    passwordSalt: text("password_salt").notNull(),
    passwordParams: jsonb("password_params").$type<{
      algorithm: "scrypt";
      N: number;
      r: number;
      p: number;
      keyLength: number;
    }>().notNull(),

    // Lockout state. Counting failures in the database (rather than in memory)
    // keeps the protection effective across restarts and multiple instances.
    failedLoginCount: integer("failed_login_count").notNull().default(0),
    lockedUntil: timestamp("locked_until", { withTimezone: true }),

    disabled: integer("disabled").notNull().default(0),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    lastLoginAt: timestamp("last_login_at", { withTimezone: true }),
  },
  (table) => [
    uniqueIndex("users_email_normalized_idx").on(table.emailNormalized),
  ],
);

/**
 * Server-side sessions.
 *
 * Only a SHA-256 of the session token is stored. A database disclosure
 * therefore does not hand an attacker usable session cookies, which is the
 * same reasoning that applies to password hashes.
 */
export const sessionsTable = pgTable(
  "sessions",
  {
    id: text("id").primaryKey(),
    tokenHash: text("token_hash").notNull(),
    userId: text("user_id")
      .notNull()
      .references(() => usersTable.id, { onDelete: "cascade" }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    lastSeenAt: timestamp("last_seen_at", { withTimezone: true }).notNull().defaultNow(),
    // Recorded for the audit trail; truncated and never used for authorization,
    // since both values are client-controlled.
    ipAddress: text("ip_address"),
    userAgent: text("user_agent"),
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
  },
  (table) => [
    uniqueIndex("sessions_token_hash_idx").on(table.tokenHash),
    index("sessions_user_id_idx").on(table.userId),
  ],
);

/**
 * Append-only audit trail. Rows are never updated or deleted by application
 * code; an audit log that can be edited is not an audit log.
 */
export const auditLogsTable = pgTable(
  "audit_logs",
  {
    id: text("id").primaryKey(),
    // Nullable: failed logins are recorded before any user is established, and
    // a deleted user must not erase their own history.
    userId: text("user_id"),
    userEmail: text("user_email"),
    action: text("action").notNull(),
    // Resource the action applied to, e.g. "scan:<id>" or "user:<id>".
    resource: text("resource"),
    outcome: text("outcome").notNull().default("success"),
    detail: text("detail"),
    ipAddress: text("ip_address"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    index("audit_logs_created_at_idx").on(table.createdAt),
    index("audit_logs_user_id_idx").on(table.userId),
    index("audit_logs_action_idx").on(table.action),
  ],
);

export type User = typeof usersTable.$inferSelect;
export type Session = typeof sessionsTable.$inferSelect;
export type AuditLog = typeof auditLogsTable.$inferSelect;
