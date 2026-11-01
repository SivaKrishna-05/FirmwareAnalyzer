/**
 * Server-side session management.
 *
 * The cookie carries an opaque 256-bit random token. Only its SHA-256 is
 * stored, so a database disclosure does not yield usable session cookies.
 * Sessions are revocable (logout, password change, admin action) which is the
 * main reason for choosing server-side sessions over stateless JWTs here.
 */

import { createHash, randomBytes, randomUUID } from "node:crypto";
import { and, eq, isNull, lt, gt } from "drizzle-orm";
import { db, sessionsTable, usersTable } from "@workspace/db";
import { assertRole, type Role } from "./rbac";

export const SESSION_COOKIE = "fwsa_session";
/** Absolute session lifetime. Idle timeout is enforced separately below. */
export const SESSION_TTL_MS = 12 * 60 * 60 * 1000;
/** A session unused for this long is rejected even if not yet expired. */
export const SESSION_IDLE_MS = 2 * 60 * 60 * 1000;

export interface AuthenticatedUser {
  id: string;
  email: string;
  name: string;
  role: Role;
}

export interface ActiveSession {
  sessionId: string;
  user: AuthenticatedUser;
}

export function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

/** Create a session and return the raw token — the only time it exists. */
export async function createSession(
  userId: string,
  context: { ipAddress?: string | null; userAgent?: string | null } = {},
): Promise<{ token: string; expiresAt: Date }> {
  const token = randomBytes(32).toString("base64url");
  const expiresAt = new Date(Date.now() + SESSION_TTL_MS);

  await db.insert(sessionsTable).values({
    id: randomUUID(),
    tokenHash: hashToken(token),
    userId,
    expiresAt,
    // Truncated: these are client-controlled and only ever used for display.
    ipAddress: context.ipAddress?.slice(0, 64) ?? null,
    userAgent: context.userAgent?.slice(0, 256) ?? null,
  });

  return { token, expiresAt };
}

/**
 * Resolve a raw token to an active session, or null.
 *
 * Returns null — never throws — for every rejection reason, so a caller
 * cannot accidentally distinguish "expired" from "revoked" from "forged".
 */
export async function resolveSession(token: string | undefined): Promise<ActiveSession | null> {
  if (!token || token.length < 16) return null;

  const rows = await db
    .select({
      sessionId: sessionsTable.id,
      expiresAt: sessionsTable.expiresAt,
      lastSeenAt: sessionsTable.lastSeenAt,
      revokedAt: sessionsTable.revokedAt,
      userId: usersTable.id,
      email: usersTable.email,
      name: usersTable.name,
      role: usersTable.role,
      disabled: usersTable.disabled,
    })
    .from(sessionsTable)
    .innerJoin(usersTable, eq(sessionsTable.userId, usersTable.id))
    .where(eq(sessionsTable.tokenHash, hashToken(token)));

  const row = rows[0];
  if (!row) return null;
  if (row.revokedAt !== null) return null;
  if (row.disabled === 1) return null;

  const now = Date.now();
  if (row.expiresAt.getTime() <= now) return null;
  if (now - row.lastSeenAt.getTime() > SESSION_IDLE_MS) {
    // Idle-expired sessions are revoked on sight rather than left to linger.
    await revokeSession(row.sessionId);
    return null;
  }

  // Sliding activity timestamp. Written at most once a minute to avoid a
  // database write on every single request.
  if (now - row.lastSeenAt.getTime() > 60_000) {
    await db
      .update(sessionsTable)
      .set({ lastSeenAt: new Date(now) })
      .where(eq(sessionsTable.id, row.sessionId));
  }

  return {
    sessionId: row.sessionId,
    user: {
      id: row.userId,
      email: row.email,
      name: row.name,
      role: assertRole(row.role),
    },
  };
}

export async function revokeSession(sessionId: string): Promise<void> {
  await db
    .update(sessionsTable)
    .set({ revokedAt: new Date() })
    .where(and(eq(sessionsTable.id, sessionId), isNull(sessionsTable.revokedAt)));
}

/** Revoke every session for a user — used on password change and lockout. */
export async function revokeAllUserSessions(userId: string): Promise<void> {
  await db
    .update(sessionsTable)
    .set({ revokedAt: new Date() })
    .where(and(eq(sessionsTable.userId, userId), isNull(sessionsTable.revokedAt)));
}

/** Housekeeping: drop sessions that expired some time ago. */
export async function purgeExpiredSessions(): Promise<number> {
  const cutoff = new Date(Date.now() - 24 * 60 * 60 * 1000);
  const removed = await db
    .delete(sessionsTable)
    .where(lt(sessionsTable.expiresAt, cutoff))
    .returning({ id: sessionsTable.id });
  return removed.length;
}

export async function countActiveSessions(userId: string): Promise<number> {
  const rows = await db
    .select({ id: sessionsTable.id })
    .from(sessionsTable)
    .where(
      and(
        eq(sessionsTable.userId, userId),
        isNull(sessionsTable.revokedAt),
        gt(sessionsTable.expiresAt, new Date()),
      ),
    );
  return rows.length;
}

/**
 * Cookie attributes.
 *
 * httpOnly blocks script access; sameSite=lax blocks cross-site form CSRF
 * while keeping normal top-level navigation working; secure is enabled
 * outside development, where the dev server is plain HTTP.
 */
export function sessionCookieOptions(expiresAt: Date): {
  httpOnly: true;
  sameSite: "lax";
  secure: boolean;
  path: string;
  expires: Date;
} {
  return {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    path: "/",
    expires: expiresAt,
  };
}
