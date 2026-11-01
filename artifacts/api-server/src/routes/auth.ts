import { Router, type IRouter } from "express";
import express from "express";
import { randomUUID } from "node:crypto";
import { eq, sql } from "drizzle-orm";
import { db, usersTable } from "@workspace/db";
import { z } from "zod";
import {
  checkPasswordPolicy,
  DEFAULT_PASSWORD_PARAMS,
  dummyVerify,
  hashPassword,
  needsRehash,
  verifyPassword,
} from "../lib/auth/passwords";
import {
  createSession,
  revokeAllUserSessions,
  revokeSession,
  SESSION_COOKIE,
  sessionCookieOptions,
} from "../lib/auth/sessions";
import { audit, clientIp, rateLimit, requireAuth } from "../lib/auth/middleware";
import { permissionsFor } from "../lib/auth/rbac";
import { logger } from "../lib/logger";

const router: IRouter = Router();

/** Account lockout thresholds — durable, unlike the per-IP rate limiter. */
const MAX_FAILED_LOGINS = 8;
const LOCKOUT_MS = 15 * 60 * 1000;

const LoginBody = z.object({
  email: z.string().trim().min(3).max(320),
  password: z.string().min(1).max(512),
});

const RegisterBody = z.object({
  email: z.string().trim().email().max(320),
  name: z.string().trim().min(1).max(120),
  password: z.string().min(1).max(512),
});

const ChangePasswordBody = z.object({
  currentPassword: z.string().min(1).max(512),
  newPassword: z.string().min(1).max(512),
});

function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

/**
 * A single generic message for every login failure.
 *
 * Distinguishing "no such user" from "wrong password" would let an attacker
 * enumerate accounts; the constant-time dummy hash in the handler closes the
 * timing side of the same leak.
 */
const GENERIC_LOGIN_FAILURE = "Email or password is incorrect.";

router.post(
  "/auth/login",
  express.json({ limit: "16kb" }),
  rateLimit({ windowMs: 15 * 60 * 1000, max: 20 }),
  async (req, res): Promise<void> => {
    const parsed = LoginBody.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: GENERIC_LOGIN_FAILURE, code: "INVALID_CREDENTIALS" });
      return;
    }

    const email = normalizeEmail(parsed.data.email);
    const ipAddress = clientIp(req);
    const [user] = await db.select().from(usersTable).where(eq(usersTable.emailNormalized, email));

    if (!user) {
      // Spend the same CPU as a real verification so timing does not reveal
      // that the account is absent.
      await dummyVerify();
      await audit({ userEmail: email, action: "auth.login", outcome: "failure", detail: "unknown account", ipAddress });
      res.status(401).json({ error: GENERIC_LOGIN_FAILURE, code: "INVALID_CREDENTIALS" });
      return;
    }

    if (user.disabled === 1) {
      await dummyVerify();
      await audit({ userId: user.id, userEmail: user.email, action: "auth.login", outcome: "denied", detail: "account disabled", ipAddress });
      res.status(401).json({ error: GENERIC_LOGIN_FAILURE, code: "INVALID_CREDENTIALS" });
      return;
    }

    if (user.lockedUntil && user.lockedUntil.getTime() > Date.now()) {
      await dummyVerify();
      await audit({ userId: user.id, userEmail: user.email, action: "auth.login", outcome: "denied", detail: "account locked", ipAddress });
      const retryAfter = Math.ceil((user.lockedUntil.getTime() - Date.now()) / 1000);
      res.setHeader("Retry-After", String(retryAfter));
      res.status(429).json({
        error: "This account is temporarily locked after repeated failed sign-ins. Try again later.",
        code: "ACCOUNT_LOCKED",
      });
      return;
    }

    const valid = await verifyPassword(parsed.data.password, {
      hash: user.passwordHash,
      salt: user.passwordSalt,
      params: user.passwordParams,
    });

    if (!valid) {
      const failures = user.failedLoginCount + 1;
      const shouldLock = failures >= MAX_FAILED_LOGINS;
      await db
        .update(usersTable)
        .set({
          failedLoginCount: failures,
          lockedUntil: shouldLock ? new Date(Date.now() + LOCKOUT_MS) : user.lockedUntil,
        })
        .where(eq(usersTable.id, user.id));

      if (shouldLock) {
        // Existing sessions are cut as well: repeated failures may mean the
        // account is under attack, and a live session would survive lockout.
        await revokeAllUserSessions(user.id);
      }
      await audit({
        userId: user.id,
        userEmail: user.email,
        action: "auth.login",
        outcome: "failure",
        detail: shouldLock ? `bad password; account locked after ${failures} attempts` : `bad password (${failures})`,
        ipAddress,
      });
      res.status(401).json({ error: GENERIC_LOGIN_FAILURE, code: "INVALID_CREDENTIALS" });
      return;
    }

    // Successful login: clear lockout state and upgrade the hash if the cost
    // parameters have been raised since it was created.
    const updates: Record<string, unknown> = {
      failedLoginCount: 0,
      lockedUntil: null,
      lastLoginAt: new Date(),
    };
    if (needsRehash(user.passwordParams)) {
      const rehashed = await hashPassword(parsed.data.password, DEFAULT_PASSWORD_PARAMS);
      updates.passwordHash = rehashed.hash;
      updates.passwordSalt = rehashed.salt;
      updates.passwordParams = rehashed.params;
      logger.info({ userId: user.id }, "Password hash upgraded to current parameters");
    }
    await db.update(usersTable).set(updates).where(eq(usersTable.id, user.id));

    const { token, expiresAt } = await createSession(user.id, {
      ipAddress,
      userAgent: req.headers["user-agent"] ?? null,
    });
    res.cookie(SESSION_COOKIE, token, sessionCookieOptions(expiresAt));
    await audit({ userId: user.id, userEmail: user.email, action: "auth.login", outcome: "success", ipAddress });

    res.json({
      authenticated: true,
      user: { id: user.id, name: user.name, email: user.email, role: user.role },
      permissions: permissionsFor(user.role),
    });
  },
);

/**
 * Bootstrap registration.
 *
 * Open self-registration is disabled: the FIRST account created becomes the
 * admin, and every subsequent account must be created by an admin through
 * /admin/users. This avoids shipping a default credential (the usual way
 * these projects get compromised) while still allowing a clean first run.
 */
router.post(
  "/auth/register",
  express.json({ limit: "16kb" }),
  rateLimit({ windowMs: 60 * 60 * 1000, max: 10 }),
  async (req, res): Promise<void> => {
    const parsed = RegisterBody.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: "A valid email, name and password are required.", code: "INVALID_INPUT" });
      return;
    }

    const [{ count }] = await db.select({ count: sql<number>`count(*)::int` }).from(usersTable);
    if (count > 0) {
      await audit({
        userEmail: normalizeEmail(parsed.data.email),
        action: "auth.register",
        outcome: "denied",
        detail: "self-registration is closed; users are created by an admin",
        ipAddress: clientIp(req),
      });
      res.status(403).json({
        error: "Self-registration is disabled. Ask an administrator to create your account.",
        code: "REGISTRATION_CLOSED",
      });
      return;
    }

    const policy = checkPasswordPolicy(parsed.data.password, { email: parsed.data.email, name: parsed.data.name });
    if (!policy.ok) {
      res.status(400).json({ error: `Password ${policy.problems.join(", ")}.`, code: "WEAK_PASSWORD" });
      return;
    }

    const hashed = await hashPassword(parsed.data.password);
    const id = randomUUID();
    await db.insert(usersTable).values({
      id,
      email: parsed.data.email.trim(),
      emailNormalized: normalizeEmail(parsed.data.email),
      name: parsed.data.name.trim(),
      // First account bootstraps the system and therefore must be an admin.
      role: "admin",
      passwordHash: hashed.hash,
      passwordSalt: hashed.salt,
      passwordParams: hashed.params,
    });

    await audit({ userId: id, userEmail: parsed.data.email, action: "auth.register", outcome: "success", detail: "initial admin account", ipAddress: clientIp(req) });
    res.status(201).json({ id, email: parsed.data.email.trim(), name: parsed.data.name.trim(), role: "admin" });
  },
);

router.post("/auth/logout", async (req, res): Promise<void> => {
  if (req.sessionId) {
    await revokeSession(req.sessionId);
    await audit({ userId: req.user?.id, userEmail: req.user?.email, action: "auth.logout", ipAddress: clientIp(req) });
  }
  res.clearCookie(SESSION_COOKIE, { path: "/" });
  res.json({ authenticated: false });
});

router.get("/session", async (req, res): Promise<void> => {
  if (!req.user) {
    // Tell the client whether ANY account exists, so a first run can show the
    // bootstrap form instead of an unusable login form. This leaks only
    // "the system is uninitialised", which is not sensitive — and once the
    // first admin exists the flag is permanently false.
    const [{ count }] = await db.select({ count: sql<number>`count(*)::int` }).from(usersTable);
    // 200 with authenticated:false, so the client can render a login screen
    // without treating an anonymous visit as an error.
    res.json({ authenticated: false, user: null, permissions: [], needsBootstrap: count === 0 });
    return;
  }
  res.json({
    authenticated: true,
    user: req.user,
    permissions: permissionsFor(req.user.role),
    needsBootstrap: false,
  });
});

router.post(
  "/auth/password",
  express.json({ limit: "16kb" }),
  requireAuth,
  rateLimit({ windowMs: 15 * 60 * 1000, max: 10 }),
  async (req, res): Promise<void> => {
    const parsed = ChangePasswordBody.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: "Current and new passwords are required.", code: "INVALID_INPUT" });
      return;
    }
    const actor = req.user!;
    const [user] = await db.select().from(usersTable).where(eq(usersTable.id, actor.id));
    if (!user) {
      res.status(401).json({ error: "Authentication is required.", code: "UNAUTHENTICATED" });
      return;
    }

    const valid = await verifyPassword(parsed.data.currentPassword, {
      hash: user.passwordHash,
      salt: user.passwordSalt,
      params: user.passwordParams,
    });
    if (!valid) {
      await audit({ userId: user.id, userEmail: user.email, action: "auth.password_change", outcome: "failure", detail: "current password incorrect", ipAddress: clientIp(req) });
      res.status(401).json({ error: "Your current password is incorrect.", code: "INVALID_CREDENTIALS" });
      return;
    }

    const policy = checkPasswordPolicy(parsed.data.newPassword, { email: user.email, name: user.name });
    if (!policy.ok) {
      res.status(400).json({ error: `Password ${policy.problems.join(", ")}.`, code: "WEAK_PASSWORD" });
      return;
    }

    const hashed = await hashPassword(parsed.data.newPassword);
    await db
      .update(usersTable)
      .set({ passwordHash: hashed.hash, passwordSalt: hashed.salt, passwordParams: hashed.params })
      .where(eq(usersTable.id, user.id));

    // Every other session is invalidated: if the password was changed because
    // it may have leaked, leaving old sessions alive would defeat the change.
    await revokeAllUserSessions(user.id);
    const { token, expiresAt } = await createSession(user.id, {
      ipAddress: clientIp(req),
      userAgent: req.headers["user-agent"] ?? null,
    });
    res.cookie(SESSION_COOKIE, token, sessionCookieOptions(expiresAt));

    await audit({ userId: user.id, userEmail: user.email, action: "auth.password_change", outcome: "success", detail: "all other sessions revoked", ipAddress: clientIp(req) });
    res.json({ ok: true, message: "Password updated. All other sessions have been signed out." });
  },
);

export default router;
