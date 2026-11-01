/**
 * Authentication and authorization middleware, plus the audit trail.
 *
 * Every protected route goes through `requireAuth`; routes needing a specific
 * capability add `requirePermission(...)`. Neither ever inspects a role
 * directly — they delegate to the RBAC matrix.
 */

import type { NextFunction, Request, Response } from "express";
import { randomUUID } from "node:crypto";
import { db, auditLogsTable } from "@workspace/db";
import { logger } from "../logger";
import { can, type Permission } from "./rbac";
import { resolveSession, SESSION_COOKIE, type AuthenticatedUser } from "./sessions";

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      user?: AuthenticatedUser;
      sessionId?: string;
    }
  }
}

/** Read the session cookie without depending on cookie-parser being present. */
export function readSessionCookie(req: Request): string | undefined {
  const parsed = (req as Request & { cookies?: Record<string, string> }).cookies;
  if (parsed && typeof parsed[SESSION_COOKIE] === "string") return parsed[SESSION_COOKIE];

  const header = req.headers.cookie;
  if (!header) return undefined;
  for (const part of header.split(";")) {
    const separator = part.indexOf("=");
    if (separator === -1) continue;
    if (part.slice(0, separator).trim() === SESSION_COOKIE) {
      return decodeURIComponent(part.slice(separator + 1).trim());
    }
  }
  return undefined;
}

export function clientIp(req: Request): string | null {
  // req.ip already honours trust proxy when the app configures it. The
  // x-forwarded-for fallback is display-only and never used for authorization.
  const forwarded = req.headers["x-forwarded-for"];
  const raw = req.ip ?? (typeof forwarded === "string" ? forwarded.split(",")[0] : undefined);
  return raw ? raw.trim().slice(0, 64) : null;
}

/**
 * Record an audit event. Never throws: a failure to write the audit log must
 * not break the request, but it is logged loudly because a silently missing
 * audit trail is its own security problem.
 */
export async function audit(entry: {
  userId?: string | null;
  userEmail?: string | null;
  action: string;
  resource?: string | null;
  outcome?: "success" | "failure" | "denied";
  detail?: string | null;
  ipAddress?: string | null;
}): Promise<void> {
  try {
    await db.insert(auditLogsTable).values({
      id: randomUUID(),
      userId: entry.userId ?? null,
      userEmail: entry.userEmail ?? null,
      action: entry.action,
      resource: entry.resource ?? null,
      outcome: entry.outcome ?? "success",
      detail: entry.detail?.slice(0, 1000) ?? null,
      ipAddress: entry.ipAddress ?? null,
    });
  } catch (error) {
    logger.error({ err: error, action: entry.action }, "Audit log write failed");
  }
}

/** Attach the user when a valid session exists; never rejects. */
export async function attachUser(req: Request, _res: Response, next: NextFunction): Promise<void> {
  try {
    const session = await resolveSession(readSessionCookie(req));
    if (session) {
      req.user = session.user;
      req.sessionId = session.sessionId;
    }
  } catch (error) {
    logger.error({ err: error }, "Session resolution failed");
  }
  next();
}

export function requireAuth(req: Request, res: Response, next: NextFunction): void {
  if (!req.user) {
    res.status(401).json({ error: "Authentication is required.", code: "UNAUTHENTICATED" });
    return;
  }
  next();
}

/**
 * Require a capability. Denials are audited: a user repeatedly probing admin
 * endpoints is exactly the signal an audit log exists to surface.
 */
export function requirePermission(permission: Permission) {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({ error: "Authentication is required.", code: "UNAUTHENTICATED" });
      return;
    }
    if (!can(req.user.role, permission)) {
      void audit({
        userId: req.user.id,
        userEmail: req.user.email,
        action: "authorization.denied",
        resource: `${req.method} ${req.path}`,
        outcome: "denied",
        detail: `missing permission ${permission}`,
        ipAddress: clientIp(req),
      });
      // 403, not 404: the caller is authenticated and the resource class
      // exists. Per-resource existence is hidden by the scan routes instead.
      res.status(403).json({ error: "You do not have permission to perform this action.", code: "FORBIDDEN" });
      return;
    }
    next();
  };
}

/**
 * Fixed-window rate limiter for authentication endpoints, keyed by IP.
 *
 * In-memory, so it is per-instance: it raises the cost of online guessing but
 * is not a substitute for the per-account lockout in the users table, which is
 * durable and shared. Both are applied to the login route.
 */
interface RateWindow {
  count: number;
  resetAt: number;
}

const rateBuckets = new Map<string, RateWindow>();

export function rateLimit(options: { windowMs: number; max: number; key?: (req: Request) => string }) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const key = options.key?.(req) ?? clientIp(req) ?? "unknown";
    const now = Date.now();

    // Opportunistic sweep so the map cannot grow without bound.
    if (rateBuckets.size > 10_000) {
      for (const [bucketKey, window] of rateBuckets) {
        if (window.resetAt <= now) rateBuckets.delete(bucketKey);
      }
    }

    const existing = rateBuckets.get(key);
    if (!existing || existing.resetAt <= now) {
      rateBuckets.set(key, { count: 1, resetAt: now + options.windowMs });
      next();
      return;
    }

    existing.count += 1;
    if (existing.count > options.max) {
      const retryAfter = Math.ceil((existing.resetAt - now) / 1000);
      res.setHeader("Retry-After", String(retryAfter));
      res.status(429).json({
        error: "Too many attempts. Please wait before trying again.",
        code: "RATE_LIMITED",
      });
      return;
    }
    next();
  };
}

/** Reset between tests. */
export function __resetRateLimiter(): void {
  rateBuckets.clear();
}
