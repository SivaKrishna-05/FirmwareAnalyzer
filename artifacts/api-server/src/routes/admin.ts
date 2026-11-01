import { Router, type IRouter } from "express";
import express from "express";
import { randomUUID } from "node:crypto";
import { and, desc, eq, sql } from "drizzle-orm";
import { db, auditLogsTable, scansTable, userSettingsTable, usersTable, vulnerabilityFindingsTable } from "@workspace/db";
import { z } from "zod";
import { checkPasswordPolicy, hashPassword } from "../lib/auth/passwords";
import { revokeAllUserSessions } from "../lib/auth/sessions";
import { audit, clientIp, requireAuth, requirePermission } from "../lib/auth/middleware";
import { assertRole, ROLES } from "../lib/auth/rbac";
import { logger } from "../lib/logger";

const router: IRouter = Router();

const CreateUserBody = z.object({
  email: z.string().trim().email().max(320),
  name: z.string().trim().min(1).max(120),
  password: z.string().min(1).max(512),
  role: z.enum(ROLES),
});

const UpdateUserBody = z.object({
  role: z.enum(ROLES).optional(),
  disabled: z.boolean().optional(),
  name: z.string().trim().min(1).max(120).optional(),
});

/** Number of enabled admins — used to prevent locking everyone out. */
async function activeAdminCount(): Promise<number> {
  const [row] = await db
    .select({ count: sql<number>`count(*)::int` })
    .from(usersTable)
    .where(and(eq(usersTable.role, "admin"), eq(usersTable.disabled, 0)));
  return row?.count ?? 0;
}

router.get("/admin/users", requireAuth, requirePermission("user:manage"), async (_req, res): Promise<void> => {
  const users = await db.select().from(usersTable).orderBy(desc(usersTable.createdAt));
  // Password material is never included in a response, not even to an admin.
  res.json(
    users.map((user: any) => ({
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      disabled: user.disabled === 1,
      createdAt: user.createdAt,
      lastLoginAt: user.lastLoginAt,
      locked: user.lockedUntil !== null && user.lockedUntil.getTime() > Date.now(),
    })),
  );
});

router.post(
  "/admin/users",
  express.json({ limit: "16kb" }),
  requireAuth,
  requirePermission("user:manage"),
  async (req, res): Promise<void> => {
    const parsed = CreateUserBody.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: "A valid email, name, password and role are required.", code: "INVALID_INPUT" });
      return;
    }
    const actor = req.user!;
    const emailNormalized = parsed.data.email.trim().toLowerCase();

    const [existing] = await db.select().from(usersTable).where(eq(usersTable.emailNormalized, emailNormalized));
    if (existing) {
      res.status(409).json({ error: "An account with that email already exists.", code: "EMAIL_TAKEN" });
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
      emailNormalized,
      name: parsed.data.name.trim(),
      role: parsed.data.role,
      passwordHash: hashed.hash,
      passwordSalt: hashed.salt,
      passwordParams: hashed.params,
    });

    await audit({
      userId: actor.id,
      userEmail: actor.email,
      action: "admin.user_create",
      resource: `user:${id}`,
      detail: `created ${parsed.data.email.trim()} with role ${parsed.data.role}`,
      ipAddress: clientIp(req),
    });
    res.status(201).json({ id, email: parsed.data.email.trim(), name: parsed.data.name.trim(), role: parsed.data.role });
  },
);

router.patch(
  "/admin/users/:userId",
  express.json({ limit: "16kb" }),
  requireAuth,
  requirePermission("user:manage"),
  async (req, res): Promise<void> => {
    const parsed = UpdateUserBody.safeParse(req.body);
    const userId = String(req.params.userId ?? "");
    if (!parsed.success || userId.length === 0) {
      res.status(400).json({ error: "A valid update payload is required.", code: "INVALID_INPUT" });
      return;
    }
    const actor = req.user!;
    const [target] = await db.select().from(usersTable).where(eq(usersTable.id, userId));
    if (!target) {
      res.status(404).json({ error: "User not found.", code: "USER_NOT_FOUND" });
      return;
    }

    const demotingAdmin =
      target.role === "admin" &&
      ((parsed.data.role !== undefined && parsed.data.role !== "admin") || parsed.data.disabled === true);

    // Refuse to remove the last usable admin, which would leave the system
    // with no way to manage users at all.
    if (demotingAdmin && (await activeAdminCount()) <= 1) {
      res.status(409).json({
        error: "This is the last active administrator. Promote another admin before changing this account.",
        code: "LAST_ADMIN",
      });
      return;
    }

    // Self-demotion and self-disable are blocked as a footgun guard; another
    // admin can still perform the change.
    if (target.id === actor.id && (parsed.data.role !== undefined && parsed.data.role !== "admin")) {
      res.status(409).json({ error: "You cannot change your own role.", code: "SELF_ROLE_CHANGE" });
      return;
    }
    if (target.id === actor.id && parsed.data.disabled === true) {
      res.status(409).json({ error: "You cannot disable your own account.", code: "SELF_DISABLE" });
      return;
    }

    const updates: Record<string, unknown> = {};
    if (parsed.data.role !== undefined) updates.role = assertRole(parsed.data.role);
    if (parsed.data.name !== undefined) updates.name = parsed.data.name;
    if (parsed.data.disabled !== undefined) updates.disabled = parsed.data.disabled ? 1 : 0;
    if (Object.keys(updates).length === 0) {
      res.status(400).json({ error: "No changes were supplied.", code: "INVALID_INPUT" });
      return;
    }

    await db.update(usersTable).set(updates).where(eq(usersTable.id, userId));

    // A role change or disable must take effect immediately, so existing
    // sessions for that user are revoked rather than retaining old privileges.
    if (parsed.data.role !== undefined || parsed.data.disabled !== undefined) {
      await revokeAllUserSessions(userId);
    }

    await audit({
      userId: actor.id,
      userEmail: actor.email,
      action: "admin.user_update",
      resource: `user:${userId}`,
      detail: JSON.stringify(updates),
      ipAddress: clientIp(req),
    });
    res.json({ ok: true });
  },
);

router.get("/admin/stats", requireAuth, requirePermission("stats:read:system"), async (_req, res): Promise<void> => {
  const [users] = await db.select({ count: sql<number>`count(*)::int` }).from(usersTable);
  const [scans] = await db.select({ count: sql<number>`count(*)::int` }).from(scansTable);
  const [highRisk] = await db
    .select({ count: sql<number>`count(*)::int` })
    .from(scansTable)
    .where(eq(scansTable.riskLevel, "HIGH"));
  const [criticalRisk] = await db
    .select({ count: sql<number>`count(*)::int` })
    .from(scansTable)
    .where(eq(scansTable.riskLevel, "CRITICAL"));
  const [findings] = await db.select({ count: sql<number>`count(*)::int` }).from(vulnerabilityFindingsTable);
  const [cveCount] = await db
    .select({ count: sql<number>`count(*)::int` })
    .from(vulnerabilityFindingsTable)
    .where(sql`cve IS NOT NULL`);
  const [yaraCount] = await db
    .select({ count: sql<number>`count(*)::int` })
    .from(vulnerabilityFindingsTable)
    .where(eq(vulnerabilityFindingsTable.detectionSource, "YARA Scanner"));
  const [mlCount] = await db
    .select({ count: sql<number>`count(*)::int` })
    .from(vulnerabilityFindingsTable)
    .where(eq(vulnerabilityFindingsTable.detectionSource, "ML Malware Classifier"));

  const { getLocalCveStatus } = await import("../lib/analysis/cve/local-cve-db");
  const cveStatus = await getLocalCveStatus();

  res.json({
    users: users?.count ?? 0,
    totalScans: scans?.count ?? 0,
    highRiskScans: highRisk?.count ?? 0,
    criticalScans: criticalRisk?.count ?? 0,
    vulnerabilityFindings: findings?.count ?? 0,
    cveFindings: cveCount?.count ?? 0,
    yaraMatches: yaraCount?.count ?? 0,
    mlDetections: mlCount?.count ?? 0,
    localCveCount: cveStatus.totalCount,
    capabilityNote: "All security engines (Static Heuristics, YARA, ML Malware Classifier, and Local CVE Database) are active.",
  });
});

router.get("/admin/cve/status", requireAuth, requirePermission("cve:manage"), async (_req, res): Promise<void> => {
  const { getLocalCveStatus } = await import("../lib/analysis/cve/local-cve-db");
  const status = await getLocalCveStatus();
  res.json(status);
});

router.post("/admin/cve/update", requireAuth, requirePermission("cve:manage"), async (req, res): Promise<void> => {
  const { syncCveDatabase } = await import("../lib/analysis/cve/local-cve-db");
  const result = await syncCveDatabase();
  await audit({
    userId: req.user!.id,
    userEmail: req.user!.email,
    action: "admin.cve_update",
    resource: "cve:database",
    detail: "Triggered background synchronization of CVE vulnerability database",
    ipAddress: clientIp(req),
  });
  res.json({ started: result.started, alreadyRunning: result.alreadyRunning, message: result.message || "CVE database update initiated" });
});

router.get("/admin/audit", requireAuth, requirePermission("audit:read"), async (req, res): Promise<void> => {
  const limit = Math.min(Math.max(Number.parseInt(String(req.query.limit ?? "100"), 10) || 100, 1), 500);
  const entries = await db.select().from(auditLogsTable).orderBy(desc(auditLogsTable.createdAt)).limit(limit);
  res.json(
    entries.map((entry: any) => ({
      id: entry.id,
      userEmail: entry.userEmail,
      action: entry.action,
      resource: entry.resource,
      outcome: entry.outcome,
      detail: entry.detail,
      ipAddress: entry.ipAddress,
      createdAt: entry.createdAt,
    })),
  );
});

const UpdateSettingsBody = z.object({
  telemetry: z.boolean().optional(),
  deepAnalysis: z.boolean().optional(),
});

router.get("/settings", requireAuth, async (req, res): Promise<void> => {
  const userId = req.user!.id;
  try {
    const [row] = await db.select().from(userSettingsTable).where(eq(userSettingsTable.userId, userId));
    if (!row) {
      res.json({ telemetry: false, deepAnalysis: true });
      return;
    }
    res.json({ telemetry: Boolean(row.telemetry), deepAnalysis: Boolean(row.deepAnalysis) });
  } catch (err) {
    logger.error({ err, userId }, "Failed to fetch user settings");
    res.status(500).json({ error: "Failed to fetch settings", code: "SETTINGS_FETCH_FAILED" });
  }
});

router.patch(
  "/settings",
  express.json({ limit: "16kb" }),
  requireAuth,
  async (req, res): Promise<void> => {
    const parsed = UpdateSettingsBody.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: "Invalid settings parameters", code: "INVALID_INPUT" });
      return;
    }
    const userId = req.user!.id;
    const { telemetry, deepAnalysis } = parsed.data;

    try {
      const [existing] = await db.select().from(userSettingsTable).where(eq(userSettingsTable.userId, userId));
      const nextTelemetry = telemetry ?? existing?.telemetry ?? false;
      const nextDeep = deepAnalysis ?? existing?.deepAnalysis ?? true;

      await db
        .insert(userSettingsTable)
        .values({
          userId,
          telemetry: nextTelemetry,
          deepAnalysis: nextDeep,
          updatedAt: new Date(),
        })
        .onConflictDoUpdate({
          target: userSettingsTable.userId,
          set: {
            telemetry: nextTelemetry,
            deepAnalysis: nextDeep,
            updatedAt: new Date(),
          },
        });
      res.json({ telemetry: nextTelemetry, deepAnalysis: nextDeep });
    } catch (err) {
      logger.error({ err, userId }, "Failed to update user settings");
      res.status(500).json({ error: "Could not save settings", code: "SETTINGS_SAVE_FAILED" });
    }
  },
);

export default router;
