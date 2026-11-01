/**
 * Role-based access control.
 *
 * The permission matrix below is the single source of truth. Routes ask
 * `can(role, permission)` rather than testing `role === "admin"` inline,
 * because scattered role comparisons are how authorization drifts out of sync
 * between endpoints.
 *
 * Default deny: an unknown role or unknown permission yields false.
 */

export const ROLES = ["admin", "analyst", "user"] as const;
export type Role = (typeof ROLES)[number];

export type Permission =
  // Scans
  | "scan:create"
  | "scan:read:own"
  | "scan:read:any"
  | "scan:delete:own"
  | "scan:delete:any"
  // Depth of analysis detail the role may see
  | "finding:read:technical"
  | "finding:read:simplified"
  | "report:download"
  // Administration
  | "user:manage"
  | "cve:manage"
  | "yara:manage"
  | "settings:manage"
  | "audit:read"
  | "stats:read:system";

const PERMISSIONS: Record<Role, readonly Permission[]> = {
  admin: [
    "scan:create",
    "scan:read:own",
    "scan:read:any",
    "scan:delete:own",
    "scan:delete:any",
    "finding:read:technical",
    "finding:read:simplified",
    "report:download",
    "user:manage",
    "cve:manage",
    "yara:manage",
    "settings:manage",
    "audit:read",
    "stats:read:system",
  ],
  analyst: [
    "scan:create",
    "scan:read:own",
    "scan:delete:own",
    "finding:read:technical",
    "finding:read:simplified",
    "report:download",
  ],
  user: [
    "scan:create",
    "scan:read:own",
    "scan:delete:own",
    // Deliberately NOT finding:read:technical — a general user sees the
    // simplified view only.
    "finding:read:simplified",
    "report:download",
  ],
};

export function isRole(value: unknown): value is Role {
  return typeof value === "string" && (ROLES as readonly string[]).includes(value);
}

/** Narrow an untrusted role string, falling back to the least-privileged role. */
export function assertRole(value: unknown): Role {
  return isRole(value) ? value : "user";
}

export function can(role: Role | string, permission: Permission): boolean {
  if (!isRole(role)) return false;
  return PERMISSIONS[role].includes(permission);
}

export function permissionsFor(role: Role | string): readonly Permission[] {
  return isRole(role) ? PERMISSIONS[role] : [];
}

/**
 * Whether `actor` may read a scan owned by `ownerId`.
 *
 * A scan with a null owner predates ownership tracking, so it is restricted to
 * admins. Treating it as public would retroactively expose every historical
 * scan the moment authentication was introduced.
 */
export function canAccessScan(
  actor: { id: string; role: Role | string },
  ownerId: string | null,
): boolean {
  if (can(actor.role, "scan:read:any")) return true;
  if (ownerId === null) return false;
  return ownerId === actor.id && can(actor.role, "scan:read:own");
}

export function canDeleteScan(
  actor: { id: string; role: Role | string },
  ownerId: string | null,
): boolean {
  if (can(actor.role, "scan:delete:any")) return true;
  if (ownerId === null) return false;
  return ownerId === actor.id && can(actor.role, "scan:delete:own");
}

/**
 * Roles a given actor is allowed to assign. Only admins manage roles at all,
 * and this is where privilege-escalation rules would be tightened further
 * (for example, preventing an admin from demoting the last remaining admin —
 * enforced separately in the user routes, which can count admins).
 */
export function assignableRoles(actorRole: Role | string): readonly Role[] {
  return can(actorRole, "user:manage") ? ROLES : [];
}
