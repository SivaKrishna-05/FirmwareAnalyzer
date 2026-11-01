import assert from "node:assert";
import { can, canAccessScan, canDeleteScan, type Role } from "./rbac";

export async function runAuthorizationTests() {
  console.log("▶ Running RBAC & Authorization Access Control Tests...");

  const adminUser = { id: "user-admin-1", role: "admin" as Role };
  const analystUser = { id: "user-analyst-1", role: "analyst" as Role };
  const ordinaryUserAlice = { id: "user-alice-1", role: "user" as Role };
  const ordinaryUserBob = { id: "user-bob-2", role: "user" as Role };

  // -------------------------------------------------------------
  // Test 1: Administrative CVE Synchronization Permission
  // -------------------------------------------------------------
  assert.strictEqual(
    can(ordinaryUserAlice.role, "cve:manage"),
    false,
    "Ordinary users MUST NOT have cve:manage permission",
  );
  assert.strictEqual(
    can(analystUser.role, "cve:manage"),
    false,
    "Analysts MUST NOT have cve:manage permission",
  );
  assert.strictEqual(
    can(adminUser.role, "cve:manage"),
    true,
    "Administrators MUST have cve:manage permission",
  );

  // -------------------------------------------------------------
  // Test 2: User Isolation - Accessing Other Users' Scans
  // -------------------------------------------------------------
  // Alice owns scanA
  const scanA_OwnerId = ordinaryUserAlice.id;
  // Bob owns scanB
  const scanB_OwnerId = ordinaryUserBob.id;

  // Alice can access Alice's scan
  assert.strictEqual(
    canAccessScan(ordinaryUserAlice, scanA_OwnerId),
    true,
    "Alice MUST be able to access her own scan",
  );

  // Bob CANNOT access Alice's scan
  assert.strictEqual(
    canAccessScan(ordinaryUserBob, scanA_OwnerId),
    false,
    "Bob MUST NOT be able to access Alice's scan",
  );

  // Alice CANNOT access Bob's scan
  assert.strictEqual(
    canAccessScan(ordinaryUserAlice, scanB_OwnerId),
    false,
    "Alice MUST NOT be able to access Bob's scan",
  );

  // Admin CAN access both Alice's and Bob's scans
  assert.strictEqual(
    canAccessScan(adminUser, scanA_OwnerId),
    true,
    "Administrator MUST have access to inspect Alice's scan",
  );
  assert.strictEqual(
    canAccessScan(adminUser, scanB_OwnerId),
    true,
    "Administrator MUST have access to inspect Bob's scan",
  );

  // Unowned legacy scan (ownerId === null) is restricted to admin
  assert.strictEqual(
    canAccessScan(ordinaryUserAlice, null),
    false,
    "Ordinary users MUST NOT be able to access unowned/unassigned scans",
  );
  assert.strictEqual(
    canAccessScan(adminUser, null),
    true,
    "Administrators MUST be able to access unowned scans",
  );

  // -------------------------------------------------------------
  // Test 3: User Isolation - Deleting Scans
  // -------------------------------------------------------------
  assert.strictEqual(
    canDeleteScan(ordinaryUserAlice, scanA_OwnerId),
    true,
    "Alice MUST be able to delete her own scan",
  );
  assert.strictEqual(
    canDeleteScan(ordinaryUserBob, scanA_OwnerId),
    false,
    "Bob MUST NOT be able to delete Alice's scan",
  );
  assert.strictEqual(
    canDeleteScan(adminUser, scanA_OwnerId),
    true,
    "Admin MUST be able to delete any scan",
  );

  // -------------------------------------------------------------
  // Test 4: Administration & User Management Permissions
  // -------------------------------------------------------------
  assert.strictEqual(can(ordinaryUserAlice.role, "user:manage"), false);
  assert.strictEqual(can(analystUser.role, "user:manage"), false);
  assert.strictEqual(can(adminUser.role, "user:manage"), true);

  // -------------------------------------------------------------
  // Test 5: Audit Log & System Statistics Read Access
  // -------------------------------------------------------------
  assert.strictEqual(can(ordinaryUserAlice.role, "audit:read"), false);
  assert.strictEqual(can(ordinaryUserAlice.role, "stats:read:system"), false);
  assert.strictEqual(can(adminUser.role, "audit:read"), true);
  assert.strictEqual(can(adminUser.role, "stats:read:system"), true);

  // -------------------------------------------------------------
  // Test 6: Technical Findings Depth
  // -------------------------------------------------------------
  // Ordinary users get simplified findings; only analysts/admins see raw technical details
  assert.strictEqual(can(ordinaryUserAlice.role, "finding:read:simplified"), true);
  assert.strictEqual(can(ordinaryUserAlice.role, "finding:read:technical"), false);
  assert.strictEqual(can(analystUser.role, "finding:read:technical"), true);
  assert.strictEqual(can(adminUser.role, "finding:read:technical"), true);

  console.log("✔ RBAC & Authorization Tests Passed Successfully!");
}

export { runAuthorizationTests as run };

if (process.argv[1] && import.meta.url.endsWith(process.argv[1].replace(/\\/g, "/"))) {
  runAuthorizationTests().catch((err) => {
    console.error("✖ Authorization Tests Failed:", err);
    process.exit(1);
  });
}
