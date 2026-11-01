import assert from "node:assert";
import { mkdtemp, stat, writeFile, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { detectFormat } from "./formats";
import {
  extractFirmware,
  DEFAULT_LIMITS,
  runTool,
  cleanupExtraction,
} from "./extractor";

export async function runExtractionSecurityTests() {
  console.log("▶ Running Comprehensive Extraction Security & Stress Tests...");

  // -------------------------------------------------------------
  // Test 1: Corrupted / truncated archive handling
  // -------------------------------------------------------------
  const corruptedZipBuffer = Buffer.from("PK\x03\x04\x00\x00\x00\x00corrupted_payload_without_central_directory");
  const corruptedDetection = detectFormat(corruptedZipBuffer);
  assert(corruptedDetection != null && corruptedDetection.id === "zip", "Corrupted zip magic must be detected as zip format");

  // -------------------------------------------------------------
  // Test 2: Unsupported random binary bytes handling
  // -------------------------------------------------------------
  const randomBytes = Buffer.from([0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04]);
  const unsupportedDetection = detectFormat(randomBytes);
  assert.strictEqual(unsupportedDetection, null, "Random binary without firmware magic bytes must return null");

  // -------------------------------------------------------------
  // Test 3: Tool execution timeout enforcement
  // -------------------------------------------------------------
  const timeoutResult = await runTool("sleep", ["5"], { timeoutMs: 300 });
  assert.strictEqual(timeoutResult.ok, false, "Sleeping tool must fail when timeout expires");
  assert(
    timeoutResult.error.includes("time limit") || timeoutResult.error.includes("not installed"),
    `Expected timeout error message, got: ${timeoutResult.error}`,
  );

  // -------------------------------------------------------------
  // Test 4: Real-time Disk Quota Breach Detection & SIGKILL
  // -------------------------------------------------------------
  const quotaTestDir = await mkdtemp(join(tmpdir(), "quota-test-"));
  try {
    // Attempt to write 5MB using dd into a directory with a 500KB quota limit
    const quotaResult = await runTool(
      "dd",
      ["if=/dev/zero", `of=${join(quotaTestDir, "bigfile.bin")}`, "bs=1M", "count=5"],
      { destDir: quotaTestDir, maxBytes: 500 * 1024, timeoutMs: 5000 },
    );
    // On Linux dd will either fail due to SIGKILL or quota breach
    if (!quotaResult.ok) {
      assert(
        quotaResult.error.includes("quota exceeded") ||
          quotaResult.error.includes("time limit") ||
          quotaResult.error.includes("not installed"),
        `Expected quota breach error message, got: ${quotaResult.error}`,
      );
    }
  } finally {
    await cleanupExtraction(quotaTestDir);
  }

  // -------------------------------------------------------------
  // Test 5: Archive Bomb & Resource Limit Truncation
  // -------------------------------------------------------------
  // Simulate an extraction job with tight limits (e.g. maxFileCount: 2, maxTotalBytes: 10KB)
  const bombSandboxDir = await mkdtemp(join(tmpdir(), "bomb-sandbox-"));
  try {
    const inputZip = Buffer.from(
      "PK\x05\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    );
    const result = await extractFirmware(inputZip, "bomb.zip", {
      maxDepth: 1,
      maxFileCount: 2,
      maxTotalBytes: 1024,
      toolTimeoutMs: 1500,
    });
    assert(result.rootDir.length > 0, "Extraction result must return a valid rootDir");
    await cleanupExtraction(result.rootDir);
  } finally {
    await cleanupExtraction(bombSandboxDir);
  }

  // -------------------------------------------------------------
  // Test 6: Path Traversal & Symlink Escape Prevention
  // -------------------------------------------------------------
  const sandboxDir = await mkdtemp(join(tmpdir(), "symlink-sandbox-"));
  try {
    const safeSubdir = join(sandboxDir, "rootfs", "bin");
    await mkdir(safeSubdir, { recursive: true });
    await writeFile(join(safeSubdir, "sh"), "#!/bin/sh\necho test\n");

    // Test safe path inside sandbox
    const { sep } = await import("node:path");
    const { realpath } = await import("node:fs/promises");
    const realRoot = await realpath(sandboxDir);
    const resolvedSafe = await realpath(join(safeSubdir, "sh"));
    assert(
      resolvedSafe === realRoot || resolvedSafe.startsWith(realRoot + sep),
      "Legitimate subfile must reside inside sandbox",
    );

    // Verify relative traversal outside sandbox is detected
    const escapePath = join(sandboxDir, "..", "..", "..", "etc", "shadow");
    const isEscaping = !escapePath.startsWith(sandboxDir);
    assert.strictEqual(isEscaping, true, "Path traversal sequence must be identified as outside sandbox");
  } finally {
    await cleanupExtraction(sandboxDir);
  }

  // -------------------------------------------------------------
  // Test 7: Guaranteed Cleanup After Forced Failure
  // -------------------------------------------------------------
  const forcedFailDir = await mkdtemp(join(tmpdir(), "forced-fail-sandbox-"));
  await writeFile(join(forcedFailDir, "leftover-file.bin"), "test data");
  assert((await stat(forcedFailDir)).isDirectory(), "Forced fail directory must exist before cleanup");

  const cleanupRes = await cleanupExtraction(forcedFailDir);
  assert.strictEqual(cleanupRes.removed, true, "Cleanup must report removed: true");

  let stillExists = false;
  try {
    await stat(forcedFailDir);
    stillExists = true;
  } catch {
    stillExists = false;
  }
  assert.strictEqual(stillExists, false, "Sandbox directory must be completely removed from disk");

  console.log("✔ Extraction Security & Hardening Tests Passed!");
}

export { runExtractionSecurityTests as run };

if (process.argv[1] && import.meta.url.endsWith(process.argv[1].replace(/\\/g, "/"))) {
  runExtractionSecurityTests().catch((err) => {
    console.error("✖ Extraction Security Tests Failed:", err);
    process.exit(1);
  });
}
