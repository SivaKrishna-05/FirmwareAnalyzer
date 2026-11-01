import assert from "node:assert";
import { matchCvesForComponents } from "./matcher";

export async function runCveMatcherTests() {
  console.log("▶ Running CVE Matcher Tests...");

  // Test empty component array
  const emptyRes = await matchCvesForComponents([]);
  assert.strictEqual(emptyRes.matches.length, 0);
  assert.strictEqual(emptyRes.checkedCount, 0);

  // Test busybox matching
  const busyboxRes = await matchCvesForComponents([{ name: "busybox", version: "1.35.0", source: "binary" }]);
  assert.strictEqual(busyboxRes.checkedCount, 1);
  assert(busyboxRes.matches.length > 0, "Expected at least one CVE match for BusyBox 1.35.0");

  const cveMatch = busyboxRes.matches[0];
  assert(cveMatch.cveId.startsWith("CVE-"));
  assert.strictEqual(cveMatch.component, "busybox");

  console.log("✔ CVE Matcher Tests Passed!");
}

export { runCveMatcherTests as run };

if (process.argv[1] && import.meta.url.endsWith(process.argv[1].replace(/\\/g, "/"))) {
  runCveMatcherTests().catch((err) => {
    console.error("✖ CVE Matcher Tests Failed:", err);
    process.exit(1);
  });
}
