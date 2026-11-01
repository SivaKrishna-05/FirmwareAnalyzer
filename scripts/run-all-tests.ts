import { performance } from "node:perf_hooks";

const SUITES = [
  { name: "CVE Matcher & Deduplication", path: "../artifacts/api-server/src/lib/analysis/cve/matcher.test" },
  { name: "CVE Integration & Local Version Range Matching", path: "../artifacts/api-server/src/lib/analysis/cve/cve-integration.test" },
  { name: "YARA Scanner & Rule Heuristics", path: "../artifacts/api-server/src/lib/analysis/yara/scanner.test" },
  { name: "YARA Findings API Schema Validation", path: "../artifacts/api-server/src/lib/analysis/yara/yara-api-validation.test" },
  { name: "Malware Risk Scorer Deduplication", path: "../artifacts/api-server/src/lib/analysis/malware-risk/scorer.test" },
  { name: "ML Malware Classifier & Benchmark Evaluation", path: "../artifacts/api-server/src/lib/analysis/ml-malware/classifier.test" },
  { name: "Extraction Limits, Sandboxing & Tool Timeout", path: "../artifacts/api-server/src/lib/extraction/extraction-security.test" },
  { name: "RBAC & Authorization User Isolation", path: "../artifacts/api-server/src/lib/auth/authorization.test" },
  { name: "PDF Security Report Generation", path: "../artifacts/api-server/src/lib/reports/pdf-report.test" },
  { name: "Genuine Firmware Sample & Real Binary Analysis", path: "../artifacts/api-server/src/lib/analysis/genuine-firmware.test" },
];

async function main() {
  console.log("==========================================================");
  console.log("      RUNNING IOT FIRMWARE SECURITY ANALYZER TEST SUITE    ");
  console.log("==========================================================\n");

  const startTotal = performance.now();
  let passedCount = 0;

  for (let i = 0; i < SUITES.length; i++) {
    const suite = SUITES[i];
    process.stdout.write(`[${i + 1}/${SUITES.length}] Suite: ${suite.name}... `);
    const startSuite = performance.now();
    try {
      const mod = await import(suite.path);
      if (typeof mod.run === "function") {
        await mod.run();
      } else if (typeof mod.default === "function") {
        await mod.default();
      } else {
        throw new Error(`Test suite "${suite.name}" does not export a run() function!`);
      }
      const elapsed = (performance.now() - startSuite).toFixed(0);
      console.log(`PASSED (${elapsed}ms)`);
      passedCount++;
    } catch (err) {
      console.log("FAILED");
      console.error(err);
      process.exit(1);
    }
  }

  const totalElapsed = ((performance.now() - startTotal) / 1000).toFixed(2);
  console.log("\n==========================================================");
  console.log(`  ALL ${passedCount}/${SUITES.length} TEST SUITES EXECUTED AND PASSED SUCCESSFULLY (${totalElapsed}s)  `);
  console.log("==========================================================\n");
}

main().catch((err) => {
  console.error("Test runner execution error:", err);
  process.exit(1);
});
