import assert from "node:assert";
import { GetScanResponse, ListScanVulnerabilitiesResponse } from "@workspace/api-zod";

export async function runYaraApiValidationTests() {
  console.log("▶ Running YARA API Response Validation Tests...");

  // Mock scan detail containing YARA-detected findings
  const mockScanDetail = {
    id: "test-scan-yara-123",
    firmwareName: "iot_firmware.bin",
    firmwareType: "ZIP archive",
    sizeBytes: 1048576,
    status: "Analysis Completed" as const,
    riskScore: 95,
    riskLevel: "CRITICAL" as const,
    vulnerabilityCount: 2,
    malwareIndicatorCount: 2,
    createdAt: new Date().toISOString(),
    completedAt: new Date().toISOString(),
    architecture: "ARM",
    operatingSystem: "Linux",
    filesystem: "SquashFS",
    extractionStatus: "Extracted 1 layer",
    extractionMethod: "unsquashfs",
    extractedFileCount: 42,
    extractionDepth: 1,
    extractionNotes: null,
    sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    findings: [
      {
        id: "test-scan-yara-123-1",
        category: "Dangerous Commands/Code Execution Indicators" as const,
        title: "Mirai Botnet Indicators hit on /bin/busybox",
        severity: "Critical" as const,
        affectedPath: "/bin/busybox",
        description: "YARA rule matched Mirai botnet signatures.",
        evidence: "YARA Rule [YARA_MIRAI_STRINGS] matched",
        confidence: "high" as const,
        recommendation: "Quarantine infected binary.",
        cve: null,
        component: null,
        componentVersion: null,
        detectionSource: "YARA Scanner",
      },
      {
        id: "test-scan-yara-123-2",
        category: "Hardcoded Credentials" as const,
        title: "Embedded Root / Backdoor Credentials hit on /etc/shadow",
        severity: "High" as const,
        affectedPath: "/etc/shadow",
        description: "YARA rule matched embedded credentials pattern.",
        evidence: "root:$1$admin",
        confidence: "high" as const,
        recommendation: "Rotate credentials immediately.",
        cve: null,
        component: null,
        componentVersion: null,
        detectionSource: "YARA Scanner",
      },
    ],
  };

  // Test 1: GetScanResponse parses scan containing YARA findings without error
  const parsedDetail = GetScanResponse.parse(mockScanDetail);
  assert.strictEqual(parsedDetail.id, "test-scan-yara-123");
  assert.strictEqual(parsedDetail.findings.length, 2);
  assert.strictEqual(parsedDetail.findings[0].detectionSource, "YARA Scanner");
  assert.strictEqual(parsedDetail.findings[0].category, "Dangerous Commands/Code Execution Indicators");

  // Test 2: ListScanVulnerabilitiesResponse parses YARA findings array
  const parsedVulns = ListScanVulnerabilitiesResponse.parse(mockScanDetail.findings);
  assert.strictEqual(parsedVulns.length, 2);
  assert.strictEqual(parsedVulns[1].category, "Hardcoded Credentials");

  console.log("✔ YARA API Validation Tests Passed!");
}

export { runYaraApiValidationTests as run };

if (process.argv[1] && import.meta.url.endsWith(process.argv[1].replace(/\\/g, "/"))) {
  runYaraApiValidationTests().catch((err) => {
    console.error("✖ YARA API Validation Tests Failed:", err);
    process.exit(1);
  });
}
