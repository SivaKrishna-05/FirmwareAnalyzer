import assert from "node:assert";
import { generatePdfReportBuffer, type PdfReportData } from "./pdf-report";

export function extractTextFromPdfBuffer(pdfBuffer: Buffer): string {
  const raw = pdfBuffer.toString("latin1");
  const tjRegex = /\[(.*?)\]\s*TJ/g;
  let text = "";
  let match: RegExpExecArray | null;
  while ((match = tjRegex.exec(raw)) !== null) {
    const inner = match[1];
    const hexBlocks = inner.match(/<([0-9a-fA-F]+)>/g) || [];
    const blockText = hexBlocks.map((h) => Buffer.from(h.slice(1, -1), "hex").toString("utf8")).join("");
    text += blockText + "\n";
  }
  return text;
}

export async function runPdfReportTests() {
  console.log("▶ Running PDF Report Generation & Field Parity Tests...");

  // Test 1: Clean scan PDF report
  const cleanScanData: PdfReportData = {
    scanId: "pdf-test-clean-1",
    firmwareName: "clean_router.bin",
    firmwareType: "SquashFS image",
    sizeBytes: 4194304,
    status: "Analysis Completed",
    riskScore: 0,
    riskLevel: "LOW",
    sha256: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
    architecture: "MIPS",
    operatingSystem: "OpenWrt Linux",
    extractionStatus: "Unpacked 1 layer via unsquashfs",
    extractedFileCount: 150,
    malwareIndicatorCount: 0,
    findings: [],
  };

  const cleanPdfBuffer = await generatePdfReportBuffer(cleanScanData);
  assert(Buffer.isBuffer(cleanPdfBuffer), "Expected a Buffer output");
  assert(cleanPdfBuffer.length > 500, "PDF buffer must be non-empty");
  assert.strictEqual(cleanPdfBuffer.subarray(0, 4).toString(), "%PDF", "Must begin with valid %PDF header");

  // Test 2: Vulnerable scan with components, CVEs, and YARA detections
  const vulnerableScanData: PdfReportData = {
    scanId: "pdf-test-vuln-2",
    firmwareName: "infected_camera.bin",
    firmwareType: "ZIP archive",
    sizeBytes: 8388608,
    status: "Analysis Completed",
    riskScore: 98,
    riskLevel: "CRITICAL",
    sha256: "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
    architecture: "ARM",
    operatingSystem: "BusyBox Embedded Linux",
    extractionStatus: "Unpacked 2 layers",
    extractedFileCount: 320,
    malwareIndicatorCount: 3,
    findings: [
      {
        id: "f-1",
        category: "Outdated/Vulnerable Software",
        title: "CVE-2023-48795 in dropbear v2020.81",
        severity: "High",
        affectedPath: "/usr/sbin/dropbear",
        description: "Terrapin attack flaw in SSH protocol.",
        evidence: "dropbear 2020.81 banner detected",
        recommendation: "Upgrade Dropbear to version 2022.82 or newer.",
        cve: "CVE-2023-48795",
        confidence: "high",
        component: "dropbear",
        componentVersion: "2020.81",
        detectionSource: "CVE Database Lookup",
      },
      {
        id: "f-2",
        category: "Dangerous Commands/Code Execution Indicators",
        title: "Mirai Botnet Indicators hit on /bin/busybox",
        severity: "Critical",
        affectedPath: "/bin/busybox",
        description: "Botnet signatures identified.",
        evidence: "YARA Rule [YARA_MIRAI_STRINGS] matched",
        recommendation: "Remove infected binary immediately.",
        confidence: "high",
        detectionSource: "YARA Scanner",
      },
      {
        id: "f-3",
        category: "Hardcoded Credentials",
        title: "Hardcoded root credentials in shadow file",
        severity: "High",
        affectedPath: "/etc/shadow",
        description: "Known default root password hash identified.",
        evidence: "root:$1$admin:12345:...",
        recommendation: "Enforce dynamic unique passwords per device.",
        confidence: "high",
        detectionSource: "Static Credential Scanner",
      },
    ],
  };

  const vulnPdfBuffer = await generatePdfReportBuffer(vulnerableScanData);
  assert(Buffer.isBuffer(vulnPdfBuffer), "Expected a Buffer output");
  assert(vulnPdfBuffer.length > cleanPdfBuffer.length, "Vulnerable report with findings must be larger than clean report");
  assert.strictEqual(vulnPdfBuffer.subarray(0, 4).toString(), "%PDF", "Must begin with valid %PDF header");

  // Test 3: Validate exact text and finding parity within generated PDF
  const decodedText = extractTextFromPdfBuffer(vulnPdfBuffer);
  assert(decodedText.includes("infected_camera.bin"), "PDF must contain firmware name");
  assert(decodedText.includes("CVE-2023-48795"), "PDF must contain CVE identifier");
  assert(decodedText.includes("dropbear"), "PDF must contain detected component name");
  assert(decodedText.includes("2020.81"), "PDF must contain component version");
  assert(decodedText.includes("/usr/sbin/dropbear"), "PDF must contain affected file path");
  assert(decodedText.includes("Terrapin attack"), "PDF must contain finding description");
  assert(decodedText.includes("Upgrade Dropbear to version 2022.82"), "PDF must contain recommendation");
  assert(decodedText.includes("Mirai Botnet"), "PDF must contain malware finding title");
  assert(decodedText.includes("YARA Scanner"), "PDF must contain detection source");
  assert(decodedText.includes("Hardcoded root credentials"), "PDF must contain credential findings");

  console.log("✔ PDF Report Generation & Field Parity Tests Passed!");
}

export { runPdfReportTests as run };

if (process.argv[1] && import.meta.url.endsWith(process.argv[1].replace(/\\/g, "/"))) {
  runPdfReportTests().catch((err) => {
    console.error("✖ PDF Report Tests Failed:", err);
    process.exit(1);
  });
}
