import { db, scansTable, vulnerabilityFindingsTable, eq } from "../lib/db/src/index";
import { runFirmwareAnalysis } from "../artifacts/api-server/src/lib/firmware-analysis";
import { matchCvesForComponents } from "../artifacts/api-server/src/lib/analysis/cve/matcher";

function createTarHeader(name: string, size: number): Buffer {
  const header = Buffer.alloc(512);
  header.write(name, 0, 100, "ascii");
  header.write("0000755\0", 100, 8, "ascii");
  header.write("0000000\0", 108, 8, "ascii");
  header.write("0000000\0", 116, 8, "ascii");
  header.write(size.toString(8).padStart(11, "0") + "\0", 124, 12, "ascii");
  header.write("00000000000\0", 136, 12, "ascii");
  header.write("        ", 148, 8, "ascii");
  header.write("0", 156, 1, "ascii");
  header.write("ustar\0", 257, 6, "ascii");
  header.write("00", 263, 2, "ascii");

  let checksum = 0;
  for (let i = 0; i < 512; i++) checksum += header[i];
  header.write(checksum.toString(8).padStart(6, "0") + "\0 ", 148, 8, "ascii");

  return header;
}

function createTarFileEntry(filename: string, content: Buffer): Buffer {
  const header = createTarHeader(filename, content.length);
  const padLen = (512 - (content.length % 512)) % 512;
  const padding = Buffer.alloc(padLen);
  return Buffer.concat([header, content, padding]);
}

async function main() {
  console.log("=== Testing CirclCveProvider Live Lookup directly ===");
  const directCve = await matchCvesForComponents([
    { name: "busybox", version: "1.35.0", source: "binary" },
    { name: "dropbear", version: "2020.81", source: "binary" }
  ]);
  console.log("Direct CVE Match Result:", JSON.stringify(directCve, null, 2));

  const scanId = `live-scan-${Date.now()}`;
  console.log("\nCreating scan in database:", scanId);

  await db.insert(scansTable).values({
    id: scanId,
    firmwareName: "firmware-busybox.tar",
    firmwareType: "TAR archive",
    sizeBytes: 4096,
    status: "Uploaded",
    progressStages: [],
  });

  const busyboxContent = Buffer.from("BusyBox v1.35.0 (2022-01-01 00:00:00 UTC) multi-call binary\n");
  const dropbearContent = Buffer.from("dropbear_v2020.81 SSH server\n");

  const entry1 = createTarFileEntry("bin/busybox", busyboxContent);
  const entry2 = createTarFileEntry("bin/dropbear", dropbearContent);
  const endBlocks = Buffer.alloc(1024);

  const tarBuffer = Buffer.concat([entry1, entry2, endBlocks]);

  console.log("Running firmware analysis pipeline...");
  await runFirmwareAnalysis(scanId, "firmware-busybox.tar", tarBuffer);

  console.log("\nQuerying vulnerabilityFindingsTable for scan:", scanId);
  const rows = await db.select().from(vulnerabilityFindingsTable).where(eq(vulnerabilityFindingsTable.scanId, scanId));

  console.log(`\nTotal Findings Inserted: ${rows.length}\n`);
  for (const row of rows) {
    console.log(`- ID: ${row.id}`);
    console.log(`  Title: ${row.title}`);
    console.log(`  Severity: ${row.severity}`);
    console.log(`  CVE: ${row.cve}`);
    console.log(`  Component: ${row.component} v${row.componentVersion}`);
    console.log(`  Source: ${row.detectionSource}`);
    console.log(`  Summary: ${row.description.slice(0, 120)}...`);
    console.log(`---`);
  }
  process.exit(0);
}

main().catch((err) => {
  console.error("End-to-end scan error:", err);
  process.exit(1);
});
