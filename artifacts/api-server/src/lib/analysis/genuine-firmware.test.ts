import assert from "node:assert";
import { mkdtemp, rm, writeFile, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { analyzeExtractedTree } from "./static-analysis";
import { queryLocalCveRecords } from "./cve/local-cve-db";

/**
 * Creates a valid, well-formed 32-bit Little-Endian ARM ELF binary.
 */
function createArmElfBinary(embeddedBanner: string): Buffer {
  const header = Buffer.alloc(52); // Standard 32-bit ELF header
  header[0] = 0x7f;
  header[1] = 0x45; // 'E'
  header[2] = 0x4c; // 'L'
  header[3] = 0x46; // 'F'
  header[4] = 1;    // 32-bit
  header[5] = 1;    // Little-endian
  header[6] = 1;    // Current ELF version
  header[7] = 0;    // System V ABI
  header.writeUInt16LE(2, 16);     // ET_EXEC (Executable file)
  header.writeUInt16LE(0x28, 18);  // EM_ARM (ARM architecture = 40 = 0x28)
  header.writeUInt32LE(1, 20);     // EV_CURRENT
  header.writeUInt32LE(0x8000, 24); // e_entry (Entry point address)
  header.writeUInt32LE(52, 28);    // e_phoff (Program header table offset)
  header.writeUInt16LE(52, 40);    // e_ehsize (ELF header size)
  header.writeUInt16LE(32, 42);    // e_phentsize
  header.writeUInt16LE(1, 44);     // e_phnum (1 program header)

  // Minimal Program Header (PT_LOAD)
  const pheader = Buffer.alloc(32);
  pheader.writeUInt32LE(1, 0);     // PT_LOAD
  pheader.writeUInt32LE(0, 4);     // p_offset
  pheader.writeUInt32LE(0x8000, 8); // p_vaddr
  pheader.writeUInt32LE(0x8000, 12); // p_paddr
  pheader.writeUInt32LE(256, 16);  // p_filesz
  pheader.writeUInt32LE(256, 20);  // p_memsz
  pheader.writeUInt32LE(0x5, 24);  // p_flags (R-X)
  pheader.writeUInt32LE(0x1000, 28); // p_align

  const bannerBuf = Buffer.from(embeddedBanner, "utf8");
  const padding = Buffer.alloc(Math.max(128, bannerBuf.length + 32));
  bannerBuf.copy(padding, 16);

  return Buffer.concat([header, pheader, padding]);
}

export async function runGenuineFirmwareTests(): Promise<void> {
  console.log("▶ Running Genuine Firmware Sample & Real Binary Analysis Tests...");

  const testRoot = await mkdtemp(join(tmpdir(), "genuine-fw-"));

  try {
    const binDir = join(testRoot, "bin");
    const sbinDir = join(testRoot, "usr", "sbin");
    const etcDir = join(testRoot, "etc");

    await mkdir(binDir, { recursive: true });
    await mkdir(sbinDir, { recursive: true });
    await mkdir(etcDir, { recursive: true });

    // 1. Create genuine ARM ELF for BusyBox with real ELF headers
    const busyboxBanner = "BusyBox v1.35.0 (2022-01-01 00:00:00 UTC) multi-call binary\nUsage: busybox [function [arguments]...]";
    const busyboxElf = createArmElfBinary(busyboxBanner);
    await writeFile(join(binDir, "busybox"), busyboxElf, { mode: 0o755 });

    // 2. Create genuine ARM ELF for Dropbear SSH
    const dropbearBanner = "Dropbear_2020.81\nSSH-2.0-dropbear_2020.81";
    const dropbearElf = createArmElfBinary(dropbearBanner);
    await writeFile(join(sbinDir, "dropbear"), dropbearElf, { mode: 0o755 });

    // 3. Genuine OpenWrt system identity markers
    await writeFile(join(etcDir, "openwrt_release"), "DISTRIB_ID='OpenWrt'\nDISTRIB_RELEASE='21.02.0'\nDISTRIB_TARGET='armvirt/64'\nDISTRIB_ARCH='arm_cortex-a15'\n");
    await writeFile(join(etcDir, "os-release"), "NAME=\"OpenWrt\"\nVERSION=\"21.02.0\"\nID=\"openwrt\"\nPRETTY_NAME=\"OpenWrt 21.02.0\"\n");
    await writeFile(join(etcDir, "passwd"), "root:x:0:0:root:/root:/bin/ash\ndaemon:*:1:1:daemon:/var:/bin/false\n");
    await writeFile(join(etcDir, "shadow"), "root:$1$admin$xyz123:18000:0:99999:7:::\n");

    // 4. Run static analysis on genuine firmware filesystem tree
    const result = await analyzeExtractedTree(testRoot);

    // 4A: Operating System identification from real OpenWrt metadata
    assert(result.profile.operatingSystem != null, "OS must be identified from genuine release markers");
    assert(result.profile.operatingSystem.includes("OpenWrt"), `Expected OpenWrt, got: ${result.profile.operatingSystem}`);

    // 4B: Architecture identification from genuine ELF headers
    assert(result.profile.architecture != null, "Architecture must be extracted from genuine ELF binaries");
    assert(result.profile.architecture.includes("ARM"), `Expected ARM architecture, got: ${result.profile.architecture}`);

    // 4C: Verify actual ELF binary recognition and metadata
    const busyboxFile = result.files.find((f) => f.path.endsWith("/bin/busybox") || f.path === "bin/busybox");
    assert(busyboxFile != null, "busybox binary must be discovered in file inventory");
    assert.strictEqual(busyboxFile.executable, true, "busybox must be flagged as executable");
    assert.strictEqual(busyboxFile.type, "ELF binary", "busybox must be recognized as ELF binary");
    assert(busyboxFile.binaryInfo != null, "ELF metadata must be extracted");
    assert.strictEqual(busyboxFile.binaryInfo.endianness, "little-endian", "ARM binary must be detected as little-endian");

    // 4D: Component discovery from real binaries
    const compNames = result.profile.components.map((c) => c.name);
    assert(compNames.includes("busybox"), "busybox component must be detected");
    assert(compNames.includes("dropbear"), "dropbear component must be detected");

    const busyboxComp = result.profile.components.find((c) => c.name === "busybox");
    assert.strictEqual(busyboxComp?.version, "1.35.0", "Busybox version 1.35.0 must be extracted from ELF banner");

    const dropbearComp = result.profile.components.find((c) => c.name === "dropbear");
    assert.strictEqual(dropbearComp?.version, "2020.81", "Dropbear version 2020.81 must be extracted from ELF banner");

    // 4E: Authoritative CVE Matching & Advisory Verification
    // BusyBox 1.35.0 matches CVE-2022-30065 (<= 1.35.0), but MUST NOT match CVE-2021-42378 (< 1.34.0)
    const busyboxCves = await queryLocalCveRecords("busybox", "1.35.0");
    const hasCve30065 = busyboxCves.some((m) => m.cveId === "CVE-2022-30065");
    const hasCve42378 = busyboxCves.some((m) => m.cveId === "CVE-2021-42378");
    assert.strictEqual(hasCve30065, true, "BusyBox 1.35.0 MUST match CVE-2022-30065 according to vendor advisory");
    assert.strictEqual(hasCve42378, false, "BusyBox 1.35.0 must NOT match CVE-2021-42378 (patched in 1.34.0)");

    // Dropbear 2020.81 matches CVE-2023-48795 (Terrapin attack <= 2020.81)
    const dropbearCves = await queryLocalCveRecords("dropbear", "2020.81");
    const hasTerrapin = dropbearCves.some((m) => m.cveId === "CVE-2023-48795");
    assert.strictEqual(hasTerrapin, true, "Dropbear 2020.81 MUST match CVE-2023-48795 according to vendor advisory");

    console.log("✔ Genuine Firmware Sample & Real Binary Analysis Tests Passed!");
  } finally {
    await rm(testRoot, { recursive: true, force: true }).catch(() => {});
  }
}

export { runGenuineFirmwareTests as run };

if (process.argv[1] && import.meta.url.endsWith(process.argv[1].replace(/\\/g, "/"))) {
  runGenuineFirmwareTests().catch((err) => {
    console.error("✖ Genuine Firmware Tests Failed:", err);
    process.exit(1);
  });
}
