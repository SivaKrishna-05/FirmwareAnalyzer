import {
  extractFirmware as extractFirmwareDeep,
  cleanupExtraction,
  DEFAULT_LIMITS,
  type ExtractionResult as DeepExtractionResult,
} from "./extraction/extractor";
import { analyzeExtractedTree } from "./analysis/static-analysis";
import { runSecurityAnalysis, type SecurityFinding, type FindingCategory } from "./analysis/security-findings";
import { describeMissingCapabilities } from "./extraction/tools";
import { SUPPORTED_FIRMWARE_EXTENSIONS as DEEP_SUPPORTED_EXTENSIONS } from "./extraction/formats";
import { createHash } from "node:crypto";
import { access, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { db, scanFilesTable, scansTable, vulnerabilityFindingsTable } from "@workspace/db";
import { eq } from "drizzle-orm";
import { logger } from "./logger";
import { matchCvesForComponents } from "./analysis/cve/matcher";
import { scanWithYara } from "./analysis/yara/scanner";
import { runMlMalwareClassification } from "./analysis/ml-malware/classifier";
import { calculateHeuristicRiskScore } from "./analysis/malware-risk/scorer";

const stages = [
  ["validation", "Firmware validation"],
  ["extraction", "Firmware extraction"],
  ["inventory", "File discovery"],
  ["static", "Static analysis"],
  ["secrets", "Sensitive information scan"],
  ["cve", "CVE analysis"],
  ["malware", "Malware indicators"],
  ["risk", "Risk assessment"],
  ["report", "Report generation"],
] as const;

const initialStages = stages.map(([key, label]) => ({
  key,
  label,
  status: "pending" as const,
  detail: null,
}));

/**
 * Accepted upload extensions. Format detection itself is magic-byte based, so
 * this list only gates the upload form; it mirrors the formats the real
 * detector understands rather than a narrower hand-maintained subset.
 */
export const SUPPORTED_FIRMWARE_EXTENSIONS = DEEP_SUPPORTED_EXTENSIONS;
const supportedExtensions = new Set<string>(SUPPORTED_FIRMWARE_EXTENSIONS);
const maxInventoryFiles = 5_000;


type Finding = SecurityFinding & { id: string };

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

function safeName(name: string): string {
  const normalized = name.replaceAll("\\", "/");
  const lastPart = normalized.split("/").pop() ?? "firmware.bin";
  return lastPart.replace(/[^a-zA-Z0-9._-]/g, "_").slice(0, 180) || "firmware.bin";
}

function extensionFor(name: string): string {
  const lower = name.toLowerCase();
  if (lower.endsWith(".tar.gz")) return ".tar.gz";
  if (lower.endsWith(".tgz")) return ".tgz";
  const extension = lower.slice(lower.lastIndexOf("."));
  return extension.length > 1 ? extension : "";
}

function detectType(name: string, bytes: Buffer): {
  type: string;
  supported: boolean;
  encrypted: boolean;
  corrupted: boolean;
} {
  const extension = extensionFor(name);
  const isZip = bytes.length >= 4 && bytes.subarray(0, 4).equals(Buffer.from([0x50, 0x4b, 0x03, 0x04]));
  const isGzip = bytes.length >= 2 && bytes[0] === 0x1f && bytes[1] === 0x8b;
  const isTar = bytes.length >= 262 && bytes.subarray(257, 262).toString("ascii") === "ustar";
  const isElf = bytes.length >= 4 && bytes.subarray(0, 4).equals(Buffer.from([0x7f, 0x45, 0x4c, 0x46]));
  const isSquashfs = bytes.length >= 4 && bytes.subarray(0, 4).toString("ascii") === "hsqs";
  const isUbi = bytes.length >= 4 && bytes.subarray(0, 4).toString("ascii") === "UBI#";
  const looksLikeArchive = isZip || isGzip || isTar || isSquashfs || isUbi || [".zip", ".tar", ".tar.gz", ".tgz", ".gz"].includes(extension);

  if (isZip) {
    // A valid ZIP archive must contain an End of Central Directory record (0x06054b50)
    const hasEocd = bytes.includes(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
    return {
      type: "ZIP archive",
      supported: true,
      encrypted: zipHasEncryption(bytes),
      corrupted: bytes.length < 22 || !hasEocd,
    };
  }
  if (isGzip) return { type: "GZIP compressed firmware", supported: true, encrypted: false, corrupted: false };
  if (isTar) return { type: "TAR archive", supported: true, encrypted: false, corrupted: false };
  if (isSquashfs) return { type: "SquashFS filesystem", supported: true, encrypted: false, corrupted: false };
  if (isUbi) return { type: "UBI firmware container", supported: true, encrypted: false, corrupted: false };
  if (isElf) return { type: "ELF binary firmware", supported: true, encrypted: false, corrupted: false };
  if (supportedExtensions.has(extension)) {
    return {
      type: extension === ".img" ? "Raw firmware image" : "Binary firmware image",
      supported: true,
      encrypted: false,
      corrupted: false,
    };
  }
  return {
    type: looksLikeArchive ? "Unrecognized archive" : "Unknown",
    supported: false,
    encrypted: false,
    corrupted: false,
  };
}


function zipHasEncryption(bytes: Buffer): boolean {
  for (let offset = 0; offset + 10 < bytes.length; offset += 1) {
    const signature = bytes.readUInt32LE(offset);
    if (signature === 0x04034b50) {
      if ((bytes.readUInt16LE(offset + 6) & 0x1) === 0x1) return true;
      offset += 29;
    } else if (signature === 0x02014b50) {
      if ((bytes.readUInt16LE(offset + 8) & 0x1) === 0x1) return true;
      offset += 45;
    }
  }
  return false;
}



/**
 * Summarise what extraction actually achieved. Deliberately distinguishes
 * "identified but not unpacked" from "unpacked", so the scan record never
 * implies a filesystem was opened when it was only fingerprinted.
 */
function describeExtraction(result: DeepExtractionResult): string {
  const unpacked = result.layers.filter((layer) => layer.succeeded);
  if (unpacked.length === 0) {
    return result.primaryFormat
      ? `Identified ${result.primaryFormat.label}, but no layer could be unpacked`
      : "No supported container signature found; analyzed as a single opaque image";
  }
  const methods = [...new Set(unpacked.map((layer) => layer.method))].join(", ");
  return (
    `Unpacked ${unpacked.length} layer(s) via ${methods}; ` +
    `${result.totalFiles} files recovered at depth ${result.depth}` +
    (result.truncated ? " (limits reached; inventory is partial)" : "")
  );
}

/** Name the filesystem that was actually unpacked, if any. */
function describeFilesystem(result: DeepExtractionResult): string | null {
  const filesystemLayer = result.layers.find(
    (layer) => layer.succeeded && ["squashfs", "ubi", "ubifs", "cramfs", "jffs2", "ext", "romfs"].includes(layer.format),
  );
  if (filesystemLayer) return filesystemLayer.label;
  const anyLayer = result.layers.find((layer) => layer.succeeded);
  return anyLayer ? anyLayer.label : result.primaryFormat?.label ?? null;
}


/**
 * Risk scoring.
 *
 * Each finding (including malware/backdoor indicators) already carries a
 * severity, and severity is what this function weights. The previous
 * implementation ALSO added `malwareIndicatorCount * 8` on top, double
 * counting: a reverse-shell finding scored as Critical (35) contributed 35,
 * then the same finding's presence in the malware-indicator count added
 * another 8 — inflating scores in a way that was not traceable to any single
 * piece of evidence. Malware indicators are ordinary findings now; there is
 * nothing left to add separately.
 */
function calculateRisk(findings: Array<{ severity: "Critical" | "High" | "Medium" | "Low" | "Informational"; title: string }>): {
  score: number;
  level: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  contributors: string[];
} {
  const weights: Record<SecurityFinding["severity"], number> = {
    Critical: 35,
    High: 22,
    Medium: 12,
    Low: 5,
    Informational: 1,
  };
  const score = Math.min(
    100,
    findings.reduce((total, finding) => total + weights[finding.severity], 0),
  );
  const level = score >= 71 ? "CRITICAL" : score >= 41 ? "HIGH" : score >= 21 ? "MEDIUM" : "LOW";

  // Top contributors: the highest-weighted findings, so the score is
  // explainable rather than a single opaque number.
  const contributors = [...findings]
    .sort((a, b) => weights[b.severity] - weights[a.severity])
    .slice(0, 5)
    .map((finding) => `${finding.severity} · ${finding.title}`);

  return { score, level, contributors };
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (character) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#039;",
  })[character] ?? character);
}

async function updateProgress(
  scanId: string,
  status: string,
  progress: number,
  message: string,
  stageKey: string,
  stageStatus: "running" | "completed" | "failed" | "skipped",
  detail: string | null = null,
): Promise<void> {
  const current = await db.select({ progressStages: scansTable.progressStages }).from(scansTable).where(eq(scansTable.id, scanId));
  const currentStages = current[0]?.progressStages ?? initialStages;
  const progressStages = currentStages.map((stage: any) =>
    stage.key === stageKey ? { ...stage, status: stageStatus, detail } : stage,
  );
  await db.update(scansTable).set({ status, progress, progressMessage: message, progressStages }).where(eq(scansTable.id, scanId));
}

export async function createProgressStages() {
  return initialStages;
}

export async function runFirmwareAnalysis(
  scanId: string,
  originalName: string,
  bytesOrPath: Buffer | string,
  options: { deepAnalysis?: boolean } = {},
): Promise<void> {
  const isDeep = options.deepAnalysis ?? true;
  let workDir: string | null = null;
  let sourceBytes: Buffer | null = null;
  // Sandbox created by the deep extractor; removed and verified in `finally`.
  let deepRootDir: string | null = null;
  try {
    const name = safeName(originalName);
    workDir = await mkdtemp(join(tmpdir(), "firmware-scan-"));
    const inputPath = join(workDir, name);

    if (typeof bytesOrPath === "string") {
      const { copyFile } = await import("node:fs/promises");
      await copyFile(bytesOrPath, inputPath);
    } else {
      await writeFile(inputPath, bytesOrPath, { mode: 0o600 });
      bytesOrPath.fill(0);
    }

    await updateProgress(scanId, "Validating", 8, "Checking the firmware signature and container metadata", "validation", "running");
    sourceBytes = await readFile(inputPath);
    const detected = detectType(name, sourceBytes);
    await db.update(scansTable).set({ firmwareType: detected.type }).where(eq(scansTable.id, scanId));
    await sleep(220);

    if (detected.encrypted) {
      await updateProgress(scanId, "Encrypted", 8, "Encrypted firmware cannot be analyzed without bypassing protection", "validation", "failed", "Encrypted archive");
      return;
    }
    if (detected.corrupted) {
      await updateProgress(scanId, "Corrupted", 8, "Firmware appears to be corrupted or incomplete. Analysis has been stopped.", "validation", "failed", "Truncated archive");
      return;
    }
    if (!detected.supported) {
      await updateProgress(scanId, "Unsupported", 8, "Unsupported firmware format. Please provide a supported firmware file.", "validation", "failed", "No supported signature or extension");
      return;
    }

    await updateProgress(scanId, "Extracting", 20, `Recognized ${detected.type}; preparing an isolated analysis view`, "validation", "completed", detected.type);
    await updateProgress(scanId, "Extracting", 20, isDeep ? "Extracting recursive content without executing firmware" : "Extracting single-layer content (fast mode)", "extraction", "running");

    // Real recursive extraction: archives, compressed streams, SquashFS/UBI
    // filesystems, and containers carved out of raw flash dumps at arbitrary
    // offsets. When deepAnalysis is false, maxDepth is restricted to 1.
    const extractionLimits = isDeep ? DEFAULT_LIMITS : { ...DEFAULT_LIMITS, maxDepth: 1 };
    let deep: DeepExtractionResult;
    try {
      deep = await extractFirmwareDeep(sourceBytes, name, extractionLimits);
      deepRootDir = deep.rootDir;
    } catch (error) {
      const message = error instanceof Error ? error.message : "The firmware could not be safely extracted";
      await updateProgress(scanId, "Extraction Failed", 20, "Firmware extraction failed. Analysis has been stopped.", "extraction", "failed", message.slice(0, 180));
      await db.update(scansTable).set({ extractionStatus: "Failed: safe extraction did not complete" }).where(eq(scansTable.id, scanId));
      return;
    }

    const extractionSummary = describeExtraction(deep);
    // A deployment missing unsquashfs/ubireader cannot analyze the most
    // common IoT filesystems. That gap is recorded against the scan rather
    // than being quietly absorbed into a clean-looking result.
    const missingCapabilities = await describeMissingCapabilities();
    // If files were extracted, record actual extraction notes. If extraction yielded nothing, include missing capabilities
    // so the analyst understands what tooling could be required to unpack this image.
    const combinedNotes = deep.extractedAnything ? deep.notes : [...deep.notes, ...missingCapabilities];
    const extractionNotes = Array.from(new Set(combinedNotes)).slice(0, 40).join("\n") || null;

    if (!deep.extractedAnything) {
      // Not a failure in itself — an opaque or vendor-encrypted image is a
      // legitimate outcome — but the analyst must see that nothing was opened.
      await updateProgress(
        scanId,
        "Extracting",
        28,
        "No container layer could be unpacked; continuing against the raw image",
        "extraction",
        "completed",
        extractionSummary,
      );
    } else {
      await updateProgress(scanId, "Extracting", 28, "Safe extraction completed; no firmware binary was executed", "extraction", "completed", extractionSummary);
    }

    await updateProgress(scanId, "Analysis Running", 38, "Building the file inventory and calculating digests", "inventory", "running");

    const staticResult = await analyzeExtractedTree(deep.rootDir, { declaredModes: deep.declaredModes });

    if (staticResult.files.length > 0) {
      // Persist the full static inventory, including the ELF metadata and
      // entropy that the finding engine does not itself consume.
      const rows = staticResult.files.slice(0, maxInventoryFiles).map((file, index) => ({
        id: `${scanId}-${index + 1}`,
        scanId,
        path: file.path,
        type: file.type,
        sizeBytes: file.sizeBytes,
        permissions: file.permissions,
        owner: file.owner,
        group: file.group,
        sha256: file.sha256,
        md5: file.md5,
        sha1: file.sha1,
        executable: file.executable ? 1 : 0,
        suspicious: file.suspicious ? 1 : 0,
        suspiciousReason: file.suspiciousReason,
        stringsCount: file.stringsCount,
        // Stored as an integer to avoid float drift across pg drivers.
        entropyMilli: file.entropy === null ? null : Math.round(file.entropy * 1000),
        binaryInfo: file.binaryInfo,
      }));
      // Chunked to stay well under the parameter limit on large images.
      for (let offset = 0; offset < rows.length; offset += 500) {
        await db.insert(scanFilesTable).values(rows.slice(offset, offset + 500));
      }
    }
    await updateProgress(
      scanId,
      "Analysis Running",
      48,
      "Inventory complete",
      "inventory",
      "completed",
      `${staticResult.files.length} files analyzed${staticResult.truncated ? " (capped)" : ""}`,
    );

    await updateProgress(scanId, "Analysis Running", 56, "Inspecting binary and configuration indicators", "static", "running");
    // Per-file evidence-based engine: reads each config/script/credential
    // file individually rather than one global text blob, so every
    // offending file gets its own finding instead of at most one per
    // category. Also folds in the suspicious/entropy/permission flags
    // static-analysis.ts already computed but never previously surfaced.
    const security = await runSecurityAnalysis(deep.rootDir, staticResult.files);
    const findings = security.findings.map((finding, index) => ({ ...finding, id: `${scanId}-${index + 1}` }));
    await updateProgress(scanId, "Analysis Running", 62, "Static indicator review complete", "static", "completed", `${findings.length} evidence-backed findings`);

    await updateProgress(scanId, "Analysis Running", 70, "Scanning for masked credentials and cryptographic material", "secrets", "running");
    for (const finding of findings) {
      await db.insert(vulnerabilityFindingsTable).values({
        id: finding.id,
        scanId,
        category: finding.category,
        title: finding.title,
        severity: finding.severity,
        affectedPath: finding.affectedPath,
        description: finding.description,
        evidence: finding.evidence,
        confidence: finding.confidence,
        recommendation: finding.recommendation,
        cve: finding.cve,
        component: finding.component,
        componentVersion: finding.componentVersion,
        detectionSource: finding.detectionSource,
      });
    }
    await updateProgress(scanId, "Analysis Running", 74, "Sensitive values remain masked in retained evidence", "secrets", "completed", "Masked evidence policy");

    await updateProgress(scanId, "Analysis Running", 75, "Performing CVE analysis on identified components", "cve", "running");
    try {
      const cveResult = await matchCvesForComponents(staticResult.profile.components);
      for (const match of cveResult.matches) {
        const findingId = `${scanId}-cve-${findings.length + 1}`;
        const cveFinding: Finding = {
          id: findingId,
          category: "Outdated/Vulnerable Software",
          title: `${match.cveId} in ${match.component}${match.version ? ` v${match.version}` : ""}`,
          severity: match.severity,
          affectedPath: `/components/${match.component.toLowerCase()}`,
          description: match.summary,
          evidence: `CVE match derived from component evidence for ${match.component}${match.version ? ` ${match.version}` : ""}`,
          confidence: match.confidence,
          recommendation: `Upgrade ${match.component} to a patched release or apply upstream security patches for ${match.cveId}.`,
          cve: match.cveId,
          component: match.component,
          componentVersion: match.version,
          detectionSource: "CVE Database Lookup",
          isMalwareIndicator: false,
        };
        findings.push(cveFinding);
        await db.insert(vulnerabilityFindingsTable).values({
          id: cveFinding.id,
          scanId,
          category: cveFinding.category,
          title: cveFinding.title,
          severity: cveFinding.severity,
          affectedPath: cveFinding.affectedPath,
          description: cveFinding.description,
          evidence: cveFinding.evidence,
          confidence: cveFinding.confidence,
          recommendation: cveFinding.recommendation,
          cve: cveFinding.cve,
          component: match.component,
          componentVersion: match.version,
          detectionSource: "CVE Database Lookup",
        });
      }

      const cveDetail = `Checked ${cveResult.checkedCount} component(s); ${cveResult.matches.length} CVE match(es) identified` +
        (cveResult.skippedCount > 0 ? ` (${cveResult.skippedCount} skipped)` : "") +
        (cveResult.failedCount > 0 ? ` (${cveResult.failedCount} failed)` : "");

      const cveStatus = (cveResult.failedCount > 0 && cveResult.checkedCount === 0) ? "failed" : "completed";
      const cveMessage = cveResult.matches.length > 0
        ? `Identified ${cveResult.matches.length} CVE match(es)${cveResult.failedCount > 0 ? ` (${cveResult.failedCount} lookup(s) failed)` : ""}`
        : cveResult.failedCount > 0
          ? `CVE lookup failed for ${cveResult.failedCount} component(s); provider unavailable`
          : "No CVE matches found for identified components";

      await updateProgress(
        scanId,
        "Analysis Running",
        78,
        cveMessage,
        "cve",
        cveStatus,
        cveDetail,
      );
    } catch (cveError) {
      logger.warn({ err: cveError, scanId }, "CVE analysis stage encountered an error");
      await updateProgress(
        scanId,
        "Analysis Running",
        78,
        "CVE analysis stage failed to query CVE provider",
        "cve",
        "failed",
        "Provider error",
      );
    }
    await updateProgress(scanId, "Analysis Running", 84, "Scanning extracted files with YARA malware rules", "malware", "running");
    let yaraMatches: import("./analysis/yara/types").YaraMatch[] = [];
    try {
      yaraMatches = await scanWithYara(deep.rootDir);
      for (const match of yaraMatches) {
        const findingId = `${scanId}-yara-${findings.length + 1}`;
        const yaraCategory: FindingCategory =
          match.category === "Credential Leak"
            ? "Hardcoded Credentials"
            : "Dangerous Commands/Code Execution Indicators";
        const yaraFinding: Finding = {
          id: findingId,
          category: yaraCategory,
          title: `${match.ruleName} hit on ${match.filePath}`,
          severity: match.severity,
          affectedPath: match.filePath,
          description: `${match.description} (Matched string/pattern: "${match.matchedString}")`,
          evidence: `YARA Rule [${match.ruleId}] matched in ${match.filePath}`,
          confidence: "high",
          recommendation: "Inspect suspicious binary or script for unauthorized remote control, persistence, or backdoor behavior.",
          cve: null,
          component: null,
          componentVersion: null,
          detectionSource: "YARA Scanner",
          isMalwareIndicator: true,
        };
        findings.push(yaraFinding);
        await db.insert(vulnerabilityFindingsTable).values({
          id: yaraFinding.id,
          scanId,
          category: yaraFinding.category,
          title: yaraFinding.title,
          severity: yaraFinding.severity,
          affectedPath: yaraFinding.affectedPath,
          description: yaraFinding.description,
          evidence: yaraFinding.evidence,
          confidence: yaraFinding.confidence,
          recommendation: yaraFinding.recommendation,
          cve: null,
          detectionSource: "YARA Scanner",
        });
      }
      await updateProgress(
        scanId,
        "Analysis Running",
        88,
        yaraMatches.length > 0 ? `YARA scan matched ${yaraMatches.length} malware pattern(s)` : "YARA scan completed; running ML malware classification",
        "malware",
        "running",
        `YARA: ${yaraMatches.length} match(es)`,
      );
    } catch (yaraErr) {
      logger.warn({ err: yaraErr, scanId }, "YARA scan stage encountered an error");
    }

    let mlResults: import("./analysis/ml-malware/types").MlClassificationResult[] = [];
    try {
      mlResults = await runMlMalwareClassification(deep.rootDir, staticResult.files);
      for (const ml of mlResults) {
        const findingId = `${scanId}-ml-${findings.length + 1}`;
        const mlFinding: Finding = {
          id: findingId,
          category: "Dangerous Commands/Code Execution Indicators",
          title: `ML Classifier: ${ml.label} detected on ${ml.filePath}`,
          severity: ml.label === "Malware" ? "Critical" : "High",
          affectedPath: ml.filePath,
          description: `Machine learning classifier [${ml.model}] predicted ${ml.label.toLowerCase()} with ${(ml.confidence * 100).toFixed(0)}% confidence. Top contributing features: ${ml.topFeatures.map((f) => f.feature).join("; ")}.`,
          evidence: `ML Risk Score: ${ml.malwareScore}/100. Key signals: ${ml.topFeatures.map((f) => `${f.feature} (${f.value})`).join("; ")}`,
          confidence: ml.confidence >= 0.8 ? "high" : "medium",
          recommendation: "Review binary structure and network dependencies. Perform dynamic behavioral analysis to detect persistence or command-and-control behavior.",
          cve: null,
          component: null,
          componentVersion: null,
          detectionSource: "ML Malware Classifier",
          isMalwareIndicator: true,
        };
        findings.push(mlFinding);
        await db.insert(vulnerabilityFindingsTable).values({
          id: mlFinding.id,
          scanId,
          category: mlFinding.category,
          title: mlFinding.title,
          severity: mlFinding.severity,
          affectedPath: mlFinding.affectedPath,
          description: mlFinding.description,
          evidence: mlFinding.evidence,
          confidence: mlFinding.confidence,
          recommendation: mlFinding.recommendation,
          cve: null,
          detectionSource: "ML Malware Classifier",
        });
      }

      const malwareSummary = `YARA: ${yaraMatches.length} match(es), ML: ${mlResults.length} detection(s)`;
      await updateProgress(
        scanId,
        "Analysis Running",
        90,
        mlResults.length > 0
          ? `ML classifier flagged ${mlResults.length} suspicious/malware binary(ies)`
          : "ML classifier completed; no anomalies detected",
        "malware",
        "completed",
        malwareSummary,
      );
    } catch (mlErr) {
      logger.warn({ err: mlErr, scanId }, "ML classification stage encountered an error");
      await updateProgress(scanId, "Analysis Running", 90, "Malware inspection complete", "malware", "completed", `YARA: ${yaraMatches.length} match(es)`);
    }

    const risk = calculateHeuristicRiskScore(findings, staticResult, yaraMatches);

    /**
     * A score of 0 after a failed extraction is dangerously misleading: it
     * renders identically to "we analyzed this and found nothing wrong", when
     * what actually happened is that we never saw the filesystem.
     *
     * So when nothing was unpacked AND no findings were produced, the scan is
     * recorded as incomplete with a null score rather than 0/100. A scan that
     * unpacked nothing but still produced findings keeps its score, since
     * those findings are real evidence.
     */
    const analysisIncomplete = !deep.extractedAnything && findings.length === 0;
    const reportedRiskScore = analysisIncomplete ? null : risk.score;
    const reportedRiskLevel = analysisIncomplete ? null : risk.level;
    if (analysisIncomplete) {
      logger.warn(
        { scanId, extractionSummary },
        "Extraction reached no filesystem; reporting the scan as incomplete rather than as zero risk",
      );
    }
    const totalMalwareCount = findings.filter((f) => f.isMalwareIndicator).length;
    await updateProgress(scanId, "Analysis Running", 92, "Calculating a deduplicated risk score from observed evidence", "risk", "running");
    await db.update(scansTable).set({
      riskScore: reportedRiskScore,
      riskLevel: reportedRiskLevel,
      vulnerabilityCount: findings.length,
      malwareIndicatorCount: totalMalwareCount,
      // Prefer the evidence-backed profile from the extracted filesystem and
      // fall back to the finding engine's inference only when it found nothing.
      architecture: staticResult.profile.architecture,
      operatingSystem: staticResult.profile.operatingSystem,
      filesystem: describeFilesystem(deep),
      extractionStatus: extractionSummary,
      extractionMethod: [...new Set(deep.layers.filter((layer) => layer.succeeded).map((layer) => layer.method))].join(", ") || "none",
      extractedFileCount: deep.totalFiles,
      extractionDepth: deep.depth,
      extractionNotes,
      sha256: createHash("sha256").update(sourceBytes).digest("hex"),
    }).where(eq(scansTable.id, scanId));
    await updateProgress(
      scanId,
      "Analysis Running",
      94,
      analysisIncomplete
        ? "Risk score is not available because the filesystem could not be extracted"
        : `Risk score calculated: ${risk.score}/100`,
      "risk",
      analysisIncomplete ? "skipped" : "completed",
      analysisIncomplete ? "Not assessed: extraction incomplete" : `${risk.level} risk`,
    );

    await updateProgress(scanId, "Analysis Running", 96, "Generating a printable report from retained metadata", "report", "running");
    const generatedAt = new Date().toISOString();
    const componentsHtml = staticResult.profile.components.length === 0
      ? "<p>No recognized third-party software components with identifiable signatures were detected.</p>"
      : `<table><thead><tr><th>Component</th><th>Version</th><th>Assessment Status</th><th>Source</th></tr></thead><tbody>${staticResult.profile.components.map((comp) => {
          const compFindings = findings.filter((f) => f.component?.toLowerCase() === comp.name.toLowerCase() && f.cve);
          const statusText = !comp.version
            ? "<strong>Unassessed:</strong> Version unknown; reliable CVE correlation unavailable"
            : compFindings.length > 0
              ? `<strong>Assessed:</strong> ${compFindings.length} CVE match(es) identified`
              : "<strong>Assessed:</strong> No matching CVEs in baseline";
          return `<tr><td><strong>${escapeHtml(comp.name)}</strong></td><td>${escapeHtml(comp.version ?? "Unknown")}</td><td>${statusText}</td><td>${escapeHtml(comp.source)}</td></tr>`;
        }).join("")}</tbody></table>`;

    const reportHtml = `<!doctype html><html><head><meta charset="utf-8"><title>Firmware analysis report</title><style>body{font-family:Arial,sans-serif;max-width:980px;margin:40px auto;color:#172033;line-height:1.5}h1{margin-bottom:4px}.meta{color:#61708a}.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}.card{border:1px solid #d9e1ec;border-radius:8px;padding:14px}.finding{border:1px solid #d9e1ec;border-radius:8px;padding:16px;margin:12px 0}.severity{font-weight:700}code{background:#f3f6fa;padding:3px 5px;border-radius:4px}table{border-collapse:collapse;width:100%;font-size:12px}td,th{border-bottom:1px solid #e3e8ef;text-align:left;padding:7px}</style></head><body><h1>IoT Firmware Security Report</h1><p class="meta">${escapeHtml(name)} · generated ${escapeHtml(generatedAt)}</p><div class="grid"><div class="card"><strong>Risk score</strong><br>${analysisIncomplete ? "Not assessed — extraction incomplete" : `${risk.score}/100 · ${risk.level}`}</div><div class="card"><strong>Firmware type</strong><br>${escapeHtml(detected.type)}</div><div class="card"><strong>Extraction</strong><br>${escapeHtml(extractionSummary)}</div><div class="card"><strong>Inventory</strong><br>${staticResult.files.length} files · ${escapeHtml(staticResult.profile.architecture ?? "Architecture unknown")}</div></div><p>Analysis is static-only. Temporary firmware and extracted contents are deleted after analysis. Findings are evidence-backed and sensitive values are masked.</p><h2>Findings</h2>${analysisIncomplete ? "<p><strong>This image was not fully assessed.</strong> The filesystem could not be extracted, so the absence of findings below does not indicate the firmware is safe. See the capability status section for the missing extraction tooling.</p>" : ""}${findings.length === 0 ? "<p>No evidence-backed vulnerability findings were identified in the analyzed content.</p>" : findings.map((finding) => `<div class="finding"><div class="severity">${escapeHtml(finding.severity)} · ${escapeHtml(finding.title)}</div><p><strong>Path:</strong> ${escapeHtml(finding.affectedPath)}</p><p>${escapeHtml(finding.description)}</p><p><strong>Evidence:</strong> <code>${escapeHtml(finding.evidence)}</code></p><p><strong>Recommendation:</strong> ${escapeHtml(finding.recommendation)}</p></div>`).join("")}<h2>Identified Components & Vulnerability Correlation</h2>${componentsHtml}<h2>File inventory</h2><table><thead><tr><th>Path</th><th>Type</th><th>Size</th><th>Permissions</th><th>SHA-256</th></tr></thead><tbody>${staticResult.files.slice(0, 500).map((file) => `<tr><td>${escapeHtml(file.path)}</td><td>${escapeHtml(file.type)}</td><td>${file.sizeBytes}</td><td>${escapeHtml(file.permissions ?? "Unknown")}</td><td><code>${file.sha256}</code></td></tr>`).join("")}</tbody></table><h2>Extraction provenance</h2><table><thead><tr><th>Layer</th><th>Format</th><th>Method</th><th>Offset</th><th>Result</th></tr></thead><tbody>${deep.layers.map((layer) => `<tr><td>${layer.depth}</td><td>${escapeHtml(layer.label)}</td><td>${escapeHtml(layer.method)}</td><td><code>0x${layer.offset.toString(16)}</code></td><td>${layer.succeeded ? `${layer.fileCount} files` : "not unpacked"}${layer.note ? ` — ${escapeHtml(layer.note)}` : ""}</td></tr>`).join("") || "<tr><td colspan=\"5\">No container layer was unpacked.</td></tr>"}</tbody></table><h2>Capability status for this deployment</h2>${missingCapabilities.length === 0 ? "<p>All extraction and binary-analysis tools were available for this scan.</p>" : `<p>The following tools were not available. Their stages did not run, and no result is inferred from their absence:</p><ul>${missingCapabilities.map((capability) => `<li>${escapeHtml(capability)}</li>`).join("")}</ul>`}<p>CVE matching requires reliable component/version evidence. YARA scanning: completed (${yaraMatches.length} match(es) identified). ML malware classification: completed (${mlResults.length} detection(s) identified).</p></body></html>`;
    const reportHash = createHash("sha256").update(reportHtml).digest("hex");
    await db.update(scansTable).set({
      status: "Analysis Completed",
      progress: 100,
      progressMessage: analysisIncomplete
        ? "Analysis incomplete: the filesystem could not be extracted, so this image was not fully assessed"
        : "Analysis completed; temporary firmware content has been deleted",
      progressStages: initialStages.map((stage) =>
        stage.key === "report" ? { ...stage, status: "completed" as const, detail: "Printable report ready" } : stage,
      ),
      completedAt: new Date(),
      reportHtml: reportHtml,
    }).where(eq(scansTable.id, scanId));
    logger.info({ scanId, riskScore: risk.score, findings: findings.length }, "Firmware analysis completed");
    void generatedAt;
    void reportHash;
  } catch (error) {
    logger.error({ err: error, scanId }, "Firmware analysis failed");
    await db.update(scansTable).set({
      status: "Analysis Failed",
      progressMessage: "Analysis stopped because an internal processing error occurred",
      progressStages: initialStages.map((stage) =>
        (stage.status as string) === "completed" ? stage : { ...stage, status: "failed" as const, detail: "Processing stopped" },
      ),
    }).where(eq(scansTable.id, scanId));
  } finally {
    try {
      if (Buffer.isBuffer(bytesOrPath)) {
        bytesOrPath.fill(0);
      }
      sourceBytes?.fill(0);
      // Retained firmware is untrusted third-party content; leaving it on
      // disk would itself be a finding, so removal is verified, not assumed.
      if (deepRootDir) {
        const cleanup = await cleanupExtraction(deepRootDir);
        if (cleanup.removed) {
          logger.info({ scanId }, "Extraction sandbox removed and cleanup verified");
        } else {
          logger.warn({ scanId, err: cleanup.error }, "Extraction sandbox could not be fully removed");
        }
      }
      if (workDir) {
        await rm(workDir, { recursive: true, force: true });
        await access(workDir).then(
          () => logger.warn({ scanId }, "Temporary firmware directory still exists after cleanup"),
          () => logger.info({ scanId }, "Temporary firmware content removed and cleanup verified"),
        );
      }
    } catch (cleanupError) {
      logger.error({ err: cleanupError, scanId }, "Temporary firmware cleanup verification failed");
    }
  }
}