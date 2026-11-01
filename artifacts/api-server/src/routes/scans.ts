import express, { Router, type IRouter, type Request, type Response } from "express";
import { and, desc, eq } from "drizzle-orm";
import {
  db,
  scanFilesTable,
  scansTable,
  userSettingsTable,
  vulnerabilityFindingsTable,
} from "@workspace/db";
import {
  GetDashboardSummaryResponse,
  GetScanProgressParams,
  GetScanProgressResponse,
  GetScanParams,
  GetScanReportParams,
  GetScanReportResponse,
  GetScanResponse,
  ListFirmwareFormatsResponse,
  ListScanFilesParams,
  ListScanFilesResponse,
  ListScanVulnerabilitiesParams,
  ListScanVulnerabilitiesResponse,
  ListScansQueryParams,
  ListScansResponse,
  type ScanStatus,
} from "@workspace/api-zod";
import { createHash, randomUUID } from "node:crypto";
import { audit, clientIp, requireAuth, requirePermission } from "../lib/auth/middleware";
import { can, canAccessScan, canDeleteScan } from "../lib/auth/rbac";
import { createProgressStages, runFirmwareAnalysis, SUPPORTED_FIRMWARE_EXTENSIONS } from "../lib/firmware-analysis";
import { logger } from "../lib/logger";
import { streamMultipartToFile, UploadError } from "../lib/streaming-upload";

const router: IRouter = Router();
const MAX_UPLOAD_BYTES = 500 * 1024 * 1024;

type MultipartFile = { name: string; data: Buffer };

function parseMultipart(body: Buffer, contentType: string): MultipartFile | null {
  const boundaryMatch = /boundary=(?:"([^"]+)"|([^;]+))/i.exec(contentType);
  const boundary = boundaryMatch?.[1] ?? boundaryMatch?.[2];
  if (!boundary) return null;

  const marker = Buffer.from(`--${boundary}`);
  let cursor = 0;
  while (cursor < body.length) {
    const markerStart = body.indexOf(marker, cursor);
    if (markerStart === -1) break;
    const sectionStart = markerStart + marker.length;
    if (body.subarray(sectionStart, sectionStart + 2).toString() === "--") break;
    const nextMarker = body.indexOf(marker, sectionStart);
    if (nextMarker === -1) break;
    const section = body.subarray(sectionStart, nextMarker);
    const headerEnd = section.indexOf(Buffer.from("\r\n\r\n"));
    if (headerEnd === -1) {
      cursor = nextMarker;
      continue;
    }
    const headers = section.subarray(0, headerEnd).toString("utf8");
    const filenameMatch = /filename="([^"]*)"/i.exec(headers);
    if (filenameMatch) {
      let data = section.subarray(headerEnd + 4);
      if (data.subarray(data.length - 2).toString() === "\r\n") {
        data = data.subarray(0, data.length - 2);
      }
      return { name: filenameMatch[1], data };
    }
    cursor = nextMarker;
  }
  return null;
}

function mapScan(scan: typeof scansTable.$inferSelect) {
  return {
    id: scan.id,
    firmwareName: scan.firmwareName,
    firmwareType: scan.firmwareType,
    sizeBytes: scan.sizeBytes,
    status: scan.status as ScanStatus,
    riskScore: scan.riskScore,
    riskLevel: (scan.riskLevel ?? null) as "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" | null,
    vulnerabilityCount: scan.vulnerabilityCount,
    malwareIndicatorCount: scan.malwareIndicatorCount,
    createdAt: scan.createdAt,
    completedAt: scan.completedAt,
  };
}

// NOTE: GET /session is served by routes/auth.ts against real sessions.
// The previous hardcoded "demo-analyst" response has been removed.

/**
 * Load a scan and confirm the caller may see it.
 *
 * Returns 404 (not 403) when the scan exists but belongs to someone else.
 * A 403 would confirm that the id is real, letting a user enumerate other
 * people's scan ids; from an unauthorized caller's perspective the scan
 * simply does not exist.
 */
async function loadAccessibleScan(
  req: Request,
  res: Response,
  scanId: string,
): Promise<typeof scansTable.$inferSelect | null> {
  if (!req.user) {
    res.status(401).json({ error: "Authentication required", code: "UNAUTHENTICATED" });
    return null;
  }

  const [scan] = await db.select().from(scansTable).where(eq(scansTable.id, scanId));
  if (!scan) {
    res.status(404).json({ error: "Scan not found", code: "SCAN_NOT_FOUND" });
    return null;
  }
  if (!canAccessScan(req.user, scan.userId)) {
    void audit({
      userId: req.user?.id,
      userEmail: req.user?.email,
      action: "scan.access_denied",
      resource: `scan:${scanId}`,
      outcome: "denied",
      detail: "scan belongs to another user",
      ipAddress: clientIp(req),
    });
    res.status(404).json({ error: "Scan not found", code: "SCAN_NOT_FOUND" });
    return null;
  }
  return scan;
}

router.delete("/scans/:scanId", requireAuth, async (req, res): Promise<void> => {
  const params = GetScanParams.safeParse(req.params);
  if (!params.success) {
    res.status(400).json({ error: params.error.message });
    return;
  }
  const [scan] = await db.select().from(scansTable).where(eq(scansTable.id, params.data.scanId));
  if (!scan) {
    // Same 404-for-both-cases rule as loadAccessibleScan: existence of a scan
    // id belonging to someone else is not revealed to an unauthorized caller.
    res.status(404).json({ error: "Scan not found", code: "SCAN_NOT_FOUND" });
    return;
  }
  if (!canDeleteScan(req.user!, scan.userId)) {
    void audit({
      userId: req.user!.id,
      userEmail: req.user!.email,
      action: "scan.delete_denied",
      resource: `scan:${scan.id}`,
      outcome: "denied",
      detail: "scan belongs to another user",
      ipAddress: clientIp(req),
    });
    res.status(404).json({ error: "Scan not found", code: "SCAN_NOT_FOUND" });
    return;
  }

  // scan_files and vulnerability_findings cascade via ON DELETE CASCADE on
  // their scan_id foreign keys; no manual cleanup needed here. Any retained
  // temp-directory content was already removed at the end of the analysis
  // run (see cleanupExtraction in firmware-analysis.ts) — this only removes
  // the database record.
  await db.delete(scansTable).where(eq(scansTable.id, scan.id));

  await audit({
    userId: req.user!.id,
    userEmail: req.user!.email,
    action: "scan.delete",
    resource: `scan:${scan.id}`,
    detail: scan.firmwareName,
    ipAddress: clientIp(req),
  });
  res.status(204).end();
});

router.get("/firmware/formats", (_req, res): void => {
  res.json(ListFirmwareFormatsResponse.parse({
    extensions: SUPPORTED_FIRMWARE_EXTENSIONS,
    maxUploadBytes: MAX_UPLOAD_BYTES,
  }));
});

router.get("/dashboard/summary", requireAuth, async (req, res): Promise<void> => {
  // A non-admin's dashboard counts only their own scans; otherwise the totals
  // would leak how much activity other users have.
  const seeAll = can(req.user!.role, "scan:read:any");
  const scans = seeAll
    ? await db.select().from(scansTable).orderBy(desc(scansTable.createdAt))
    : await db.select().from(scansTable).where(eq(scansTable.userId, req.user!.id)).orderBy(desc(scansTable.createdAt));
  const completed = scans.filter((scan: any) => scan.status === "Analysis Completed");
  const running = scans.filter((scan: any) => ["Uploaded", "Validating", "Extracting", "Analysis Running"].includes(scan.status));
  const riskScores = completed.map((scan: any) => scan.riskScore).filter((score: any): score is number => score != null);
  const summary = {
    totalScans: scans.length,
    completedScans: completed.length,
    runningScans: running.length,
    highRiskScans: completed.filter((scan: any) => ["HIGH", "CRITICAL"].includes(scan.riskLevel ?? "")).length,
    // null (not 0) when nothing has been assessed yet: 0 would read as "we
    // checked and everything is safe", which is not something zero scans
    // can support. This mirrors the same fix applied to a single scan's
    // riskScore when its extraction never reached a filesystem.
    averageRiskScore: riskScores.length ? Math.round(riskScores.reduce((total: number, score: number) => total + score, 0) / riskScores.length) : null,
    recentScans: scans.slice(0, 5).map(mapScan),
  };
  res.json(GetDashboardSummaryResponse.parse(summary));
});

router.get("/scans", requireAuth, async (req, res): Promise<void> => {
  const params = ListScansQueryParams.parse(req.query);
  const seeAll = can(req.user!.role, "scan:read:any");
  const scans = seeAll
    ? await db.select().from(scansTable).orderBy(desc(scansTable.createdAt))
    : await db.select().from(scansTable).where(eq(scansTable.userId, req.user!.id)).orderBy(desc(scansTable.createdAt));
  const filtered = scans.filter((scan: any) => {
    if (params.status === "completed") return scan.status === "Analysis Completed";
    if (params.status === "running") return ["Uploaded", "Validating", "Extracting", "Analysis Running"].includes(scan.status);
    if (params.status === "failed") return ["Analysis Failed", "Extraction Failed", "Unsupported", "Encrypted", "Corrupted"].includes(scan.status);
    return true;
  });
  res.json(ListScansResponse.parse(filtered.slice(0, params.limit).map(mapScan)));
});

router.post(
  "/scans",
  requireAuth,
  requirePermission("scan:create"),
  async (req, res): Promise<void> => {
    let uploadedFile: import("../lib/streaming-upload").StreamedUploadResult | null = null;
    try {
      uploadedFile = await streamMultipartToFile(req, MAX_UPLOAD_BYTES);
    } catch (err) {
      if (err instanceof UploadError) {
        res.status(err.status).json({ error: err.message, code: err.code });
        return;
      }
      const msg = err instanceof Error ? err.message : "Upload processing failed";
      res.status(400).json({ error: msg, code: "UPLOAD_FAILED" });
      return;
    }

    const { tempFilePath, originalFilename, sizeBytes: uploadedSize, sha256: uploadedSha256, cleanup } = uploadedFile;
    const id = randomUUID();
    const firmwareName = originalFilename;
    const initialScan = {
      id,
      // Ownership is recorded at creation; every read path filters on it.
      userId: req.user!.id,
      firmwareName,
      firmwareType: "Pending identification",
      sizeBytes: uploadedSize,
      status: "Uploaded",
      vulnerabilityCount: 0,
      malwareIndicatorCount: 0,
      progressStages: await createProgressStages(),
      progress: 0,
      progressMessage: "Upload received; validation is starting",
      extractionStatus: "Not started",
      sha256: uploadedSha256,
    };
    const [scan] = await db.insert(scansTable).values(initialScan).returning();
    if (!scan) {
      await cleanup();
      res.status(500).json({ error: "The scan could not be created.", code: "SCAN_CREATE_FAILED" });
      return;
    }

    await audit({
      userId: req.user!.id,
      userEmail: req.user!.email,
      action: "scan.upload",
      resource: `scan:${id}`,
      detail: `${firmwareName} (${uploadedSize} bytes)`,
      ipAddress: clientIp(req),
    });

    const [settings] = await db
      .select()
      .from(userSettingsTable)
      .where(eq(userSettingsTable.userId, req.user!.id));
    const deepAnalysis = settings?.deepAnalysis ?? true;

    // Start background analysis using the streamed temporary file, and guarantee cleanup
    void (async () => {
      try {
        await runFirmwareAnalysis(id, firmwareName, tempFilePath, { deepAnalysis });
      } finally {
        await cleanup();
      }
    })();

    res.status(201).json(mapScan(scan));
  },
);

router.get("/scans/:scanId", requireAuth, async (req, res): Promise<void> => {
  const params = GetScanParams.safeParse(req.params);
  if (!params.success) {
    res.status(400).json({ error: params.error.message });
    return;
  }
  const scan = await loadAccessibleScan(req, res, params.data.scanId);
  if (!scan) return;
  const findings = await db.select().from(vulnerabilityFindingsTable).where(eq(vulnerabilityFindingsTable.scanId, scan.id));

  const VALID_CATEGORIES = new Set([
    "Hardcoded Credentials",
    "Insecure Configuration",
    "Outdated/Vulnerable Software",
    "Weak Cryptography",
    "Insecure Network Services",
    "Excessive/Unsafe File Permissions",
    "Sensitive Information Exposure",
    "Dangerous Commands/Code Execution Indicators",
    "Other Security Weaknesses",
  ]);

  const detail = {
    ...mapScan(scan),
    architecture: scan.architecture,
    operatingSystem: scan.operatingSystem,
    filesystem: scan.filesystem,
    extractionStatus: scan.extractionStatus,
    extractionMethod: scan.extractionMethod,
    extractedFileCount: scan.extractedFileCount,
    extractionDepth: scan.extractionDepth,
    extractionNotes: scan.extractionNotes,
    sha256: scan.sha256,
    findings: findings.map((finding: any) => ({
      id: finding.id,
      // Normalize any legacy category that no longer matches the schema enum
      category: VALID_CATEGORIES.has(finding.category) ? finding.category : "Other Security Weaknesses",
      title: finding.title,
      severity: finding.severity,
      affectedPath: finding.affectedPath,
      description: finding.description,
      evidence: finding.evidence,
      confidence: finding.confidence,
      recommendation: finding.recommendation,
      cve: finding.cve,
      component: finding.component ?? null,
      componentVersion: finding.componentVersion ?? null,
      detectionSource: finding.detectionSource ?? null,
    })),
  };

  const parsed = GetScanResponse.safeParse(detail);
  if (!parsed.success) {
    // Log schema mismatch details for debugging but still return the raw data
    // so the frontend can render what it can
    logger.warn({ scanId: scan.id, issues: parsed.error.issues }, "GetScanResponse schema validation warning — returning raw detail");
    res.json(detail);
    return;
  }
  res.json(parsed.data);
});

router.get("/scans/:scanId/progress", requireAuth, async (req, res): Promise<void> => {
  const params = GetScanProgressParams.safeParse(req.params);
  if (!params.success) {
    res.status(400).json({ error: params.error.message });
    return;
  }
  const scan = await loadAccessibleScan(req, res, params.data.scanId);
  if (!scan) return;
  const progress = {
    scanId: scan.id,
    status: scan.status,
    percent: scan.progress,
    message: scan.progressMessage,
    stages: scan.progressStages,
  };
  res.json(GetScanProgressResponse.parse(progress));
});

router.get("/scans/:scanId/files", requireAuth, async (req, res): Promise<void> => {
  const params = ListScanFilesParams.safeParse(req.params);
  if (!params.success) {
    res.status(400).json({ error: params.error.message });
    return;
  }
  if (!(await loadAccessibleScan(req, res, params.data.scanId))) return;
  const files = await db.select().from(scanFilesTable).where(eq(scanFilesTable.scanId, params.data.scanId));
  res.json(ListScanFilesResponse.parse(files.map((file: any) => ({
    path: file.path,
    type: file.type,
    sizeBytes: file.sizeBytes,
    permissions: file.permissions,
    owner: file.owner,
    group: file.group,
    sha256: file.sha256,
    md5: file.md5,
    sha1: file.sha1,
    executable: file.executable === 1,
    suspicious: file.suspicious === 1,
    suspiciousReason: file.suspiciousReason,
    stringsCount: file.stringsCount,
    // Stored as an integer to avoid float drift; divided back at the edge.
    entropy: file.entropyMilli === null ? null : file.entropyMilli / 1000,
    binaryInfo: file.binaryInfo ?? null,
  }))));
});

router.get("/scans/:scanId/vulnerabilities", requireAuth, async (req, res): Promise<void> => {
  const params = ListScanVulnerabilitiesParams.safeParse(req.params);
  if (!params.success) {
    res.status(400).json({ error: params.error.message });
    return;
  }
  if (!(await loadAccessibleScan(req, res, params.data.scanId))) return;
  const findings = await db.select().from(vulnerabilityFindingsTable).where(eq(vulnerabilityFindingsTable.scanId, params.data.scanId));

  const VALID_CATEGORIES = new Set([
    "Hardcoded Credentials",
    "Insecure Configuration",
    "Outdated/Vulnerable Software",
    "Weak Cryptography",
    "Insecure Network Services",
    "Excessive/Unsafe File Permissions",
    "Sensitive Information Exposure",
    "Dangerous Commands/Code Execution Indicators",
    "Other Security Weaknesses",
  ]);

  const mapped = findings.map((finding: any) => ({
    id: finding.id,
    category: VALID_CATEGORIES.has(finding.category) ? finding.category : "Other Security Weaknesses",
    title: finding.title,
    severity: finding.severity,
    affectedPath: finding.affectedPath,
    description: finding.description,
    evidence: finding.evidence,
    confidence: finding.confidence,
    recommendation: finding.recommendation,
    cve: finding.cve,
    component: finding.component ?? null,
    componentVersion: finding.componentVersion ?? null,
    detectionSource: finding.detectionSource ?? null,
  }));

  const parsed = ListScanVulnerabilitiesResponse.safeParse(mapped);
  if (!parsed.success) {
    logger.warn({ scanId: params.data.scanId, issues: parsed.error.issues }, "ListScanVulnerabilitiesResponse schema validation warning — returning raw data");
    res.json(mapped);
    return;
  }
  res.json(parsed.data);
});

router.get("/scans/:scanId/report", requireAuth, requirePermission("report:download"), async (req, res): Promise<void> => {
  const params = GetScanReportParams.safeParse(req.params);
  if (!params.success) {
    res.status(400).json({ error: params.error.message });
    return;
  }
  const scan = await loadAccessibleScan(req, res, params.data.scanId);
  if (!scan) return;
  if (!scan.reportHtml || !scan.sha256) {
    res.status(404).json({ error: "Report is not ready yet.", code: "REPORT_NOT_READY" });
    return;
  }
  const report = {
    scanId: scan.id,
    title: `${scan.firmwareName} security report`,
    generatedAt: scan.completedAt ?? scan.createdAt,
    html: scan.reportHtml,
    sha256: createHash("sha256").update(scan.reportHtml).digest("hex"),
  };
  res.json(GetScanReportResponse.parse(report));
});

router.get("/scans/:scanId/report/pdf", requireAuth, requirePermission("report:download"), async (req, res): Promise<void> => {
  const params = GetScanReportParams.safeParse(req.params);
  if (!params.success) {
    res.status(400).json({ error: params.error.message });
    return;
  }
  const scan = await loadAccessibleScan(req, res, params.data.scanId);
  if (!scan) return;

  const findings = await db.select().from(vulnerabilityFindingsTable).where(eq(vulnerabilityFindingsTable.scanId, scan.id));

  try {
    const { generatePdfReportBuffer } = await import("../lib/reports/pdf-report");
    const pdfBuffer = await generatePdfReportBuffer({
      scanId: scan.id,
      firmwareName: scan.firmwareName,
      firmwareType: scan.firmwareType,
      sizeBytes: scan.sizeBytes,
      status: scan.status,
      riskScore: scan.riskScore,
      riskLevel: scan.riskLevel,
      sha256: scan.sha256,
      architecture: scan.architecture,
      operatingSystem: scan.operatingSystem,
      extractionStatus: scan.extractionStatus,
      extractedFileCount: scan.extractedFileCount,
      malwareIndicatorCount: scan.malwareIndicatorCount,
      findings: findings.map((f: any) => ({
        id: f.id,
        category: f.category,
        title: f.title,
        severity: f.severity,
        affectedPath: f.affectedPath,
        evidence: f.evidence,
        description: f.description,
        recommendation: f.recommendation,
        cve: f.cve ?? null,
        confidence: f.confidence,
        component: f.component ?? null,
        componentVersion: f.componentVersion ?? null,
        detectionSource: f.detectionSource ?? null,
      })),
    });

    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", `attachment; filename="${scan.firmwareName.replaceAll('"', '_')}-report.pdf"`);
    res.send(pdfBuffer);
  } catch (pdfErr) {
    res.status(500).json({ error: "Failed to generate PDF report" });
  }
});

export default router;