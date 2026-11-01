import PDFDocument from "pdfkit";

export interface PdfReportItem {
  id?: string;
  category: string;
  title: string;
  severity: string;
  affectedPath: string;
  description?: string;
  evidence?: string;
  recommendation?: string;
  cve?: string | null;
  confidence?: string;
  component?: string | null;
  componentVersion?: string | null;
  detectionSource?: string | null;
}

export interface PdfReportData {
  scanId: string;
  firmwareName: string;
  firmwareType: string;
  sizeBytes: number;
  status: string;
  riskScore: number | null;
  riskLevel: string | null;
  sha256: string | null;
  architecture?: string | null;
  operatingSystem?: string | null;
  filesystem?: string | null;
  extractionStatus?: string | null;
  extractedFileCount?: number;
  malwareIndicatorCount?: number;
  findings: PdfReportItem[];
}

export function generatePdfReportBuffer(data: PdfReportData, options?: { compress?: boolean }): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({ margin: 40, compress: options?.compress ?? false });
    const chunks: Buffer[] = [];

    doc.on("data", (chunk: Buffer) => chunks.push(chunk));
    doc.on("end", () => resolve(Buffer.concat(chunks)));
    doc.on("error", (err: Error) => reject(err));

    // Header
    doc.fontSize(22).fillColor("#1E293B").text("IoT Firmware Security Report", { align: "left" });
    doc.fontSize(9).fillColor("#64748B").text(`Scan ID: ${data.scanId}  |  Generated: ${new Date().toISOString().split("T")[0]}`);
    doc.moveDown(1.2);

    // Executive Summary Box
    doc.fontSize(13).fillColor("#0F172A").text("Executive Summary");
    doc.moveDown(0.4);
    doc.fontSize(9.5).fillColor("#334155");
    doc.text(`Firmware Name: ${data.firmwareName}`);
    doc.text(`Format: ${data.firmwareType} (${(data.sizeBytes / 1024 / 1024).toFixed(2)} MB)`);
    doc.text(`SHA-256: ${data.sha256 ?? "N/A"}`);
    doc.text(`Architecture: ${data.architecture ?? "Unknown"}  |  OS: ${data.operatingSystem ?? "Linux/Embedded"}`);
    if (data.extractionStatus) {
      doc.text(`Extraction: ${data.extractionStatus} (${data.extractedFileCount ?? 0} files recovered)`);
    }
    const scoreText = data.riskScore !== null ? `${data.riskScore}/100 [${data.riskLevel ?? "INFO"} Risk]` : "Unassessed / Extraction Incomplete";
    doc.text(`Risk Assessment: ${scoreText}  |  Malware Indicators: ${data.malwareIndicatorCount ?? 0}`);
    doc.moveDown(1.2);

    // Component & CVE Status Overview
    const componentsWithFindings = data.findings.filter((f) => f.component);
    const uniqueComponents = [...new Map(componentsWithFindings.map((f) => [f.component!.toLowerCase(), f])).values()];

    if (uniqueComponents.length > 0) {
      doc.fontSize(12).fillColor("#0F172A").text("Identified Software Components & Vulnerabilities");
      doc.moveDown(0.3);
      doc.fontSize(9).fillColor("#475569");
      for (const comp of uniqueComponents) {
        const verStr = comp.componentVersion ? `v${comp.componentVersion}` : "Version Unknown (Unassessed for matching CVEs)";
        const cveCount = data.findings.filter((f) => f.component?.toLowerCase() === comp.component?.toLowerCase() && f.cve).length;
        doc.text(`• ${comp.component} (${verStr}) — ${cveCount > 0 ? `${cveCount} CVE match(es) correlated` : "No matching CVEs detected"}`);
      }
      doc.moveDown(1.2);
    }

    // Findings Section
    doc.fontSize(13).fillColor("#0F172A").text(`Vulnerability & Risk Findings (${data.findings.length})`);
    doc.moveDown(0.4);

    if (data.findings.length === 0) {
      if (data.riskScore === null) {
        doc.fontSize(9.5).fillColor("#9A3412").text("NOTICE: Firmware analysis was incomplete because the filesystem could not be extracted (unsupported container or missing extraction tool). The absence of findings does NOT indicate the firmware is safe.");
      } else {
        doc.fontSize(9.5).fillColor("#166534").text("No security vulnerabilities or malware indicators were detected in the extracted filesystem.");
      }
    } else {
      for (let i = 0; i < data.findings.length; i++) {
        const f = data.findings[i];
        const sevColor = f.severity === "Critical" ? "#991B1B" : f.severity === "High" ? "#C2410C" : f.severity === "Medium" ? "#D97706" : "#2563EB";

        doc.fontSize(10.5).fillColor(sevColor).text(`[${f.severity.toUpperCase()}] ${f.title}`);
        doc.fontSize(8.5).fillColor("#475569").text(`Category: ${f.category}  |  Path: ${f.affectedPath ?? "N/A"}`);

        if (f.cve) {
          doc.fontSize(8.5).fillColor("#1D4ED8").text(`CVE: ${f.cve}  |  Confidence: ${f.confidence ?? "medium"}`);
        }
        if (f.component) {
          doc.fontSize(8.5).fillColor("#047857").text(`Component: ${f.component}${f.componentVersion ? ` ${f.componentVersion}` : " (version unknown)"}  |  Source: ${f.detectionSource ?? "Static Analysis"}`);
        } else if (f.detectionSource) {
          doc.fontSize(8.5).fillColor("#64748B").text(`Detection Source: ${f.detectionSource}`);
        }
        if (f.description) {
          doc.fontSize(8.5).fillColor("#334155").text(`Summary: ${f.description}`);
        }
        if (f.evidence) {
          doc.fontSize(8).fillColor("#64748B").text(`Evidence: ${f.evidence.slice(0, 160)}${f.evidence.length > 160 ? "..." : ""}`);
        }
        if (f.recommendation) {
          doc.fontSize(8).fillColor("#4338CA").text(`Remediation: ${f.recommendation}`);
        }
        doc.moveDown(0.7);

        // Page break if getting close to page bottom
        if (doc.y > 690 && i < data.findings.length - 1) {
          doc.addPage();
        }
      }
    }

    doc.moveDown(1);
    doc.fontSize(8).fillColor("#94A3B8").text("Assessment conducted via static analysis and verified signatures. Temporary files purged immediately after scan completion.", { align: "center" });

    doc.end();
  });
}
