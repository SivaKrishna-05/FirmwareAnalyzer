import { createInsertSchema } from "drizzle-zod";
import {
  integer,
  jsonb,
  pgTable,
  text,
  timestamp,
} from "drizzle-orm/pg-core";
import { z } from "zod/v4";

export const scansTable = pgTable("scans", {
  id: text("id").primaryKey(),
  /**
   * Owning user. Nullable only so the column can be added to a populated
   * database; new scans always set it. Rows with a null owner are treated as
   * admin-only by the access layer rather than as public.
   */
  userId: text("user_id"),
  firmwareName: text("firmware_name").notNull(),
  firmwareType: text("firmware_type").notNull(),
  sizeBytes: integer("size_bytes").notNull(),
  status: text("status").notNull().default("Uploaded"),
  riskScore: integer("risk_score"),
  riskLevel: text("risk_level"),
  vulnerabilityCount: integer("vulnerability_count").notNull().default(0),
  malwareIndicatorCount: integer("malware_indicator_count").notNull().default(0),
  createdAt: timestamp("created_at", { withTimezone: true })
    .notNull()
    .defaultNow(),
  completedAt: timestamp("completed_at", { withTimezone: true }),
  architecture: text("architecture"),
  operatingSystem: text("operating_system"),
  filesystem: text("filesystem"),
  extractionStatus: text("extraction_status").notNull().default("Not started"),
  // Which extractor actually ran (unzip / tar / unsquashfs / ubireader /
  // cpio / raw-carve / none). Recorded so a report never implies a
  // filesystem was unpacked when it was only fingerprinted.
  extractionMethod: text("extraction_method"),
  extractedFileCount: integer("extracted_file_count").notNull().default(0),
  extractionDepth: integer("extraction_depth").notNull().default(0),
  // Human-readable reason extraction stopped short, e.g. a missing
  // unsquashfs binary. Surfaced verbatim so gaps are visible, not hidden.
  extractionNotes: text("extraction_notes"),
  sha256: text("sha256"),
  progress: integer("progress").notNull().default(0),
  progressMessage: text("progress_message").notNull().default("Upload received"),
  progressStages: jsonb("progress_stages").$type<
    Array<{
      key: string;
      label: string;
      status: "pending" | "running" | "completed" | "failed" | "skipped";
      detail: string | null;
    }>
  >().notNull(),
  reportHtml: text("report_html"),
});

export const scanFilesTable = pgTable("scan_files", {
  id: text("id").primaryKey(),
  scanId: text("scan_id")
    .notNull()
    .references(() => scansTable.id, { onDelete: "cascade" }),
  path: text("path").notNull(),
  type: text("type").notNull(),
  sizeBytes: integer("size_bytes").notNull(),
  permissions: text("permissions"),
  owner: text("owner"),
  group: text("group"),
  sha256: text("sha256").notNull(),
  md5: text("md5"),
  sha1: text("sha1"),
  executable: integer("executable").notNull().default(0),
  suspicious: integer("suspicious").notNull().default(0),
  suspiciousReason: text("suspicious_reason"),
  stringsCount: integer("strings_count").notNull().default(0),
  // Shannon entropy over sampled bytes, 0-8. Stored x1000 as an integer to
  // avoid float drift across pg drivers; divided back down at the API edge.
  entropyMilli: integer("entropy_milli"),
  binaryInfo: jsonb("binary_info").$type<{
    architecture: string | null;
    endianness: string | null;
    entryPoint: string | null;
    interpreter: string | null;
    sections: string[];
    dynamicDependencies: string[];
    symbolCount: number | null;
  } | null>(),
});

export const vulnerabilityFindingsTable = pgTable("vulnerability_findings", {
  id: text("id").primaryKey(),
  scanId: text("scan_id")
    .notNull()
    .references(() => scansTable.id, { onDelete: "cascade" }),
  category: text("category").notNull(),
  title: text("title").notNull(),
  severity: text("severity").notNull(),
  affectedPath: text("affected_path").notNull(),
  description: text("description").notNull(),
  evidence: text("evidence").notNull(),
  confidence: text("confidence").notNull(),
  recommendation: text("recommendation").notNull(),
  cve: text("cve"),
  // Component this finding is about, when applicable (feeds a future CVE
  // match). Nullable: most findings — a weak permission, a plaintext telnet
  // config — are not about a specific piece of software.
  component: text("component"),
  componentVersion: text("component_version"),
  // How the finding was derived (which check/pattern produced it), so an
  // analyst auditing a result can see the exact rule rather than trusting
  // the description alone.
  detectionSource: text("detection_source"),
});

export const insertScanSchema = createInsertSchema(scansTable).omit({
  createdAt: true,
  completedAt: true,
});
export type InsertScan = z.infer<typeof insertScanSchema>;
export type Scan = typeof scansTable.$inferSelect;
export type ScanFile = typeof scanFilesTable.$inferSelect;
export type VulnerabilityFinding = typeof vulnerabilityFindingsTable.$inferSelect;