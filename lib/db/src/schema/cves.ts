import { integer, pgTable, text, timestamp } from "drizzle-orm/pg-core";

export const cveRecordsTable = pgTable("cve_records", {
  id: text("id").primaryKey(), // e.g. CVE-2023-48795
  component: text("component").notNull(), // e.g. dropbear
  vendor: text("vendor").notNull(),
  affectedVersion: text("affected_version"), // e.g. "< 2020.82"
  severity: text("severity").notNull().default("Medium"),
  cvssScore: integer("cvss_score"), // multiplied by 10 (e.g. 75 = 7.5)
  summary: text("summary").notNull(),
  sourceUrl: text("source_url"),
  createdAt: timestamp("created_at", { withTimezone: true })
    .notNull()
    .defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true })
    .notNull()
    .defaultNow(),
});

export const cveMetadataTable = pgTable("cve_metadata", {
  key: text("key").primaryKey(), // e.g. "sync_status"
  status: text("status").notNull().default("idle"), // idle, updating, completed, failed
  totalCount: integer("total_count").notNull().default(0),
  lastMessage: text("last_message"),
  lastUpdatedAt: timestamp("last_updated_at", { withTimezone: true })
    .notNull()
    .defaultNow(),
});
