import { boolean, pgTable, text, timestamp } from "drizzle-orm/pg-core";

export const userSettingsTable = pgTable("user_settings", {
  userId: text("user_id").primaryKey(),
  telemetry: boolean("telemetry").notNull().default(false),
  deepAnalysis: boolean("deep_analysis").notNull().default(true),
  updatedAt: timestamp("updated_at", { withTimezone: true })
    .notNull()
    .defaultNow(),
});
