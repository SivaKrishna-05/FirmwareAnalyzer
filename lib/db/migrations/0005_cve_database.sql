CREATE TABLE IF NOT EXISTS "cve_records" (
	"id" text PRIMARY KEY NOT NULL,
	"component" text NOT NULL,
	"vendor" text NOT NULL,
	"affected_version" text,
	"severity" text DEFAULT 'Medium' NOT NULL,
	"cvss_score" integer,
	"summary" text NOT NULL,
	"source_url" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE IF NOT EXISTS "cve_metadata" (
	"key" text PRIMARY KEY NOT NULL,
	"status" text DEFAULT 'idle' NOT NULL,
	"total_count" integer DEFAULT 0 NOT NULL,
	"last_message" text,
	"last_updated_at" timestamp with time zone DEFAULT now() NOT NULL
);

CREATE INDEX IF NOT EXISTS "cve_records_component_idx" ON "cve_records" ("component");
