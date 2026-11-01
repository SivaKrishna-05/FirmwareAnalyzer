import { migrate } from "drizzle-orm/node-postgres/migrator";
import { drizzle } from "drizzle-orm/node-postgres";
import pg from "pg";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const { Pool } = pg;

const databaseUrl =
  process.env.DATABASE_URL ||
  "postgresql://postgres:postgres@localhost:5432/iot_firmware";

const pool = new Pool({ connectionString: databaseUrl });
const db = drizzle(pool);

const migrationsFolder = path.resolve(__dirname, "../migrations");

console.log("Running DB migrations from:", migrationsFolder);

try {
  await migrate(db, { migrationsFolder });
  console.log("✔ All migrations applied successfully!");
  await pool.end();
  process.exit(0);
} catch (err) {
  console.error("❌ Migration failed:", err);
  await pool.end();
  process.exit(1);
}
