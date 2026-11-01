import { randomBytes, scrypt } from "node:crypto";
import pg from "pg";

const { Pool } = pg;

const email = process.argv[2] || "admin@example.com";
const newPassword = process.argv[3] || "AdminPassword@123";

const DEFAULT_PASSWORD_PARAMS = {
  algorithm: "scrypt",
  N: 32768,
  r: 8,
  p: 1,
  keyLength: 64,
};

function scryptAsync(password, salt, keyLength, options) {
  return new Promise((resolve, reject) => {
    scrypt(password, salt, keyLength, options, (error, derivedKey) => {
      if (error) reject(error);
      else resolve(derivedKey);
    });
  });
}

async function hashPassword(password) {
  const salt = randomBytes(32);
  const normalized = password.normalize("NFKC");
  const derived = await scryptAsync(normalized, salt, DEFAULT_PASSWORD_PARAMS.keyLength, {
    N: DEFAULT_PASSWORD_PARAMS.N,
    r: DEFAULT_PASSWORD_PARAMS.r,
    p: DEFAULT_PASSWORD_PARAMS.p,
    maxmem: 256 * DEFAULT_PASSWORD_PARAMS.N * DEFAULT_PASSWORD_PARAMS.r,
  });
  return {
    hash: derived.toString("base64"),
    salt: salt.toString("base64"),
    params: DEFAULT_PASSWORD_PARAMS,
  };
}

const databaseUrl =
  process.env.DATABASE_URL ||
  "postgresql://postgres:postgres@localhost:5432/iot_firmware";

const pool = new Pool({ connectionString: databaseUrl });

async function reset() {
  console.log(`Resetting password for: ${email}`);
  console.log(`New password: ${newPassword}`);

  const { hash, salt, params } = await hashPassword(newPassword);

  const client = await pool.connect();
  try {
    const res = await client.query(
      `UPDATE users
       SET password_hash = $1,
           password_salt = $2,
           password_params = $3::jsonb,
           failed_login_count = 0,
           locked_until = NULL
       WHERE LOWER(email) = LOWER($4)
       RETURNING id, email, name, role;`,
      [hash, salt, JSON.stringify(params), email]
    );

    if (res.rows.length === 0) {
      console.log(`User not found: ${email}`);
    } else {
      console.log("Password updated successfully:", res.rows[0]);
    }
  } finally {
    client.release();
    await pool.end();
  }
}

reset().catch((err) => {
  console.error("Password reset failed:", err);
  process.exit(1);
});
