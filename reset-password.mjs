import { randomBytes, scrypt } from "node:crypto";
import pg from "pg";

const { Pool } = pg;

const email = process.argv[2] || "sivakrishnapothuraju3@gmail.com";
const newPassword = process.argv[3] || "SivaKrishna@123";

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

  const res = await pool.query(
    `UPDATE users 
     SET password_hash = $1, 
         password_salt = $2, 
         password_params = $3,
         failed_login_count = 0,
         locked_until = NULL
     WHERE LOWER(email) = LOWER($4)
     RETURNING id, email, name, role`,
    [hash, salt, JSON.stringify(params), email]
  );

  if (res.rowCount === 0) {
    console.error(`User with email "${email}" not found in database!`);
    await pool.end();
    process.exit(1);
  }

  console.log("✔ Password successfully updated for user:", res.rows[0]);
  console.log(`\nYou can now log in with:`);
  console.log(`Email:    ${res.rows[0].email}`);
  console.log(`Password: ${newPassword}\n`);
  await pool.end();
}

reset().catch(async (err) => {
  console.error("Failed to reset password:", err);
  await pool.end();
  process.exit(1);
});
