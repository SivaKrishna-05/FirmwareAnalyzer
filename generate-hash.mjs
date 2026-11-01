import { randomBytes, scrypt } from "node:crypto";

const newPassword = process.argv[2] || "SivaKrishna@123";

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

const salt = randomBytes(32);
const normalized = newPassword.normalize("NFKC");
const derived = await scryptAsync(normalized, salt, DEFAULT_PASSWORD_PARAMS.keyLength, {
  N: DEFAULT_PASSWORD_PARAMS.N,
  r: DEFAULT_PASSWORD_PARAMS.r,
  p: DEFAULT_PASSWORD_PARAMS.p,
  maxmem: 256 * DEFAULT_PASSWORD_PARAMS.N * DEFAULT_PASSWORD_PARAMS.r,
});

const hashB64 = derived.toString("base64");
const saltB64 = salt.toString("base64");
const paramsJson = JSON.stringify(DEFAULT_PASSWORD_PARAMS);

console.log(`${hashB64}\n${saltB64}\n${paramsJson}`);
