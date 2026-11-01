/**
 * Password hashing.
 *
 * Uses scrypt from Node's standard library. scrypt is memory-hard and is an
 * appropriate choice for password storage (RFC 7914); it is preferred here
 * over bcrypt/argon2 because it needs no native dependency, which keeps the
 * deployment reproducible. The cost parameters are stored per-user so they
 * can be raised later without invalidating existing credentials.
 *
 * Rules enforced in this module:
 *   - a plaintext password is never logged, returned, or stored
 *   - verification is constant-time with respect to the hash
 *   - an unknown user still performs a full hash computation, so response
 *     timing does not reveal whether an email is registered
 */

import { randomBytes, scrypt, timingSafeEqual, type ScryptOptions } from "node:crypto";

/**
 * `promisify` cannot infer the options-bearing scrypt overload, so the
 * signature is declared explicitly. This keeps full type checking on the call
 * sites instead of falling back to `any`.
 */
const scryptAsync = (
  password: string,
  salt: Buffer,
  keyLength: number,
  options: ScryptOptions,
): Promise<Buffer> =>
  new Promise((resolve, reject) => {
    scrypt(password, salt, keyLength, options, (error, derivedKey) => {
      if (error) reject(error);
      else resolve(derivedKey);
    });
  });

export interface PasswordParams {
  algorithm: "scrypt";
  N: number;
  r: number;
  p: number;
  keyLength: number;
}

/**
 * N=2^15 costs roughly 100ms and ~32 MB per hash on typical hardware: high
 * enough to make offline cracking expensive, low enough that a login request
 * stays responsive. `maxmem` must be raised to match, since Node's default
 * 32 MB limit rejects these parameters.
 */
export const DEFAULT_PASSWORD_PARAMS: PasswordParams = Object.freeze({
  algorithm: "scrypt",
  N: 32768,
  r: 8,
  p: 1,
  keyLength: 64,
});

function maxmemFor(params: PasswordParams): number {
  // scrypt needs about 128 * N * r bytes; allow generous headroom.
  return 256 * params.N * params.r;
}

async function derive(password: string, salt: Buffer, params: PasswordParams): Promise<Buffer> {
  // Normalise to NFKC so a password typed with a different Unicode
  // composition still verifies — otherwise some non-ASCII passwords become
  // impossible to re-enter on a different keyboard or platform.
  const normalized = password.normalize("NFKC");
  return scryptAsync(normalized, salt, params.keyLength, {
    N: params.N,
    r: params.r,
    p: params.p,
    maxmem: maxmemFor(params),
  });
}

export interface HashedPassword {
  hash: string;
  salt: string;
  params: PasswordParams;
}

export async function hashPassword(
  password: string,
  params: PasswordParams = DEFAULT_PASSWORD_PARAMS,
): Promise<HashedPassword> {
  const salt = randomBytes(32);
  const derived = await derive(password, salt, params);
  return {
    hash: derived.toString("base64"),
    salt: salt.toString("base64"),
    params,
  };
}

/**
 * Verify a password against a stored hash.
 *
 * Returns false rather than throwing on malformed stored values: a corrupt
 * row must fail closed, not crash the login route.
 */
export async function verifyPassword(
  password: string,
  stored: { hash: string; salt: string; params: PasswordParams },
): Promise<boolean> {
  try {
    const salt = Buffer.from(stored.salt, "base64");
    const expected = Buffer.from(stored.hash, "base64");
    if (salt.length === 0 || expected.length === 0) return false;

    const actual = await derive(password, salt, stored.params);
    if (actual.length !== expected.length) return false;
    return timingSafeEqual(actual, expected);
  } catch {
    return false;
  }
}

/**
 * Burn an equivalent amount of CPU when the account does not exist.
 *
 * Without this, a missing user returns in microseconds while a real user
 * takes ~100ms, which turns the login endpoint into an account enumeration
 * oracle. The result is deliberately discarded.
 */
export async function dummyVerify(params: PasswordParams = DEFAULT_PASSWORD_PARAMS): Promise<void> {
  await derive("invalid-password-placeholder", Buffer.alloc(32, 7), params);
}

/** True when a stored hash was made with weaker parameters than current policy. */
export function needsRehash(params: PasswordParams): boolean {
  return (
    params.algorithm !== DEFAULT_PASSWORD_PARAMS.algorithm ||
    params.N < DEFAULT_PASSWORD_PARAMS.N ||
    params.r < DEFAULT_PASSWORD_PARAMS.r ||
    params.keyLength < DEFAULT_PASSWORD_PARAMS.keyLength
  );
}

export interface PasswordPolicyResult {
  ok: boolean;
  problems: string[];
}

/**
 * Minimum password policy. Length is weighted most heavily because it
 * contributes far more to resistance than composition rules do; the
 * composition checks exist only to reject the most obviously weak inputs.
 */
export function checkPasswordPolicy(password: string, context: { email?: string; name?: string } = {}): PasswordPolicyResult {
  const problems: string[] = [];

  if (password.length < 12) problems.push("must be at least 12 characters long");
  if (password.length > 512) problems.push("must be at most 512 characters long");
  if (!/[a-z]/.test(password) || !/[A-Z]/.test(password)) problems.push("must contain both upper and lower case letters");
  if (!/[0-9]/.test(password)) problems.push("must contain at least one digit");

  const lower = password.toLowerCase();
  const localPart = context.email?.split("@")[0]?.toLowerCase();
  if (localPart && localPart.length >= 3 && lower.includes(localPart)) {
    problems.push("must not contain your email address");
  }
  if (context.name && context.name.length >= 3 && lower.includes(context.name.toLowerCase())) {
    problems.push("must not contain your name");
  }

  // A small denylist of passwords that pass the composition rules above but
  // are near the top of every breach corpus.
  const common = ["password1234", "qwerty123456", "administrator1", "letmein12345", "welcome12345"];
  if (common.some((entry) => lower.includes(entry))) {
    problems.push("is too common");
  }

  return { ok: problems.length === 0, problems };
}
