/**
 * Robust SemVer and embedded version comparator for firmware components.
 * Correctly compares:
 * - Numeric SemVer: 1.34.0 < 1.35.0
 * - Year-based versions: 2018.75 < 2018.76 < 2020.81
 * - Letter patch levels: OpenSSL 1.1.1j < 1.1.1k < 1.1.1n
 * - Patch release suffixes: OpenSSH 9.3p1 < 9.3p2 < 9.4
 */

export type VersionToken = number | string;

export function tokenizeVersion(v: string): VersionToken[] {
  const cleaned = v.replace(/^v/i, "").trim();
  const rawParts = cleaned.split(/[-+.]/);
  const tokens: VersionToken[] = [];

  for (const part of rawParts) {
    if (!part) continue;
    // Match consecutive runs of digits or letters within each segment (e.g., "9.3p1" -> ["9", "3", "p", 1])
    const subParts = part.match(/\d+|[a-zA-Z]+/g);
    if (!subParts) continue;
    for (const sp of subParts) {
      const n = Number.parseInt(sp, 10);
      tokens.push(Number.isNaN(n) ? sp.toLowerCase() : n);
    }
  }
  return tokens;
}

export function compareVersions(v1: string, v2: string): number {
  const p1 = tokenizeVersion(v1);
  const p2 = tokenizeVersion(v2);
  const len = Math.max(p1.length, p2.length);

  for (let i = 0; i < len; i++) {
    const t1 = p1[i];
    const t2 = p2[i];

    // If one version has no token at index i:
    // e.g. "9.3" vs "9.3p2": base release "9.3" comes before patch "9.3p2"
    if (t1 === undefined && t2 !== undefined) return -1;
    if (t1 !== undefined && t2 === undefined) return 1;

    if (typeof t1 === "number" && typeof t2 === "number") {
      if (t1 > t2) return 1;
      if (t1 < t2) return -1;
    } else {
      const s1 = String(t1);
      const s2 = String(t2);
      const c = s1.localeCompare(s2);
      if (c !== 0) return c > 0 ? 1 : -1;
    }
  }
  return 0;
}

export function isVersionAffected(targetVersion: string, affectedExpr: string): boolean {
  const expr = affectedExpr.trim();
  const matchOp = /^(<=|<|>=|>|=)?\s*([v\d\w.-]+)$/.exec(expr);
  if (!matchOp) return true;

  const op = matchOp[1] ?? "<=";
  const boundVer = matchOp[2];
  const cmp = compareVersions(targetVersion, boundVer);

  if (op === "<=") return cmp <= 0;
  if (op === "<") return cmp < 0;
  if (op === ">=") return cmp >= 0;
  if (op === ">") return cmp > 0;
  if (op === "=") return cmp === 0;
  return true;
}
