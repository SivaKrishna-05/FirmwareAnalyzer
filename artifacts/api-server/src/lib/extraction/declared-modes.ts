/**
 * Recovery of archive-declared file modes.
 *
 * We deliberately extract with --no-same-permissions (tar) and without
 * restoring modes (unzip), because faithfully recreating a setuid-root binary
 * from untrusted vendor firmware onto the analysis host is an unnecessary
 * risk. But setuid/setgid/world-writable bits are exactly what a firmware
 * audit needs to report.
 *
 * So we read the modes out of the archive's own listing instead. The analyst
 * gets the truth about what the image declares; the host never materialises
 * it. Where a format carries real modes on disk (SquashFS via unsquashfs),
 * the on-disk value is authoritative and this module is not consulted.
 */

import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

export interface DeclaredMode {
  /** Octal permission bits including setuid/setgid/sticky. */
  mode: number;
  /** Owner as named in the archive, when the format records it. */
  owner: string | null;
  group: string | null;
}

/** Convert a symbolic mode string (`-rwsr-xr-x`) into numeric permission bits. */
export function parseSymbolicMode(symbolic: string): number | null {
  const text = symbolic.trim();
  if (text.length < 10) return null;

  const body = text.slice(1, 10);
  let mode = 0;

  const triples: Array<{ read: number; write: number; execute: number; special: number; specialChars: [string, string] }> = [
    { read: 0o400, write: 0o200, execute: 0o100, special: 0o4000, specialChars: ["s", "S"] },
    { read: 0o040, write: 0o020, execute: 0o010, special: 0o2000, specialChars: ["s", "S"] },
    { read: 0o004, write: 0o002, execute: 0o001, special: 0o1000, specialChars: ["t", "T"] },
  ];

  for (let index = 0; index < 3; index += 1) {
    const chunk = body.slice(index * 3, index * 3 + 3);
    const triple = triples[index]!;
    if (chunk[0] === "r") mode |= triple.read;
    if (chunk[1] === "w") mode |= triple.write;

    const third = chunk[2];
    if (third === "x") {
      mode |= triple.execute;
    } else if (third === triple.specialChars[0]) {
      // Lowercase: the special bit AND the execute bit are both set.
      mode |= triple.execute | triple.special;
    } else if (third === triple.specialChars[1]) {
      // Uppercase: the special bit is set WITHOUT execute — unusual and
      // worth preserving faithfully, since it often indicates a mistake.
      mode |= triple.special;
    }
  }

  return mode;
}

/** Normalise an archive entry path to match the extractor's relative paths. */
function normaliseEntryPath(entry: string): string {
  let path = entry.trim().replaceAll("\\", "/");
  // tar commonly prefixes "./"; strip it so paths line up with the walk.
  while (path.startsWith("./")) path = path.slice(2);
  if (path.startsWith("/")) path = path.slice(1);
  // Directory entries carry a trailing slash in both formats.
  if (path.endsWith("/")) path = path.slice(0, -1);
  // A symlink listing renders as "link -> target"; keep only the link name.
  const arrow = path.indexOf(" -> ");
  if (arrow !== -1) path = path.slice(0, arrow);
  return path;
}

/**
 * `tar -tvf` renders one entry per line:
 *   -rwsr-xr-x root/root  139 2024-01-01 00:00 ./bin/backdoor.sh
 */
export async function readTarDeclaredModes(archive: string, timeoutMs: number): Promise<Map<string, DeclaredMode>> {
  const modes = new Map<string, DeclaredMode>();
  try {
    const { stdout } = await execFileAsync("tar", ["-tvf", archive], {
      timeout: timeoutMs,
      maxBuffer: 32 * 1024 * 1024,
    });

    for (const line of stdout.split("\n")) {
      if (line.trim().length === 0) continue;
      // Mode, owner/group, size, date, time, then the name (which may
      // contain spaces, so we split on a bounded number of fields).
      const match = /^([-dlbcpsSt][rwxsStT-]{9})\s+(\S+)\s+\d+\s+[\d-]+\s+[\d:]+\s+(.+)$/.exec(line);
      if (!match) continue;

      const mode = parseSymbolicMode(match[1]!);
      if (mode === null) continue;

      const ownerGroup = match[2]!.split("/");
      const path = normaliseEntryPath(match[3]!);
      if (path.length === 0) continue;

      modes.set(path, {
        mode,
        owner: ownerGroup[0] ?? null,
        group: ownerGroup[1] ?? null,
      });
    }
  } catch {
    // A listing failure is non-fatal: on-disk modes are still reported.
  }
  return modes;
}

/**
 * `unzip -Z` long listing renders:
 *   -rwsr-xr-x  3.0 unx  139 tx defN 24-Jan-01 00:00 rootfs/bin/backdoor.sh
 *
 * Note that ZIP only carries Unix modes when the archive was created on a
 * Unix host ("unx"); otherwise the mode column is not meaningful and we skip
 * the entry rather than inventing permissions for it.
 */
export async function readZipDeclaredModes(archive: string, timeoutMs: number): Promise<Map<string, DeclaredMode>> {
  const modes = new Map<string, DeclaredMode>();
  try {
    const { stdout } = await execFileAsync("unzip", ["-Z", archive], {
      timeout: timeoutMs,
      maxBuffer: 32 * 1024 * 1024,
    });

    for (const line of stdout.split("\n")) {
      const match = /^([-dl][rwxsStT-]{9})\s+\d+\.\d+\s+(\S+)\s+\d+\s+\S+\s+\S+\s+\S+\s+\S+\s+(.+)$/.exec(line);
      if (!match) continue;
      // Only Unix-originated entries carry real permission bits.
      if (match[2] !== "unx") continue;

      const mode = parseSymbolicMode(match[1]!);
      if (mode === null) continue;

      const path = normaliseEntryPath(match[3]!);
      if (path.length === 0) continue;

      modes.set(path, { mode, owner: null, group: null });
    }
  } catch {
    // Non-fatal, as above.
  }
  return modes;
}
