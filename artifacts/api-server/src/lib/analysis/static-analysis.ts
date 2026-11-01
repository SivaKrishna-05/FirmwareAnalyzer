/**
 * Static analysis of an extracted firmware filesystem.
 *
 * Everything reported here is derived from bytes actually present on disk.
 * Where a signal requires a tool we do not have, the field is null and the
 * reason is recorded — it is never guessed at or filled with a plausible
 * placeholder.
 */

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { readdir, lstat, readFile, readlink, open } from "node:fs/promises";
import { join, relative, sep } from "node:path";
import { createHash } from "node:crypto";
import { shannonEntropy } from "../extraction/formats";
import { hasTool } from "../extraction/tools";

const execFileAsync = promisify(execFile);

export interface BinaryInfo {
  architecture: string | null;
  endianness: string | null;
  entryPoint: string | null;
  interpreter: string | null;
  sections: string[];
  dynamicDependencies: string[];
  symbolCount: number | null;
}

export interface AnalyzedFile {
  /**
   * Path as it appears inside the firmware's own filesystem, e.g.
   * "/bin/busybox". This is what an analyst sees and what findings cite —
   * the sandbox and nested-extraction directories are an implementation
   * detail and must never leak into a report.
   */
  path: string;
  /**
   * Full sandbox-relative path including every extraction layer. Retained so
   * a finding can be traced back to the exact container it came from.
   */
  sandboxPath: string;
  type: string;
  sizeBytes: number;
  permissions: string | null;
  owner: string | null;
  group: string | null;
  sha256: string;
  md5: string | null;
  sha1: string | null;
  executable: boolean;
  suspicious: boolean;
  suspiciousReason: string | null;
  stringsCount: number;
  entropy: number | null;
  binaryInfo: BinaryInfo | null;
  /** Set for symlinks; used by permission analysis, not persisted directly. */
  symlinkTarget: string | null;
  isSetuid: boolean;
  isSetgid: boolean;
  isWorldWritable: boolean;
}

export interface FilesystemProfile {
  architecture: string | null;
  operatingSystem: string | null;
  /** Evidence backing the OS identification, so the claim is auditable. */
  osEvidence: string | null;
  initSystem: string | null;
  /** Packages/components with versions, feeding the future CVE stage. */
  components: Array<{ name: string; version: string | null; source: string }>;
}

export interface StaticAnalysisResult {
  files: AnalyzedFile[];
  profile: FilesystemProfile;
  notes: string[];
  truncated: boolean;
}

const MAX_FILES = 20_000;
const HASH_SIZE_LIMIT = 256 * 1024 * 1024;
const STRINGS_SAMPLE_LIMIT = 4 * 1024 * 1024;
const MIN_STRING_LENGTH = 4;

/** ELF e_machine → human architecture. Values from the ELF spec. */
const ELF_MACHINES: Record<number, string> = {
  0x02: "SPARC",
  0x03: "x86",
  0x08: "MIPS",
  0x14: "PowerPC",
  0x15: "PowerPC64",
  0x16: "S390",
  0x28: "ARM",
  0x2a: "SuperH",
  0x32: "IA-64",
  0x3e: "x86-64",
  0x53: "AVR",
  0x8c: "TI MSP430",
  0xb7: "AArch64",
  0xf3: "RISC-V",
  0xf7: "BPF",
};

function toPosix(path: string): string {
  return path.split(sep).join("/");
}

function octalMode(mode: number): string {
  return (mode & 0o7777).toString(8).padStart(4, "0");
}

/**
 * Parse the ELF header directly rather than shelling out. This always works,
 * even when binutils is absent, and gives us architecture for every binary.
 */
function parseElfHeader(head: Buffer): { architecture: string | null; endianness: string | null; bits: number | null; entryPoint: string | null } | null {
  if (head.length < 20) return null;
  if (head[0] !== 0x7f || head[1] !== 0x45 || head[2] !== 0x4c || head[3] !== 0x46) return null;

  const bits = head[4] === 1 ? 32 : head[4] === 2 ? 64 : null;
  const little = head[5] === 1;
  const endianness = head[5] === 1 ? "little-endian" : head[5] === 2 ? "big-endian" : null;

  const machine = little ? head.readUInt16LE(18) : head.readUInt16BE(18);
  const architecture = ELF_MACHINES[machine] ?? `unknown (e_machine 0x${machine.toString(16)})`;

  let entryPoint: string | null = null;
  try {
    if (bits === 32 && head.length >= 28) {
      const value = little ? head.readUInt32LE(24) : head.readUInt32BE(24);
      entryPoint = `0x${value.toString(16)}`;
    } else if (bits === 64 && head.length >= 32) {
      const value = little ? head.readBigUInt64LE(24) : head.readBigUInt64BE(24);
      entryPoint = `0x${value.toString(16)}`;
    }
  } catch {
    entryPoint = null;
  }

  return { architecture: bits ? `${architecture} (${bits}-bit)` : architecture, endianness, bits, entryPoint };
}

/** Enrich ELF metadata via readelf when binutils is present. */
async function readelfDetails(path: string): Promise<Partial<BinaryInfo>> {
  if (!(await hasTool("readelf"))) return {};
  try {
    const { stdout } = await execFileAsync("readelf", ["-dSh", "-W", path], {
      timeout: 15_000,
      maxBuffer: 4 * 1024 * 1024,
    });

    const sections: string[] = [];
    const sectionPattern = /^\s*\[\s*\d+\]\s+(\S+)/gm;
    let match: RegExpExecArray | null;
    while ((match = sectionPattern.exec(stdout)) !== null) {
      if (match[1] && match[1] !== "NULL") sections.push(match[1]);
    }

    const dependencies: string[] = [];
    const neededPattern = /NEEDED\)\s+Shared library:\s+\[([^\]]+)\]/g;
    while ((match = neededPattern.exec(stdout)) !== null) {
      if (match[1]) dependencies.push(match[1]);
    }

    return { sections: sections.slice(0, 60), dynamicDependencies: dependencies.slice(0, 60) };
  } catch {
    return {};
  }
}

/** Read the PT_INTERP program header value — reveals the libc in use. */
async function readInterpreter(path: string): Promise<string | null> {
  if (!(await hasTool("readelf"))) return null;
  try {
    const { stdout } = await execFileAsync("readelf", ["-l", "-W", path], {
      timeout: 15_000,
      maxBuffer: 2 * 1024 * 1024,
    });
    const match = /\[Requesting program interpreter:\s*([^\]]+)\]/.exec(stdout);
    return match?.[1]?.trim() ?? null;
  } catch {
    return null;
  }
}

async function countSymbols(path: string): Promise<number | null> {
  if (!(await hasTool("readelf"))) return null;
  try {
    const { stdout } = await execFileAsync("readelf", ["-s", "-W", path], {
      timeout: 15_000,
      maxBuffer: 8 * 1024 * 1024,
    });
    const matches = stdout.match(/^\s*\d+:\s/gm);
    return matches ? matches.length : 0;
  } catch {
    return null;
  }
}

/**
 * Extract printable ASCII runs, the same way `strings(1)` does.
 * Implemented in-process so the count is available even without binutils.
 */
export function extractStrings(buffer: Buffer, minLength = MIN_STRING_LENGTH): string[] {
  const results: string[] = [];
  let current: number[] = [];

  const limit = Math.min(buffer.length, STRINGS_SAMPLE_LIMIT);
  for (let i = 0; i < limit; i += 1) {
    const byte = buffer[i]!;
    // Printable ASCII plus tab.
    if ((byte >= 0x20 && byte <= 0x7e) || byte === 0x09) {
      current.push(byte);
    } else {
      if (current.length >= minLength) {
        results.push(Buffer.from(current).toString("latin1"));
      }
      current = [];
    }
  }
  if (current.length >= minLength) {
    results.push(Buffer.from(current).toString("latin1"));
  }
  return results;
}

/**
 * Map an extracted /etc/passwd and /etc/group so numeric uid/gid values can
 * be resolved to the names the *firmware* uses, not the host's.
 *
 * `rootfsPrefix` locates the filesystem root inside the extraction sandbox;
 * passing it explicitly keeps this usable before the profile is built.
 */
async function loadIdMaps(
  root: string,
  rootfsPrefix: string,
): Promise<{ users: Map<number, string>; groups: Map<number, string> }> {
  const users = new Map<number, string>();
  const groups = new Map<number, string>();

  for (const candidate of ["etc/passwd", "etc/group"]) {
    try {
      const content = await readFile(
        rootfsPrefix ? join(root, rootfsPrefix, candidate) : join(root, candidate),
        "utf8",
      );
      for (const line of content.split("\n")) {
        const fields = line.split(":");
        if (fields.length < 3) continue;
        const name = fields[0]?.trim();
        const id = Number.parseInt(fields[2] ?? "", 10);
        if (!name || Number.isNaN(id)) continue;
        if (candidate.endsWith("passwd")) users.set(id, name);
        else groups.set(id, name);
      }
    } catch {
      // Absent passwd/group is normal for many images; ids stay numeric.
    }
  }
  return { users, groups };
}

/** Classify a file by magic bytes, falling back to a generic label. */
function classifyType(head: Buffer, isSymlink: boolean, isDirectory: boolean): string {
  if (isDirectory) return "directory";
  if (isSymlink) return "symlink";
  if (head.length === 0) return "empty file";
  if (head.length >= 4 && head[0] === 0x7f && head[1] === 0x45 && head[2] === 0x4c && head[3] === 0x46) return "ELF binary";
  if (head.length >= 2 && head[0] === 0x23 && head[1] === 0x21) return "script (shebang)";
  if (head.length >= 4 && head[0] === 0x50 && head[1] === 0x4b) return "ZIP archive";
  if (head.length >= 2 && head[0] === 0x1f && head[1] === 0x8b) return "gzip stream";
  if (head.length >= 4 && head[0] === 0x68 && head[1] === 0x73 && head[2] === 0x71 && head[3] === 0x73) return "SquashFS image";

  // Heuristic text detection: no NULs and mostly printable in the sample.
  const sample = head.subarray(0, Math.min(head.length, 1024));
  let printable = 0;
  let hasNull = false;
  for (const byte of sample) {
    if (byte === 0) { hasNull = true; break; }
    if ((byte >= 0x20 && byte <= 0x7e) || byte === 0x09 || byte === 0x0a || byte === 0x0d) printable += 1;
  }
  if (!hasNull && printable / Math.max(sample.length, 1) > 0.9) return "text";
  return "binary data";
}

/**
 * Flag a file as suspicious with a concrete, stated reason.
 * Every reason here is something an analyst can independently verify.
 */
function assessSuspicion(
  path: string,
  mode: number,
  entropy: number | null,
  type: string,
  isSymlink: boolean,
  symlinkTarget: string | null,
): { suspicious: boolean; reason: string | null } {
  const reasons: string[] = [];

  if ((mode & 0o4000) !== 0) reasons.push("setuid bit is set");
  if ((mode & 0o2000) !== 0) reasons.push("setgid bit is set");
  if ((mode & 0o0002) !== 0) reasons.push("world-writable");

  if (isSymlink && symlinkTarget && (symlinkTarget.startsWith("/") || symlinkTarget.includes(".."))) {
    reasons.push(`symlink escapes its directory (target ${symlinkTarget.slice(0, 80)})`);
  }

  // High entropy is a packing/encryption signal — but only where it is not
  // expected. Compressed containers and archives are high-entropy by
  // construction, and flagging them produces noise that trains an analyst to
  // ignore the column entirely.
  const entropyExpected = /archive|stream|image|compressed/i.test(type);
  if (entropy !== null && entropy > 7.5 && !entropyExpected && type !== "binary data") {
    reasons.push(`high entropy (${entropy.toFixed(2)}) for a ${type}`);
  }

  const lower = path.toLowerCase();
  if (/(^|\/)\.[^/]+$/.test(lower) && /(ssh|history|netrc|aws|git)/.test(lower)) {
    reasons.push("hidden credential-bearing dotfile");
  }
  if (/\/(tmp|dev|proc)\/.+\.(sh|elf|bin)$/.test(lower)) {
    reasons.push("executable staged in a volatile directory");
  }

  return {
    suspicious: reasons.length > 0,
    reason: reasons.length > 0 ? reasons.join("; ") : null,
  };
}

/**
 * Find the directory within the extracted tree that is the actual filesystem
 * root, expressed as a prefix relative to the sandbox (empty string when the
 * sandbox root is itself the rootfs).
 *
 * Scoring is evidence-based: a real Unix root has /etc plus at least one of
 * bin, sbin, usr or lib. The shallowest directory satisfying that wins, since
 * nested extraction layers only ever add depth.
 */
export function findRootfsPrefix(files: AnalyzedFile[]): string {
  const directories = new Set<string>();
  for (const file of files) {
    const parts = file.sandboxPath.split("/");
    for (let i = 0; i < parts.length; i += 1) {
      directories.add(parts.slice(0, i).join("/"));
    }
  }

  const hasChildDir = (prefix: string, name: string): boolean => {
    const needle = prefix ? `${prefix}/${name}/` : `${name}/`;
    return files.some((file) => file.sandboxPath.startsWith(needle));
  };

  const candidates: Array<{ prefix: string; score: number; depth: number }> = [];
  for (const prefix of directories) {
    if (!hasChildDir(prefix, "etc")) continue;
    let score = 1;
    for (const marker of ["bin", "sbin", "usr", "lib", "var", "dev"]) {
      if (hasChildDir(prefix, marker)) score += 1;
    }
    if (score < 2) continue;
    candidates.push({ prefix, score, depth: prefix === "" ? 0 : prefix.split("/").length });
  }

  if (candidates.length === 0) return "";
  // Highest evidence score first; break ties by shallowest path.
  candidates.sort((a, b) => (b.score - a.score) || (a.depth - b.depth));
  return candidates[0]!.prefix;
}

/**
 * Identify the OS and userland from real evidence in the extracted tree.
 * Returns nulls rather than guesses when no marker file is present.
 */
async function profileFilesystem(root: string, files: AnalyzedFile[]): Promise<FilesystemProfile> {
  const components: FilesystemProfile["components"] = [];
  let operatingSystem: string | null = null;
  let osEvidence: string | null = null;
  let initSystem: string | null = null;

  // The extracted rootfs is almost never the sandbox root: it sits under one
  // or more `_extracted_*` layers, and vendors often wrap it in an extra
  // directory. Locate it by evidence before looking for any marker file,
  // otherwise every lookup below silently misses and we wrongly report
  // "not identified" on an image we fully unpacked.
  const rootfsPrefix = findRootfsPrefix(files);
  const atRootfs = (relativePath: string): string =>
    rootfsPrefix ? join(root, rootfsPrefix, relativePath) : join(root, relativePath);

  // os-release is the most authoritative marker when present.
  for (const candidate of ["etc/os-release", "usr/lib/os-release"]) {
    try {
      const content = await readFile(atRootfs(candidate), "utf8");
      const pretty = /^PRETTY_NAME="?([^"\n]+)"?/m.exec(content)?.[1];
      const name = /^NAME="?([^"\n]+)"?/m.exec(content)?.[1];
      const version = /^VERSION_ID="?([^"\n]+)"?/m.exec(content)?.[1];
      if (pretty || name) {
        operatingSystem = pretty ?? `${name}${version ? ` ${version}` : ""}`;
        osEvidence = `/${candidate}`;
        break;
      }
    } catch {
      // continue
    }
  }

  if (!operatingSystem) {
    const markers: Array<{ file: string; label: string }> = [
      { file: "etc/openwrt_release", label: "OpenWrt" },
      { file: "etc/openwrt_version", label: "OpenWrt" },
      { file: "etc/dd-wrt_release", label: "DD-WRT" },
      { file: "etc/debian_version", label: "Debian-based Linux" },
      { file: "etc/alpine-release", label: "Alpine Linux" },
      { file: "etc/redhat-release", label: "RHEL-based Linux" },
      { file: "etc/buildroot-release", label: "Buildroot Linux" },
    ];
    for (const marker of markers) {
      try {
        const content = (await readFile(atRootfs(marker.file), "utf8")).trim();
        operatingSystem = content ? `${marker.label} (${content.split("\n")[0]?.slice(0, 60)})` : marker.label;
        osEvidence = `/${marker.file}`;
        break;
      } catch {
        // continue
      }
    }
  }

  // Fall back to structural evidence rather than claiming nothing at all.
  if (!operatingSystem) {
    const hasLinuxLayout = files.some((file) => /^\/(bin|sbin|etc|usr\/bin|lib)\//.test(file.path));
    if (hasLinuxLayout) {
      operatingSystem = "Linux-based (distribution not identified)";
      osEvidence = "standard Linux directory layout present; no release file found";
    }
  }

  // Init system, which tells an analyst how services are started.
  const initMarkers: Array<{ path: string; label: string }> = [
    { path: "etc/init.d", label: "SysV init / BusyBox init" },
    { path: "lib/systemd/systemd", label: "systemd" },
    { path: "usr/lib/systemd/systemd", label: "systemd" },
    { path: "etc/inittab", label: "inittab-driven init" },
    { path: "sbin/procd", label: "procd (OpenWrt)" },
  ];
  for (const marker of initMarkers) {
    // Paths have already been rebased to the firmware's own root, so match
    // against the leading-slash form rather than the sandbox layout.
    const markerPath = `/${marker.path}`;
    if (files.some((file) => file.path === markerPath || file.path.startsWith(`${markerPath}/`))) {
      initSystem = marker.label;
      break;
    }
  }

  // Component inventory. These feed the CVE stage later; each records where
  // the version string came from so the match can be audited.
  try {
    const busybox = files.find((file) => /(^|\/)busybox$/.test(file.sandboxPath));
    if (busybox) {
      // Read via the sandbox path; `path` is the firmware-relative display
      // form and does not resolve on our filesystem.
      const buffer = await readFile(join(root, busybox.sandboxPath)).catch(() => null);
      if (buffer) {
        const version = /BusyBox\s+v(\d+\.\d+\.\d+)/.exec(buffer.toString("latin1"))?.[1] ?? null;
        components.push({ name: "busybox", version, source: `${busybox.path} (embedded version string)` });
      }
    }
  } catch {
    // non-fatal
  }

  // Dropbear, OpenSSL, lighttpd, OpenSSH, nginx, curl and friends embed a version banner.
  const bannerTargets: Array<{ match: RegExp; name: string; version: RegExp }> = [
    { match: /(^|\/)dropbear(multi)?$/, name: "dropbear", version: /[Dd]ropbear[_ ]v?(\d+\.\d+)/ },
    { match: /(^|\/)libcrypto\.so/, name: "openssl", version: /OpenSSL\s+(\d+\.\d+\.\d+[a-z]?)/ },
    { match: /(^|\/)lighttpd$/, name: "lighttpd", version: /lighttpd[/-](\d+\.\d+\.\d+)/ },
    { match: /(^|\/)uhttpd$/, name: "uhttpd", version: /uhttpd[/-](\d+[\w.]*)/ },
    { match: /(^|\/)dnsmasq$/, name: "dnsmasq", version: /dnsmasq[- ]v?(\d+\.\d+)/ },
    { match: /(^|\/)sshd?$/, name: "openssh", version: /OpenSSH[_-](\d+\.\d+[p\d]*)/i },
    { match: /(^|\/)nginx$/, name: "nginx", version: /nginx[/-](\d+\.\d+\.\d+)/i },
    { match: /(^|\/)(curl|libcurl\.so.*)$/, name: "curl", version: /curl[ /-](\d+\.\d+\.\d+)/i },
    { match: /(^|\/)libwolfssl\.so/, name: "wolfssl", version: /wolfSSL[ _-]v?(\d+\.\d+\.\d+)/i },
    { match: /(^|\/)libmbed(tls|crypto)\.so/, name: "mbedtls", version: /mbed\s*TLS\s*(\d+\.\d+\.\d+)/i },
    { match: /(^|\/)boa$/, name: "boa", version: /Boa[/-](\d+\.\d+[\w.]*)/i },
    { match: /(^|\/)thttpd$/, name: "thttpd", version: /thttpd[/-](\d+\.\d+[\w.]*)/i },
    { match: /(^|\/)mini_httpd$/, name: "mini_httpd", version: /mini_httpd[/-](\d+\.\d+[\w.]*)/i },
    { match: /(^|\/)smbd$/, name: "samba", version: /Samba[ -]v?(\d+\.\d+\.\d+)/i },
    { match: /(^|\/)(sqlite3|libsqlite3\.so.*)$/, name: "sqlite", version: /3\.\d+\.\d+/ },
    { match: /(^|\/)mosquitto$/, name: "mosquitto", version: /mosquitto\s+version\s+(\d+\.\d+\.\d+)/i },
    { match: /(^|\/)hostapd$/, name: "hostapd", version: /hostapd\s+v?(\d+\.\d+)/i },
    { match: /(^|\/)wpa_supplicant$/, name: "wpa_supplicant", version: /wpa_supplicant\s+v?(\d+\.\d+)/i },
    { match: /(^|\/)iptables$/, name: "iptables", version: /iptables\s+v(\d+\.\d+\.\d+)/i },
  ];

  for (const target of bannerTargets) {
    const file = files.find((candidate) => target.match.test(candidate.sandboxPath));
    if (!file) continue;
    try {
      const buffer = await readFile(join(root, file.sandboxPath));
      const text = buffer.toString("latin1");
      const version = target.version.exec(text)?.[1] ?? null;
      components.push({
        name: target.name,
        version,
        source: version ? `${file.path} (embedded version string)` : `${file.path} (version unverified; assessed as unknown)`,
      });
    } catch {
      // non-fatal
    }
  }

  // Architecture: take the most common one across real ELF binaries, which is
  // more reliable than trusting any single file.
  const archCounts = new Map<string, number>();
  for (const file of files) {
    const arch = file.binaryInfo?.architecture;
    if (arch) archCounts.set(arch, (archCounts.get(arch) ?? 0) + 1);
  }
  const architecture = [...archCounts.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] ?? null;

  return { architecture, operatingSystem, osEvidence, initSystem, components };
}

/**
 * Walk the extracted tree and analyze every regular file.
 */
export async function analyzeExtractedTree(
  root: string,
  options: { declaredModes?: Map<string, { mode: number; owner: string | null; group: string | null }> } = {},
): Promise<StaticAnalysisResult> {
  const declaredModes = options.declaredModes ?? new Map();
  const files: AnalyzedFile[] = [];
  const notes: string[] = [];
  let truncated = false;

  // uid/gid are captured during the walk and resolved to names afterwards:
  // the passwd/group files we resolve against live inside the extracted
  // rootfs, whose location we only know once the walk has produced paths.
  const rawIds = new Map<string, { uid: number; gid: number }>();

  const stack: string[] = [root];
  while (stack.length > 0 && files.length < MAX_FILES) {
    const current = stack.pop()!;
    let entries;
    try {
      entries = await readdir(current, { withFileTypes: true });
    } catch (error) {
      notes.push(`could not read ${toPosix(relative(root, current))}: ${(error as Error).message.slice(0, 120)}`);
      continue;
    }

    for (const entry of entries) {
      if (files.length >= MAX_FILES) {
        truncated = true;
        break;
      }
      const fullPath = join(current, entry.name);
      const relativePath = toPosix(relative(root, fullPath));
      if (relativePath.length === 0) continue;

      let info;
      try {
        info = await lstat(fullPath);
      } catch {
        continue;
      }

      if (info.isDirectory()) {
        stack.push(fullPath);
        continue;
      }

      const isSymlink = info.isSymbolicLink();
      let symlinkTarget: string | null = null;
      if (isSymlink) {
        symlinkTarget = await readlink(fullPath).catch(() => null);
      }

      if (!info.isFile() && !isSymlink) continue;

      // Read a head sample for classification; full read only when needed.
      let head = Buffer.alloc(0);
      if (info.isFile() && info.size > 0) {
        try {
          const handle = await open(fullPath, "r");
          head = Buffer.alloc(Math.min(info.size, 8192));
          await handle.read(head, 0, head.length, 0);
          await handle.close();
        } catch {
          head = Buffer.alloc(0);
        }
      }

      const type = classifyType(head, isSymlink, false);

      // Prefer the archive-declared mode when the extractor deliberately
      // dropped privileged bits. A setuid-root binary in the image is a
      // finding even though we refused to recreate it as setuid on disk.
      const declared = declaredModes.get(relativePath);
      const onDiskMode = info.mode;
      const declaredAddsPrivilege =
        declared != null && (declared.mode & 0o7000) !== 0 && (onDiskMode & 0o7000) === 0;
      const mode = declaredAddsPrivilege ? declared!.mode : onDiskMode;
      if (declaredAddsPrivilege) {
        notes.push(
          `${relativePath}: archive declares mode ${(declared!.mode & 0o7777).toString(8)}; ` +
          "extraction did not restore the privileged bits on disk (reported from the archive metadata)",
        );
      }
      const isElf = type === "ELF binary";

      let sha256 = "";
      let md5: string | null = null;
      let sha1: string | null = null;
      let entropy: number | null = null;
      let stringsCount = 0;
      let binaryInfo: BinaryInfo | null = null;

      if (isSymlink) {
        // Hash the link target text, not the resolved file — the link itself
        // is the artifact, and following it could leave the sandbox.
        const payload = Buffer.from(symlinkTarget ?? "", "utf8");
        sha256 = createHash("sha256").update(payload).digest("hex");
      } else if (info.size <= HASH_SIZE_LIMIT) {
        try {
          const buffer = await readFile(fullPath);
          sha256 = createHash("sha256").update(buffer).digest("hex");
          md5 = createHash("md5").update(buffer).digest("hex");
          sha1 = createHash("sha1").update(buffer).digest("hex");
          entropy = Number(shannonEntropy(buffer).toFixed(3));
          stringsCount = extractStrings(buffer).length;

          if (isElf) {
            const header = parseElfHeader(buffer.subarray(0, 64));
            const [details, interpreter, symbolCount] = await Promise.all([
              readelfDetails(fullPath),
              readInterpreter(fullPath),
              countSymbols(fullPath),
            ]);
            binaryInfo = {
              architecture: header?.architecture ?? null,
              endianness: header?.endianness ?? null,
              entryPoint: header?.entryPoint ?? null,
              interpreter,
              sections: details.sections ?? [],
              dynamicDependencies: details.dynamicDependencies ?? [],
              symbolCount,
            };
          }
        } catch (error) {
          notes.push(`could not hash ${relativePath}: ${(error as Error).message.slice(0, 120)}`);
          sha256 = "";
        }
      } else {
        notes.push(`${relativePath} exceeds the ${HASH_SIZE_LIMIT}-byte hashing limit and was inventoried without digests`);
        sha256 = "";
      }

      const suspicion = assessSuspicion(relativePath, mode, entropy, type, isSymlink, symlinkTarget);

      rawIds.set(relativePath, { uid: info.uid, gid: info.gid });

      files.push({
        path: relativePath,
        sandboxPath: relativePath,
        type: isSymlink && symlinkTarget ? `symlink → ${symlinkTarget.slice(0, 80)}` : type,
        sizeBytes: info.size,
        permissions: octalMode(mode),
        // Placeholders; replaced below once passwd/group have been located.
        owner: String(info.uid),
        group: String(info.gid),
        sha256,
        md5,
        sha1,
        executable: !isSymlink && (mode & 0o111) !== 0,
        suspicious: suspicion.suspicious,
        suspiciousReason: suspicion.reason,
        stringsCount,
        entropy,
        binaryInfo,
        symlinkTarget,
        isSetuid: (mode & 0o4000) !== 0,
        isSetgid: (mode & 0o2000) !== 0,
        isWorldWritable: (mode & 0o0002) !== 0,
      });
    }
  }

  if (files.length >= MAX_FILES) {
    truncated = true;
    notes.push(`file inventory was capped at ${MAX_FILES} entries; the image contains more`);
  }

  // Now that paths exist, locate the rootfs and resolve ownership against the
  // firmware's own passwd/group rather than leaving bare numeric ids.
  const rootfsPrefix = findRootfsPrefix(files);

  // Re-express every path relative to the firmware's filesystem root so
  // reports cite "/bin/busybox" rather than the sandbox scaffolding.
  for (const file of files) {
    if (rootfsPrefix && file.sandboxPath.startsWith(`${rootfsPrefix}/`)) {
      file.path = `/${file.sandboxPath.slice(rootfsPrefix.length + 1)}`;
    } else if (rootfsPrefix && file.sandboxPath === rootfsPrefix) {
      file.path = "/";
    } else {
      // Outside the detected rootfs: keep the layer path, marked so it is
      // clearly not a filesystem path from the device.
      file.path = `<image>/${file.sandboxPath}`;
    }
  }

  const { users, groups } = await loadIdMaps(root, rootfsPrefix);
  for (const file of files) {
    const ids = rawIds.get(file.sandboxPath);
    if (!ids) continue;
    const userName = users.get(ids.uid);
    const groupName = groups.get(ids.gid);
    file.owner = userName ? `${userName} (${ids.uid})` : String(ids.uid);
    file.group = groupName ? `${groupName} (${ids.gid})` : String(ids.gid);
  }

  const profile = await profileFilesystem(root, files);

  return { files, profile, notes, truncated };
}
