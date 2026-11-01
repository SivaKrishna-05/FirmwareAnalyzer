/**
 * External extraction tool discovery.
 *
 * The analyzer shells out to real tools (unsquashfs, ubireader, 7z, ...).
 * Those tools may or may not be installed in a given deployment, so the rule
 * this module enforces is: we probe for them once, and whenever one is
 * missing we record that fact and surface it to the analyst.
 *
 * A stage must never be marked "completed" because its tool was absent. That
 * is the difference between "we looked and found nothing" and "we never
 * looked", and conflating the two is how a security tool lies to its user.
 */

import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

export type ToolName =
  | "unzip"
  | "tar"
  | "gzip"
  | "bzip2"
  | "xz"
  | "zstd"
  | "unsquashfs"
  | "ubireader_extract_files"
  | "cpio"
  | "7z"
  | "file"
  | "readelf"
  | "objdump"
  | "strings"
  | "jefferson"
  | "cramfsck"
  | "abootimg";

interface ToolProbe {
  name: ToolName;
  /** Argument that makes the tool exit quickly; version flags vary widely. */
  probeArgs: string[];
  /** What the analyst loses when this tool is missing. */
  capability: string;
  /** How an operator installs it. Shown verbatim in extraction notes. */
  installHint: string;
}

const PROBES: readonly ToolProbe[] = Object.freeze([
  { name: "unzip", probeArgs: ["-v"], capability: "ZIP archive extraction", installHint: "apt-get install unzip" },
  { name: "tar", probeArgs: ["--version"], capability: "tar archive extraction", installHint: "apt-get install tar" },
  { name: "gzip", probeArgs: ["--version"], capability: "gzip decompression", installHint: "apt-get install gzip" },
  { name: "bzip2", probeArgs: ["--version"], capability: "bzip2 decompression", installHint: "apt-get install bzip2" },
  { name: "xz", probeArgs: ["--version"], capability: "XZ/LZMA decompression", installHint: "apt-get install xz-utils" },
  { name: "zstd", probeArgs: ["--version"], capability: "Zstandard decompression", installHint: "apt-get install zstd" },
  {
    name: "unsquashfs",
    probeArgs: ["-version"],
    capability: "SquashFS root filesystem extraction (the most common IoT rootfs)",
    installHint: "apt-get install squashfs-tools",
  },
  {
    name: "ubireader_extract_files",
    probeArgs: ["--help"],
    capability: "UBI/UBIFS volume extraction (common on NAND-flash devices)",
    installHint: "pip install ubi-reader",
  },
  { name: "cpio", probeArgs: ["--version"], capability: "cpio/initramfs extraction", installHint: "apt-get install cpio" },
  { name: "7z", probeArgs: ["i"], capability: "fallback extraction for several container formats", installHint: "apt-get install p7zip-full" },
  { name: "file", probeArgs: ["--version"], capability: "file type identification", installHint: "apt-get install file" },
  { name: "readelf", probeArgs: ["--version"], capability: "ELF binary metadata analysis", installHint: "apt-get install binutils" },
  { name: "objdump", probeArgs: ["--version"], capability: "binary disassembly metadata", installHint: "apt-get install binutils" },
  { name: "strings", probeArgs: ["--version"], capability: "printable string extraction", installHint: "apt-get install binutils" },
  { name: "jefferson", probeArgs: ["--help"], capability: "JFFS2 filesystem extraction", installHint: "pip install jefferson" },
  { name: "cramfsck", probeArgs: ["-h"], capability: "CramFS filesystem extraction", installHint: "apt-get install e2fsprogs" },
  { name: "abootimg", probeArgs: ["--help"], capability: "Android boot image unpacking", installHint: "apt-get install abootimg" },
]);

export interface ToolStatus {
  name: ToolName;
  available: boolean;
  version: string | null;
  capability: string;
  installHint: string;
}

let cachedToolset: Map<ToolName, ToolStatus> | null = null;

async function probe(tool: ToolProbe): Promise<ToolStatus> {
  try {
    const { stdout, stderr } = await execFileAsync(tool.name, tool.probeArgs, {
      timeout: 5_000,
      maxBuffer: 256 * 1024,
    });
    const output = `${stdout}${stderr}`.trim();
    const firstLine = output.split("\n")[0]?.trim() ?? null;
    return {
      name: tool.name,
      available: true,
      version: firstLine && firstLine.length > 0 ? firstLine.slice(0, 200) : null,
      capability: tool.capability,
      installHint: tool.installHint,
    };
  } catch (error) {
    // Some tools (7z, unzip) exit non-zero on a bare probe but still exist.
    // ENOENT is the only signal that definitively means "not installed".
    const code = (error as NodeJS.ErrnoException).code;
    if (code === "ENOENT") {
      return {
        name: tool.name,
        available: false,
        version: null,
        capability: tool.capability,
        installHint: tool.installHint,
      };
    }
    return {
      name: tool.name,
      available: true,
      version: null,
      capability: tool.capability,
      installHint: tool.installHint,
    };
  }
}

/** Probe every tool once per process and cache the result. */
export async function getToolset(): Promise<Map<ToolName, ToolStatus>> {
  if (cachedToolset) return cachedToolset;
  const statuses = await Promise.all(PROBES.map(probe));
  cachedToolset = new Map(statuses.map((status) => [status.name, status]));
  return cachedToolset;
}

export async function hasTool(name: ToolName): Promise<boolean> {
  const toolset = await getToolset();
  return toolset.get(name)?.available ?? false;
}

/** For the settings/diagnostics view: what this deployment can actually do. */
export async function describeMissingCapabilities(): Promise<string[]> {
  const toolset = await getToolset();
  const has7z = toolset.get("7z")?.available ?? false;
  return [...toolset.values()]
    .filter((status) => {
      if (status.available) return false;
      // If unzip is missing but 7z is installed, ZIP extraction is supported via 7z fallback
      if (status.name === "unzip" && has7z) return false;
      return true;
    })
    .map((status) => `${status.name} is not installed — ${status.capability} is unavailable (${status.installHint})`);
}

/** Reset between tests. */
export function __resetToolsetCache(): void {
  cachedToolset = null;
}
