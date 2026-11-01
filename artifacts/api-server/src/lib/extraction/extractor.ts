/**
 * Recursive firmware extraction.
 *
 * Design rules, in priority order:
 *
 * 1. Containment. Extraction runs against hostile input by definition. Every
 *    extractor writes into a dedicated sandbox directory, and every produced
 *    path is verified to resolve inside that sandbox before we touch it.
 *    Archive entries are validated *before* extraction where the tool allows.
 * 2. Honesty. If we cannot unpack something, the reason is recorded and
 *    propagated. We never mark a layer "extracted" that was merely detected.
 * 3. Bounded work. Recursion depth, total output bytes, file count and per-
 *    tool wall time are all capped, so a zip bomb or a self-referential image
 *    degrades into a truthful partial result rather than taking down the box.
 */

import { execFile, spawn } from "node:child_process";
import { promisify } from "node:util";
import { mkdtemp, mkdir, writeFile, readdir, stat, lstat, rm, realpath } from "node:fs/promises";
import { join, dirname, resolve, sep, basename } from "node:path";
import { tmpdir } from "node:os";
import { detectFormat, findEmbeddedSignatures, type DetectedFormat, type FirmwareFormatId } from "./formats";
import { getToolset, hasTool } from "./tools";
import { readTarDeclaredModes, readZipDeclaredModes, type DeclaredMode } from "./declared-modes";

const execFileAsync = promisify(execFile);

export interface ExtractionLimits {
  maxDepth: number;
  maxTotalBytes: number;
  maxFileCount: number;
  toolTimeoutMs: number;
}

export const DEFAULT_LIMITS: ExtractionLimits = Object.freeze({
  maxDepth: 6,
  maxTotalBytes: 2 * 1024 * 1024 * 1024,
  maxFileCount: 200_000,
  toolTimeoutMs: 180_000,
});

export interface ExtractedLayer {
  /** Path of the container this layer came from, relative to the sandbox. */
  source: string;
  format: FirmwareFormatId;
  label: string;
  /** Byte offset within the source where this container began. */
  offset: number;
  depth: number;
  method: string;
  fileCount: number;
  succeeded: boolean;
  note: string | null;
}

export interface ExtractionResult {
  /** Absolute path of the sandbox root holding all extracted content. */
  rootDir: string;
  layers: ExtractedLayer[];
  /** Deepest successfully extracted nesting level. */
  depth: number;
  totalFiles: number;
  /** Primary detected container of the uploaded image. */
  primaryFormat: DetectedFormat | null;
  /** Non-fatal problems worth telling the analyst about. */
  notes: string[];
  /** True when at least one real filesystem/archive layer was unpacked. */
  extractedAnything: boolean;
  truncated: boolean;
  /** Modes the archives declared, which on-disk extraction intentionally drops. */
  declaredModes: Map<string, DeclaredMode>;
}

interface ExtractionState {
  rootDir: string;
  limits: ExtractionLimits;
  layers: ExtractedLayer[];
  notes: string[];
  totalFiles: number;
  totalBytes: number;
  truncated: boolean;
  visited: Set<string>;
  /**
   * Archive-declared permission bits keyed by sandbox-relative path. We never
   * recreate setuid/setgid bits on disk from untrusted firmware, so this map
   * is how those bits still reach the analyst.
   */
  declaredModes: Map<string, DeclaredMode>;
}

/** Strip anything that could escape the sandbox or confuse a shell. */
function safeName(name: string): string {
  const base = name.replaceAll("\\", "/").split("/").pop() ?? "artifact";
  const cleaned = base.replace(/[^A-Za-z0-9._-]/g, "_").replace(/^\.+/, "_");
  return cleaned.length > 0 ? cleaned.slice(0, 120) : "artifact";
}

/**
 * Verify that `candidate` really lives inside `root` after symlink
 * resolution. Firmware images routinely contain absolute and dangling
 * symlinks, so we resolve the *parent* when the target itself is dangling.
 */
async function assertInside(root: string, candidate: string): Promise<boolean> {
  const realRoot = await realpath(root);
  let probe = candidate;
  for (let i = 0; i < 64; i += 1) {
    try {
      const resolved = await realpath(probe);
      return resolved === realRoot || resolved.startsWith(realRoot + sep);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") return false;
      const parent = dirname(probe);
      if (parent === probe) return false;
      probe = parent;
    }
  }
  return false;
}

async function getDirectorySize(dir: string): Promise<number> {
  let total = 0;
  const stack = [dir];
  while (stack.length > 0) {
    const cur = stack.pop()!;
    try {
      const entries = await readdir(cur, { withFileTypes: true });
      for (const e of entries) {
        const full = join(cur, e.name);
        if (e.isDirectory()) {
          stack.push(full);
        } else if (e.isFile()) {
          try {
            const st = await stat(full);
            total += st.size;
          } catch {
            // Ignore temporary access errors
          }
        }
      }
    } catch {
      // Directory may be in flux
    }
  }
  return total;
}

export async function runTool(
  command: string,
  args: string[],
  options: { cwd?: string; destDir?: string; timeoutMs: number; maxBytes?: number },
): Promise<{ ok: true; stdout: string } | { ok: false; error: string }> {
  return new Promise((resolve) => {
    let stdoutData = "";
    let stderrData = "";
    let isFinished = false;
    let killedForQuota = false;

    const child = spawn(command, args, {
      cwd: options.cwd,
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"],
    });

    const targetWatchDir = options.destDir ?? options.cwd;
    let quotaTimer: NodeJS.Timeout | null = null;

    if (targetWatchDir && options.maxBytes) {
      const maxB = options.maxBytes;
      quotaTimer = setInterval(async () => {
        if (isFinished) return;
        try {
          const currentSize = await getDirectorySize(targetWatchDir);
          if (currentSize > maxB) {
            killedForQuota = true;
            child.kill("SIGKILL");
          }
        } catch {
          // Non-fatal inspection error
        }
      }, 300);
      quotaTimer.unref();
    }

    const timeoutTimer = setTimeout(() => {
      if (!isFinished) {
        child.kill("SIGTERM");
        setTimeout(() => {
          if (!isFinished) child.kill("SIGKILL");
        }, 1500).unref();
      }
    }, options.timeoutMs);
    timeoutTimer.unref();

    child.stdout.on("data", (chunk: Buffer) => {
      if (stdoutData.length < 16 * 1024 * 1024) {
        stdoutData += chunk.toString("utf8");
      }
    });

    child.stderr.on("data", (chunk: Buffer) => {
      if (stderrData.length < 1024 * 1024) {
        stderrData += chunk.toString("utf8");
      }
    });

    child.on("error", (err: NodeJS.ErrnoException) => {
      if (isFinished) return;
      isFinished = true;
      clearTimeout(timeoutTimer);
      if (quotaTimer) clearInterval(quotaTimer);

      if (err.code === "ENOENT") {
        resolve({ ok: false, error: `${command} is not installed` });
      } else {
        resolve({ ok: false, error: `${command}: ${err.message}` });
      }
    });

    child.on("close", (code, signal) => {
      if (isFinished) return;
      isFinished = true;
      clearTimeout(timeoutTimer);
      if (quotaTimer) clearInterval(quotaTimer);

      if (killedForQuota) {
        resolve({
          ok: false,
          error: `${command} aborted: extraction disk quota exceeded (${Math.round(options.maxBytes! / (1024 * 1024))}MB limit reached during execution)`,
        });
        return;
      }

      if (signal === "SIGTERM" || signal === "SIGKILL") {
        resolve({ ok: false, error: `${command} exceeded its ${options.timeoutMs}ms time limit` });
        return;
      }

      if (code === 0) {
        resolve({ ok: true, stdout: stdoutData });
      } else {
        const detail = (stderrData || stdoutData || `exit code ${code}`).trim().split("\n")[0] || "unknown error";
        resolve({ ok: false, error: `${command}: ${detail.slice(0, 300)}` });
      }
    });
  });
}

/**
 * Merge an archive's declared modes into the run state, rebasing each entry
 * onto the sandbox-relative path where it will actually land.
 */
async function recordDeclaredModes(
  declared: Map<string, DeclaredMode>,
  destDir: string,
  state: ExtractionState,
): Promise<void> {
  if (declared.size === 0) return;
  const prefix = destDir.startsWith(state.rootDir + sep)
    ? destDir.slice(state.rootDir.length + 1)
    : "";
  for (const [entryPath, mode] of declared) {
    const key = prefix ? `${prefix}/${entryPath}` : entryPath;
    state.declaredModes.set(key, mode);
  }
}

/** Count files produced under a directory, respecting global caps. */
async function countFiles(dir: string, state: ExtractionState): Promise<number> {
  let count = 0;
  const stack = [dir];
  while (stack.length > 0) {
    const current = stack.pop()!;
    let entries;
    try {
      entries = await readdir(current, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      const full = join(current, entry.name);
      if (entry.isSymbolicLink()) {
        count += 1;
        continue;
      }
      if (entry.isDirectory()) {
        stack.push(full);
      } else if (entry.isFile()) {
        count += 1;
        if (count + state.totalFiles > state.limits.maxFileCount) {
          state.truncated = true;
          return count;
        }
      }
    }
  }
  return count;
}

// ---------------------------------------------------------------------------
// Individual extractors
// ---------------------------------------------------------------------------

/**
 * ZIP. `unzip -Z1` lists entries without extracting, so we validate every
 * entry name for traversal before any bytes hit the disk.
 */
async function extractZip(
  archive: string,
  dest: string,
  state: ExtractionState,
): Promise<{ ok: boolean; note: string | null; method: string }> {
  if (await hasTool("unzip")) {
    const listing = await runTool("unzip", ["-Z1", archive], { timeoutMs: state.limits.toolTimeoutMs });
    if (listing.ok) {
      const entries = listing.stdout.split("\n").map((line) => line.trim()).filter(Boolean);
      const hostile = entries.find(
        (entry) => entry.startsWith("/") || entry.split("/").includes("..") || /^[A-Za-z]:/.test(entry),
      );
      if (hostile) {
        return { ok: false, note: `refused: archive contains a path-traversal entry (${safeName(hostile)})`, method: "unzip" };
      }
    }

    // Capture the modes the archive declares before extracting, since we
    // intentionally do not restore them onto our own filesystem.
    await recordDeclaredModes(await readZipDeclaredModes(archive, state.limits.toolTimeoutMs), dest, state);

    // -qq quiet, -o overwrite, -DD skip timestamps, -d destination.
    const result = await runTool("unzip", ["-qq", "-o", "-DD", archive, "-d", dest], {
      timeoutMs: state.limits.toolTimeoutMs,
    });
    if (!result.ok) {
      const produced = await countFiles(dest, state);
      if (produced > 0) return { ok: true, note: `partial extraction: ${result.error}`, method: "unzip" };
      return { ok: false, note: result.error, method: "unzip" };
    }
    return { ok: true, note: null, method: "unzip" };
  }

  if (await hasTool("7z")) {
    const result = await runTool("7z", ["x", `-o${dest}`, "-y", archive], { timeoutMs: state.limits.toolTimeoutMs });
    const produced = await countFiles(dest, state);
    if (produced > 0) {
      return { ok: true, note: result.ok ? null : `partial extraction via 7z: ${result.error}`, method: "7z" };
    }
    return { ok: false, note: result.ok ? "7z produced no files" : result.error, method: "7z" };
  }

  return { ok: false, note: "neither unzip nor 7z is installed", method: "none" };
}

/** tar, including compressed variants — tar autodetects via -a on GNU tar. */
async function extractTar(archive: string, dest: string, state: ExtractionState): Promise<{ ok: boolean; note: string | null }> {
  if (await hasTool("tar")) {
    const listing = await runTool("tar", ["-tf", archive], { timeoutMs: state.limits.toolTimeoutMs });
    if (listing.ok) {
      const entries = listing.stdout.split("\n").map((line) => line.trim()).filter(Boolean);
      const hostile = entries.find((entry) => entry.startsWith("/") || entry.split("/").includes(".."));
      if (hostile) {
        return { ok: false, note: `refused: archive contains a path-traversal entry (${safeName(hostile)})` };
      }
    }

    await recordDeclaredModes(await readTarDeclaredModes(archive, state.limits.toolTimeoutMs), dest, state);

    const result = await runTool(
      "tar",
      // --no-same-owner/--no-same-permissions stop the archive dictating modes
      // on our sandbox; --delay-directory-restore avoids traversal via dir perms.
      ["-xf", archive, "-C", dest, "--no-same-owner", "--no-same-permissions", "--delay-directory-restore"],
      { timeoutMs: state.limits.toolTimeoutMs },
    );
    if (result.ok) return { ok: true, note: null };
    const produced = await countFiles(dest, state);
    if (produced > 0) return { ok: true, note: `partial extraction: ${result.error}` };
  }

  if (await hasTool("7z")) {
    const result = await runTool("7z", ["x", `-o${dest}`, "-y", archive], { timeoutMs: state.limits.toolTimeoutMs });
    const produced = await countFiles(dest, state);
    if (produced > 0) return { ok: true, note: result.ok ? "extracted via 7z" : `partial extraction via 7z: ${result.error}` };
  }

  return { ok: false, note: "neither tar nor 7z is installed" };
}

/** SquashFS — the single most important format for IoT firmware, and the one
 * the previous implementation detected but never unpacked.
 *
 * unsquashfs handles all the byte-order and compressor variants itself.
 * -no-xattrs and -no-exit-code keep hostile images from failing the run,
 * and we force a non-existent user mapping so extracted modes cannot
 * meaningfully escalate.
 */
async function extractSquashfs(
  image: string,
  dest: string,
  state: ExtractionState,
  offset: number,
): Promise<{ ok: boolean; note: string | null }> {
  if (await hasTool("unsquashfs")) {
    const args = ["-d", dest, "-f", "-no-xattrs", "-ignore-errors", "-quiet"];
    if (offset > 0) args.push("-offset", String(offset));
    args.push(image);

    const result = await runTool("unsquashfs", args, { timeoutMs: state.limits.toolTimeoutMs });
    const produced = await countFiles(dest, state);
    if (produced > 0) {
      return { ok: true, note: result.ok ? null : `partial extraction: ${result.error}` };
    }
  }

  if (await hasTool("7z")) {
    const result = await runTool("7z", ["x", `-o${dest}`, "-y", image], { timeoutMs: state.limits.toolTimeoutMs });
    const produced = await countFiles(dest, state);
    if (produced > 0) {
      return { ok: true, note: result.ok ? "extracted via 7z" : `partial extraction via 7z: ${result.error}` };
    }
  }

  return { ok: false, note: "unsquashfs/7z is not available or SquashFS root filesystem could not be unpacked" };
}

/** UBI / UBIFS volumes, common on NAND-flash devices. */
async function extractUbi(image: string, dest: string, state: ExtractionState): Promise<{ ok: boolean; note: string | null }> {
  if (await hasTool("ubireader_extract_files")) {
    const result = await runTool("ubireader_extract_files", ["-k", "-o", dest, image], {
      timeoutMs: state.limits.toolTimeoutMs,
    });
    const produced = await countFiles(dest, state);
    if (produced > 0) return { ok: true, note: result.ok ? null : `partial extraction: ${result.error}` };
  }

  if (await hasTool("7z")) {
    const result = await runTool("7z", ["x", `-o${dest}`, "-y", image], { timeoutMs: state.limits.toolTimeoutMs });
    const produced = await countFiles(dest, state);
    if (produced > 0) return { ok: true, note: result.ok ? "extracted via 7z" : `partial extraction via 7z: ${result.error}` };
  }

  return { ok: false, note: "ubi-reader/7z is not available or UBI volume could not be unpacked" };
}

/** cpio / initramfs. cpio reads stdin, so we pipe the file in via sh -c. */
async function extractCpio(image: string, dest: string, state: ExtractionState): Promise<{ ok: boolean; note: string | null }> {
  if (await hasTool("cpio")) {
    const result = await runTool(
      "sh",
      ["-c", `cpio -idmv --no-absolute-filenames -D "$1" < "$2"`, "sh", dest, image],
      { timeoutMs: state.limits.toolTimeoutMs },
    );
    const produced = await countFiles(dest, state);
    if (produced > 0) return { ok: true, note: result.ok ? null : `partial extraction: ${result.error}` };
  }

  if (await hasTool("7z")) {
    const result = await runTool("7z", ["x", `-o${dest}`, "-y", image], { timeoutMs: state.limits.toolTimeoutMs });
    const produced = await countFiles(dest, state);
    if (produced > 0) return { ok: true, note: result.ok ? "extracted via 7z" : `partial extraction via 7z: ${result.error}` };
  }

  return { ok: false, note: "neither cpio nor 7z is installed" };
}

/** JFFS2 filesystem via jefferson or 7z. */
async function extractJffs2(image: string, dest: string, state: ExtractionState): Promise<{ ok: boolean; note: string | null }> {
  if (await hasTool("jefferson")) {
    const result = await runTool("jefferson", ["-d", dest, image], { timeoutMs: state.limits.toolTimeoutMs });
    const produced = await countFiles(dest, state);
    if (produced > 0) return { ok: true, note: result.ok ? null : `partial extraction: ${result.error}` };
  }
  if (await hasTool("7z")) {
    const result = await runTool("7z", ["x", `-o${dest}`, "-y", image], { timeoutMs: state.limits.toolTimeoutMs });
    const produced = await countFiles(dest, state);
    if (produced > 0) return { ok: true, note: `extracted via 7z fallback: ${result.ok ? "" : result.error}` };
  }
  return { ok: false, note: "jefferson/7z is not available or JFFS2 image could not be parsed" };
}

/** CramFS filesystem via cramfsck or 7z. */
async function extractCramfs(image: string, dest: string, state: ExtractionState): Promise<{ ok: boolean; note: string | null }> {
  if (await hasTool("cramfsck")) {
    const result = await runTool("cramfsck", ["-x", dest, image], { timeoutMs: state.limits.toolTimeoutMs });
    const produced = await countFiles(dest, state);
    if (produced > 0) return { ok: true, note: result.ok ? null : `partial extraction: ${result.error}` };
  }
  if (await hasTool("7z")) {
    const result = await runTool("7z", ["x", `-o${dest}`, "-y", image], { timeoutMs: state.limits.toolTimeoutMs });
    const produced = await countFiles(dest, state);
    if (produced > 0) return { ok: true, note: `extracted via 7z fallback: ${result.ok ? "" : result.error}` };
  }
  return { ok: false, note: "cramfsck/7z is not available or CramFS image could not be unpacked" };
}

/** ROMFS filesystem via 7z or carving. */
async function extractRomfs(image: string, dest: string, state: ExtractionState): Promise<{ ok: boolean; note: string | null }> {
  if (await hasTool("7z")) {
    const result = await runTool("7z", ["x", `-o${dest}`, "-y", image], { timeoutMs: state.limits.toolTimeoutMs });
    const produced = await countFiles(dest, state);
    if (produced > 0) return { ok: true, note: result.ok ? null : `partial extraction: ${result.error}` };
  }
  return { ok: false, note: "7z is not available to unpack ROMFS filesystem" };
}

/** EXT2/3/4 filesystem via 7z. */
async function extractExt(image: string, dest: string, state: ExtractionState): Promise<{ ok: boolean; note: string | null }> {
  if (await hasTool("7z")) {
    const result = await runTool("7z", ["x", `-o${dest}`, "-y", image], { timeoutMs: state.limits.toolTimeoutMs });
    const produced = await countFiles(dest, state);
    if (produced > 0) return { ok: true, note: result.ok ? null : `partial extraction: ${result.error}` };
  }
  return { ok: false, note: "7z is not available to unpack EXT filesystem" };
}

/** Android Boot Image via abootimg or header unpacking. */
async function extractAndroidBoot(image: string, dest: string, state: ExtractionState): Promise<{ ok: boolean; note: string | null }> {
  if (await hasTool("abootimg")) {
    const result = await runTool("abootimg", ["-x", image], { cwd: dest, timeoutMs: state.limits.toolTimeoutMs });
    const produced = await countFiles(dest, state);
    if (produced > 0) return { ok: true, note: result.ok ? null : `partial extraction: ${result.error}` };
  }
  if (await hasTool("7z")) {
    const result = await runTool("7z", ["x", `-o${dest}`, "-y", image], { timeoutMs: state.limits.toolTimeoutMs });
    const produced = await countFiles(dest, state);
    if (produced > 0) return { ok: true, note: `extracted via 7z fallback` };
  }
  return { ok: false, note: "abootimg/7z is not available to unpack Android boot image" };
}

/** Single-stream decompressors that emit one output file. */
async function decompressStream(
  image: string,
  dest: string,
  state: ExtractionState,
  format: FirmwareFormatId,
): Promise<{ ok: boolean; note: string | null }> {
  const toolByFormat: Partial<Record<FirmwareFormatId, { tool: string; args: (input: string) => string[] }>> = {
    gzip: { tool: "gzip", args: (input) => ["-dc", input] },
    bzip2: { tool: "bzip2", args: (input) => ["-dc", input] },
    xz: { tool: "xz", args: (input) => ["-dc", input] },
    lzma: { tool: "xz", args: (input) => ["-dc", "--format=lzma", input] },
    zstd: { tool: "zstd", args: (input) => ["-dc", input] },
  };
  const spec = toolByFormat[format];
  if (!spec) return { ok: false, note: `no decompressor wired for ${format}` };
  if (!(await hasTool(spec.tool as never))) return { ok: false, note: `${spec.tool} is not installed` };

  const outputName = basename(image).replace(/\.(gz|bz2|xz|lzma|zst)$/i, "") || "decompressed.bin";
  const outputPath = join(dest, safeName(outputName) + ".out");

  // Stream stdout straight to disk. These expand enormously (a 4 MB gzip can
  // become a 60 MB rootfs), so buffering in memory is not an option, and we
  // enforce the byte cap as the stream arrives rather than after the fact.
  const outcome = await new Promise<{ ok: boolean; note: string | null }>((resolvePromise) => {
    void (async () => {
      const { createWriteStream } = await import("node:fs");
      const { spawn } = await import("node:child_process");

      const sink = createWriteStream(outputPath, { mode: 0o600 });
      const child = spawn(spec.tool, spec.args(image), { stdio: ["ignore", "pipe", "pipe"] });

      let written = 0;
      let overflowed = false;
      let stderrText = "";
      let settled = false;

      const finish = (value: { ok: boolean; note: string | null }): void => {
        if (settled) return;
        settled = true;
        sink.end();
        resolvePromise(value);
      };

      const timer = setTimeout(() => {
        child.kill("SIGKILL");
        finish({ ok: written > 0, note: `${spec.tool} exceeded its ${state.limits.toolTimeoutMs}ms time limit` });
      }, state.limits.toolTimeoutMs);

      const remainingBudget = Math.max(0, state.limits.maxTotalBytes - state.totalBytes);

      child.stdout.on("data", (chunk: Buffer) => {
        written += chunk.length;
        if (written > remainingBudget) {
          overflowed = true;
          child.kill("SIGKILL");
          return;
        }
        sink.write(chunk);
      });
      child.stderr.on("data", (chunk: Buffer) => {
        if (stderrText.length < 2048) stderrText += chunk.toString("utf8");
      });
      child.on("error", (error) => {
        clearTimeout(timer);
        const code = (error as NodeJS.ErrnoException).code;
        finish({ ok: false, note: code === "ENOENT" ? `${spec.tool} is not installed` : error.message.slice(0, 300) });
      });
      child.on("close", (code) => {
        clearTimeout(timer);
        state.totalBytes += written;
        if (overflowed) {
          state.truncated = true;
          finish({ ok: written > 0, note: `decompression stopped at the ${state.limits.maxTotalBytes}-byte output budget` });
          return;
        }
        if (written === 0) {
          const detail = stderrText.trim().split("\n")[0] ?? `exit code ${code}`;
          finish({ ok: false, note: `${spec.tool} produced no output (${detail.slice(0, 200)})` });
          return;
        }
        // Non-zero exit with bytes written is normal for truncated firmware
        // streams; the payload we did recover is still worth analyzing.
        finish({
          ok: true,
          note: code === 0 ? null : `partial decompression (${spec.tool} exit ${code})`,
        });
      });
    })();
  });

  return outcome;
}

/**
 * U-Boot uImage: a 64-byte header followed by the payload. We strip the
 * header and hand the payload back for recursive analysis, which is normally
 * a gzip-compressed kernel or a filesystem.
 */
async function extractUimage(image: string, dest: string): Promise<{ ok: boolean; note: string | null }> {
  const { readFile } = await import("node:fs/promises");
  const buffer = await readFile(image);
  if (buffer.length <= 64) return { ok: false, note: "uImage is too small to contain a payload" };

  const nameBytes = buffer.subarray(32, 64);
  const imageName = nameBytes.toString("latin1").replace(/\0.*$/, "").trim();
  const payload = buffer.subarray(64);
  const outputPath = join(dest, safeName(imageName || "uimage-payload") + ".payload");
  await writeFile(outputPath, payload, { mode: 0o600 });
  return { ok: true, note: imageName ? `uImage payload "${imageName}"` : null };
}

/**
 * Carve an embedded container out of a raw image at a known offset and write
 * it to its own file so the normal extractor path can handle it.
 */
async function carveRegion(image: string, offset: number, dest: string, label: string): Promise<string | null> {
  const { readFile } = await import("node:fs/promises");
  const buffer = await readFile(image);
  if (offset >= buffer.length) return null;
  const region = buffer.subarray(offset);
  const outputPath = join(dest, `carved_${offset}_${safeName(label)}.bin`);
  await writeFile(outputPath, region, { mode: 0o600 });
  return outputPath;
}

// ---------------------------------------------------------------------------
// Recursive driver
// ---------------------------------------------------------------------------

async function extractOne(
  imagePath: string,
  destDir: string,
  format: DetectedFormat,
  state: ExtractionState,
): Promise<{ ok: boolean; note: string | null; method: string }> {
  switch (format.id) {
    case "zip": {
      const res = await extractZip(imagePath, destDir, state);
      return { ok: res.ok, note: res.note, method: res.method };
    }
    case "tar":
      return { ...(await extractTar(imagePath, destDir, state)), method: "tar" };
    case "squashfs":
      return { ...(await extractSquashfs(imagePath, destDir, state, format.offset > 0 ? format.offset : 0)), method: "unsquashfs" };
    case "ubi":
    case "ubifs":
      return { ...(await extractUbi(imagePath, destDir, state)), method: "ubireader" };
    case "cpio":
      return { ...(await extractCpio(imagePath, destDir, state)), method: "cpio" };
    case "jffs2":
      return { ...(await extractJffs2(imagePath, destDir, state)), method: "jefferson/7z" };
    case "cramfs":
      return { ...(await extractCramfs(imagePath, destDir, state)), method: "cramfsck/7z" };
    case "romfs":
      return { ...(await extractRomfs(imagePath, destDir, state)), method: "7z-romfs" };
    case "ext":
      return { ...(await extractExt(imagePath, destDir, state)), method: "7z-ext" };
    case "android-boot":
      return { ...(await extractAndroidBoot(imagePath, destDir, state)), method: "abootimg" };
    case "uimage":
      return { ...(await extractUimage(imagePath, destDir)), method: "uimage-header-strip" };
    case "gzip":
    case "bzip2":
    case "xz":
    case "lzma":
    case "zstd":
      return { ...(await decompressStream(imagePath, destDir, state, format.id)), method: format.id };
    default:
      return { ok: false, note: `no extractor is implemented for ${format.label}`, method: "none" };
  }
}

/**
 * gzip streams are frequently tar.gz. Decompress, then let the recursive pass
 * detect tar inside. Handled by the generic recursion, so nothing special here.
 */
async function processImage(
  imagePath: string,
  relativeSource: string,
  depth: number,
  state: ExtractionState,
): Promise<void> {
  if (depth > state.limits.maxDepth) {
    state.truncated = true;
    state.notes.push(`recursion stopped at depth ${state.limits.maxDepth} for ${relativeSource}`);
    return;
  }
  if (state.totalFiles >= state.limits.maxFileCount || state.totalBytes >= state.limits.maxTotalBytes) {
    state.truncated = true;
    return;
  }

  let info;
  try {
    info = await stat(imagePath);
  } catch {
    return;
  }
  if (!info.isFile() || info.size < 4) return;

  // Guard against self-referential extraction loops.
  const key = `${info.size}:${relativeSource}`;
  if (state.visited.has(key)) return;
  state.visited.add(key);

  const { readFile, open } = await import("node:fs/promises");
  // Read only the head for detection; full read happens inside extractors.
  const handle = await open(imagePath, "r");
  const headLength = Math.min(info.size, 64 * 1024);
  const head = Buffer.alloc(headLength);
  await handle.read(head, 0, headLength, 0);
  await handle.close();

  const format = detectFormat(head);

  if (format && format.extractable) {
    const layerDir = join(dirname(imagePath), `_extracted_${safeName(basename(imagePath))}_${depth}`);
    await mkdir(layerDir, { recursive: true, mode: 0o700 });
    if (!(await assertInside(state.rootDir, layerDir))) {
      state.notes.push(`refused to extract ${relativeSource}: destination escaped the sandbox`);
      return;
    }

    const outcome = await extractOne(imagePath, layerDir, format, state);
    const produced = outcome.ok ? await countFiles(layerDir, state) : 0;
    state.totalFiles += produced;

    state.layers.push({
      source: relativeSource,
      format: format.id,
      label: format.variant ? `${format.label} (${format.variant})` : format.label,
      offset: format.offset,
      depth,
      method: outcome.method,
      fileCount: produced,
      succeeded: outcome.ok,
      note: outcome.note,
    });
    if (outcome.note) state.notes.push(`${relativeSource}: ${outcome.note}`);

    if (outcome.ok) {
      await walkAndRecurse(layerDir, depth + 1, state);
      return;
    }
    // Extraction failed. Fall through to carving — a failed header does not
    // mean there is nothing recoverable deeper in the image.
  } else if (format && !format.extractable) {
    state.layers.push({
      source: relativeSource,
      format: format.id,
      label: format.variant ? `${format.label} (${format.variant})` : format.label,
      offset: format.offset,
      depth,
      method: "none",
      fileCount: 0,
      succeeded: false,
      note: `${format.label} is identified but no extractor is available for it`,
    });
  }

  // Raw image / unknown container: look for embedded filesystems.
  if (info.size > 512 && depth < state.limits.maxDepth) {
    const fullBuffer = await readFile(imagePath);
    const candidates = findEmbeddedSignatures(fullBuffer, { maxResults: 8, minOffset: 4 });
    // Only the first occurrence of each format matters for a first pass;
    // carving every hit on a noisy image explodes the work for little gain.
    const seen = new Set<FirmwareFormatId>();
    for (const candidate of candidates) {
      if (seen.has(candidate.id) || !candidate.extractable) continue;
      seen.add(candidate.id);

      const carvedPath = await carveRegion(imagePath, candidate.offset, dirname(imagePath), candidate.label);
      if (!carvedPath) continue;
      if (!(await assertInside(state.rootDir, carvedPath))) continue;

      state.notes.push(
        `carved an embedded ${candidate.label} from ${relativeSource} at offset 0x${candidate.offset.toString(16)}`,
      );
      await processImage(carvedPath, `${relativeSource}@0x${candidate.offset.toString(16)}`, depth + 1, state);
    }
  }
}

/** Walk an extracted tree and recurse into any nested containers found. */
async function walkAndRecurse(dir: string, depth: number, state: ExtractionState): Promise<void> {
  if (depth > state.limits.maxDepth) {
    state.truncated = true;
    return;
  }

  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return;
  }

  for (const entry of entries) {
    if (state.totalFiles >= state.limits.maxFileCount) {
      state.truncated = true;
      return;
    }
    const full = join(dir, entry.name);
    // Never follow symlinks during recursion; lstat tells us what it really is.
    let linkInfo;
    try {
      linkInfo = await lstat(full);
    } catch {
      continue;
    }
    if (linkInfo.isSymbolicLink()) continue;

    if (linkInfo.isDirectory()) {
      await walkAndRecurse(full, depth, state);
      continue;
    }
    if (!linkInfo.isFile()) continue;
    // Skip the artifacts we ourselves produced, or we recurse forever.
    if (entry.name.startsWith("carved_") || entry.name.startsWith("_extracted_")) continue;

    const head = Buffer.alloc(Math.min(linkInfo.size, 4096));
    if (head.length >= 4) {
      try {
        const { open } = await import("node:fs/promises");
        const handle = await open(full, "r");
        await handle.read(head, 0, head.length, 0);
        await handle.close();
      } catch {
        continue;
      }
      const nested = detectFormat(head);
      if (nested && nested.extractable) {
        await processImage(full, full.slice(state.rootDir.length + 1), depth, state);
      }
    }
  }
}

/**
 * Entry point. Writes `buffer` into a fresh sandbox and extracts it as deeply
 * as the limits allow.
 *
 * The caller owns cleanup via `cleanupExtraction(result.rootDir)`.
 */
export async function extractFirmware(
  buffer: Buffer,
  originalName: string,
  limits: ExtractionLimits = DEFAULT_LIMITS,
): Promise<ExtractionResult> {
  const rootDir = await mkdtemp(join(tmpdir(), "fwscan-"));
  // 0700: no other local user can read retained firmware content.
  const { chmod } = await import("node:fs/promises");
  await chmod(rootDir, 0o700);

  const imagePath = join(rootDir, safeName(originalName) || "firmware.bin");
  await writeFile(imagePath, buffer, { mode: 0o600 });

  const state: ExtractionState = {
    rootDir,
    limits,
    layers: [],
    notes: [],
    totalFiles: 0,
    totalBytes: buffer.length,
    truncated: false,
    visited: new Set(),
    declaredModes: new Map(),
  };

  const primaryFormat = detectFormat(buffer);


  try {
    await processImage(imagePath, basename(imagePath), 0, state);
  } catch (error) {
    state.notes.push(`extraction aborted: ${(error as Error).message.slice(0, 300)}`);
  }

  const successfulLayers = state.layers.filter((layer) => layer.succeeded);
  const depth = successfulLayers.reduce((max, layer) => Math.max(max, layer.depth + 1), 0);

  return {
    rootDir,
    layers: state.layers,
    depth,
    totalFiles: state.totalFiles,
    primaryFormat,
    notes: state.notes,
    extractedAnything: successfulLayers.length > 0,
    truncated: state.truncated,
    declaredModes: state.declaredModes,
  };
}

/**
 * Remove a sandbox and verify it is actually gone. Retained firmware is
 * untrusted third-party content; leaving it on disk is itself a finding.
 */
export async function cleanupExtraction(rootDir: string): Promise<{ removed: boolean; error: string | null }> {
  if (!rootDir || !rootDir.startsWith(tmpdir())) {
    return { removed: false, error: "refused to remove a directory outside the temp root" };
  }
  try {
    await rm(rootDir, { recursive: true, force: true, maxRetries: 3 });
  } catch (error) {
    return { removed: false, error: (error as Error).message.slice(0, 300) };
  }
  try {
    await stat(rootDir);
    return { removed: false, error: "sandbox still present after removal" };
  } catch {
    return { removed: true, error: null };
  }
}

export { assertInside, safeName };
