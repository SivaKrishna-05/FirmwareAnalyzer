/**
 * Firmware container format detection.
 *
 * Detection is magic-byte based, never extension based. An uploaded file
 * named "firmware.bin" is far more often a SquashFS image, a U-Boot uImage,
 * or a raw flash dump than it is anything the extension implies.
 *
 * Every signature here is one we can act on: either we have an extractor for
 * it, or we can positively identify it well enough to tell the analyst why we
 * could not unpack it. We never claim a format we cannot substantiate.
 */

export type FirmwareFormatId =
  | "zip"
  | "gzip"
  | "bzip2"
  | "xz"
  | "lzma"
  | "lz4"
  | "zstd"
  | "tar"
  | "cpio"
  | "ar"
  | "squashfs"
  | "cramfs"
  | "jffs2"
  | "ubi"
  | "ubifs"
  | "romfs"
  | "ext"
  | "uimage"
  | "android-boot"
  | "dtb"
  | "elf"
  | "pe"
  | "iso9660"
  | "unknown";

export interface FormatSignature {
  id: FirmwareFormatId;
  label: string;
  /** Byte pattern to match. */
  magic: number[];
  /** Offset within the file where the pattern must appear. */
  offset: number;
  /** Endianness variant note, where a format has more than one on-disk form. */
  variant?: string;
  /** True when we have a real extractor wired up for this format. */
  extractable: boolean;
}

/**
 * Ordered most-specific-first. SquashFS has four magic variants because the
 * superblock byte order follows the target device, and big-endian MIPS
 * consumer routers are extremely common in IoT firmware.
 */
export const FORMAT_SIGNATURES: readonly FormatSignature[] = Object.freeze([
  // --- Archive containers -------------------------------------------------
  { id: "zip", label: "ZIP archive", magic: [0x50, 0x4b, 0x03, 0x04], offset: 0, extractable: true },
  { id: "zip", label: "ZIP archive (empty)", magic: [0x50, 0x4b, 0x05, 0x06], offset: 0, extractable: true },
  { id: "gzip", label: "gzip stream", magic: [0x1f, 0x8b], offset: 0, extractable: true },
  { id: "bzip2", label: "bzip2 stream", magic: [0x42, 0x5a, 0x68], offset: 0, extractable: true },
  { id: "xz", label: "XZ stream", magic: [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00], offset: 0, extractable: true },
  { id: "lz4", label: "LZ4 frame", magic: [0x04, 0x22, 0x4d, 0x18], offset: 0, extractable: true },
  { id: "zstd", label: "Zstandard frame", magic: [0x28, 0xb5, 0x2f, 0xfd], offset: 0, extractable: true },
  // POSIX tar keeps "ustar" at offset 257, not at the start of the file.
  { id: "tar", label: "POSIX tar archive", magic: [0x75, 0x73, 0x74, 0x61, 0x72], offset: 257, extractable: true },
  { id: "cpio", label: "cpio archive (newc)", magic: [0x30, 0x37, 0x30, 0x37, 0x30, 0x31], offset: 0, extractable: true },
  { id: "cpio", label: "cpio archive (crc)", magic: [0x30, 0x37, 0x30, 0x37, 0x30, 0x32], offset: 0, extractable: true },
  { id: "ar", label: "ar archive", magic: [0x21, 0x3c, 0x61, 0x72, 0x63, 0x68, 0x3e], offset: 0, extractable: true },

  // --- Filesystem images --------------------------------------------------
  { id: "squashfs", label: "SquashFS image", magic: [0x68, 0x73, 0x71, 0x73], offset: 0, variant: "little-endian", extractable: true },
  { id: "squashfs", label: "SquashFS image", magic: [0x73, 0x71, 0x73, 0x68], offset: 0, variant: "big-endian", extractable: true },
  { id: "squashfs", label: "SquashFS image", magic: [0x73, 0x71, 0x6c, 0x7a], offset: 0, variant: "LZMA variant", extractable: true },
  { id: "squashfs", label: "SquashFS image", magic: [0x71, 0x73, 0x68, 0x73], offset: 0, variant: "big-endian (older)", extractable: true },
  { id: "cramfs", label: "CramFS image", magic: [0x45, 0x3d, 0xcd, 0x28], offset: 0, extractable: true },
  { id: "jffs2", label: "JFFS2 image", magic: [0x19, 0x85], offset: 0, variant: "little-endian", extractable: true },
  { id: "jffs2", label: "JFFS2 image", magic: [0x85, 0x19], offset: 0, variant: "big-endian", extractable: true },
  { id: "ubi", label: "UBI volume image", magic: [0x55, 0x42, 0x49, 0x23], offset: 0, extractable: true },
  { id: "ubifs", label: "UBIFS image", magic: [0x31, 0x18, 0x10, 0x06], offset: 0, extractable: true },
  { id: "romfs", label: "romfs image", magic: [0x2d, 0x72, 0x6f, 0x6d, 0x31, 0x66, 0x73, 0x2d], offset: 0, extractable: true },
  // ext2/3/4 superblock magic sits at offset 1080 (0x438).
  { id: "ext", label: "ext2/3/4 filesystem", magic: [0x53, 0xef], offset: 1080, extractable: true },
  { id: "iso9660", label: "ISO 9660 image", magic: [0x43, 0x44, 0x30, 0x30, 0x31], offset: 32769, extractable: false },

  // --- Boot / executable containers ---------------------------------------
  { id: "uimage", label: "U-Boot uImage", magic: [0x27, 0x05, 0x19, 0x56], offset: 0, extractable: true },
  { id: "android-boot", label: "Android boot image", magic: [0x41, 0x4e, 0x44, 0x52, 0x4f, 0x49, 0x44, 0x21], offset: 0, extractable: true },
  { id: "dtb", label: "Flattened device tree", magic: [0xd0, 0x0d, 0xfe, 0xed], offset: 0, extractable: false },
  { id: "elf", label: "ELF executable", magic: [0x7f, 0x45, 0x4c, 0x46], offset: 0, extractable: false },
  { id: "pe", label: "PE/DOS executable", magic: [0x4d, 0x5a], offset: 0, extractable: false },
]);

export interface DetectedFormat {
  id: FirmwareFormatId;
  label: string;
  variant: string | null;
  offset: number;
  extractable: boolean;
}

function matchesAt(buffer: Buffer, signature: FormatSignature, at: number): boolean {
  if (at + signature.magic.length > buffer.length) return false;
  for (let i = 0; i < signature.magic.length; i += 1) {
    if (buffer[at + i] !== signature.magic[i]) return false;
  }
  return true;
}

/**
 * Identify the container format at the very start of the image.
 * Returns null when nothing matches, which is a legitimate outcome for a raw
 * flash dump — the caller should then fall back to carving.
 */
export function detectFormat(buffer: Buffer): DetectedFormat | null {
  for (const signature of FORMAT_SIGNATURES) {
    if (matchesAt(buffer, signature, signature.offset)) {
      return {
        id: signature.id,
        label: signature.label,
        variant: signature.variant ?? null,
        offset: signature.offset,
        extractable: signature.extractable,
      };
    }
  }
  return null;
}

/**
 * Scan the whole image for embedded filesystem/archive signatures.
 *
 * This is what makes raw flash dumps tractable: a vendor .bin is typically a
 * bootloader, then a uImage-wrapped kernel, then a SquashFS rootfs at some
 * arbitrary offset. Finding that rootfs offset is the difference between a
 * real analysis and reporting one opaque blob.
 *
 * Only formats we can actually carve and extract are scanned for, and only at
 * erase-block-plausible alignments, which keeps false positives down on
 * high-entropy data.
 */
const CARVE_TARGETS: readonly FirmwareFormatId[] = Object.freeze([
  "squashfs",
  "ubi",
  "ubifs",
  "cramfs",
  "jffs2",
  "cpio",
  "uimage",
  "gzip",
  "xz",
]);

export interface CarvedCandidate {
  id: FirmwareFormatId;
  label: string;
  variant: string | null;
  offset: number;
  extractable: boolean;
}

export function findEmbeddedSignatures(
  buffer: Buffer,
  options: { maxResults?: number; minOffset?: number } = {},
): CarvedCandidate[] {
  const maxResults = options.maxResults ?? 64;
  const minOffset = options.minOffset ?? 1;
  const carveSignatures = FORMAT_SIGNATURES.filter(
    (signature) => CARVE_TARGETS.includes(signature.id) && signature.offset === 0,
  );

  const found: CarvedCandidate[] = [];

  // Scan every byte offset, not just aligned ones. A vendor image's payload
  // begins wherever the preceding bootloader blob happened to end, which is
  // routinely unaligned — an aligned-only scan silently misses real rootfs
  // images. Buffer.indexOf runs in native code, so an exhaustive search of
  // each signature is still far cheaper than a JS byte loop.
  for (const signature of carveSignatures) {
    // JFFS2's 2-byte marker matches constantly in random data; it needs a
    // node-header validator we do not have, so it is not carved.
    if (signature.id === "jffs2") continue;

    const needle = Buffer.from(signature.magic);
    let at = buffer.indexOf(needle, minOffset);

    while (at !== -1 && found.length < maxResults) {
      let accept = true;

      // gzip's 2-byte magic is too weak to trust mid-image. Require the
      // deflate compression method and a reserved-bits-clear flag byte.
      if (signature.id === "gzip") {
        const method = buffer[at + 2];
        const flags = buffer[at + 3];
        if (method !== 0x08 || flags === undefined || (flags & 0xe0) !== 0) accept = false;
      }

      // SquashFS: sanity-check the superblock so random data does not match.
      // Block size must be a power of two in the 4 KiB - 1 MiB range.
      if (accept && signature.id === "squashfs" && signature.variant === "little-endian") {
        if (at + 32 <= buffer.length) {
          const blockSize = buffer.readUInt32LE(at + 12);
          const isPowerOfTwo = blockSize > 0 && (blockSize & (blockSize - 1)) === 0;
          if (!isPowerOfTwo || blockSize < 4096 || blockSize > 1024 * 1024) accept = false;
        } else {
          accept = false;
        }
      }

      if (accept) {
        found.push({
          id: signature.id,
          label: signature.label,
          variant: signature.variant ?? null,
          offset: at,
          extractable: signature.extractable,
        });
      }

      at = buffer.indexOf(needle, at + 1);
    }
  }

  // Earliest offset first, so the outermost container is processed before
  // anything nested inside it.
  return found.sort((a, b) => a.offset - b.offset).slice(0, maxResults);
}

/**
 * Shannon entropy over a byte sample, 0-8 bits per byte.
 *
 * Used to distinguish compressed/encrypted regions (~7.9) from code and text
 * (~4-6). High entropy on a file we could not identify is a real signal that
 * the image may be vendor-encrypted, which is an analyst-actionable outcome
 * rather than a failure.
 */
export function shannonEntropy(buffer: Buffer, sampleLimit = 1024 * 1024): number {
  const length = Math.min(buffer.length, sampleLimit);
  if (length === 0) return 0;

  const counts = new Uint32Array(256);
  for (let i = 0; i < length; i += 1) {
    counts[buffer[i]!]! += 1;
  }

  let entropy = 0;
  for (let value = 0; value < 256; value += 1) {
    const count = counts[value]!;
    if (count === 0) continue;
    const probability = count / length;
    entropy -= probability * Math.log2(probability);
  }
  return entropy;
}

export const SUPPORTED_FIRMWARE_EXTENSIONS: readonly string[] = Object.freeze([
  ".bin",
  ".img",
  ".zip",
  ".tar",
  ".tar.gz",
  ".tgz",
  ".gz",
  ".bz2",
  ".xz",
  ".squashfs",
  ".sqsh",
  ".ubi",
  ".ubifs",
  ".cramfs",
  ".jffs2",
  ".cpio",
  ".rom",
  ".fw",
  ".pkg",
  ".trx",
  ".dtb",
  ".elf",
]);
