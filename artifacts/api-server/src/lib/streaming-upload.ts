import { createHash, randomUUID } from "node:crypto";
import { createWriteStream } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Request } from "express";

export interface StreamedUploadResult {
  tempFilePath: string;
  originalFilename: string;
  sizeBytes: number;
  sha256: string;
  cleanup: () => Promise<void>;
}

export class UploadError extends Error {
  code: string;
  status: number;
  constructor(message: string, code: string, status = 400) {
    super(message);
    this.name = "UploadError";
    this.code = code;
    this.status = status;
  }
}

/**
 * Streams a multipart/form-data request directly to a temporary file on disk,
 * computing SHA-256 and enforcing byte limits on the fly without loading
 * the entire payload into Node.js heap memory.
 */
export async function streamMultipartToFile(
  req: Request,
  maxBytes: number,
): Promise<StreamedUploadResult> {
  const contentType = req.headers["content-type"] ?? "";
  const boundaryMatch = /boundary=(?:"([^"]+)"|([^;]+))/i.exec(contentType);
  const boundary = boundaryMatch?.[1] ?? boundaryMatch?.[2];

  if (!boundary) {
    throw new UploadError("Invalid multipart payload: missing boundary delimiter.", "INVALID_MULTIPART");
  }

  const tempDir = await mkdtemp(join(tmpdir(), "firmware-upload-"));
  const tempFilePath = join(tempDir, `upload-${randomUUID()}.bin`);
  const writeStream = createWriteStream(tempFilePath, { mode: 0o600 });
  const hash = createHash("sha256");

  const cleanup = async () => {
    try {
      await rm(tempDir, { recursive: true, force: true });
    } catch {
      // Best-effort cleanup
    }
  };

  const boundaryMarker = Buffer.from(`--${boundary}`);
  const crlf = Buffer.from("\r\n");
  const doubleCrlf = Buffer.from("\r\n\r\n");

  let originalFilename = "firmware.bin";
  let inHeader = true;
  let headerBuffer = Buffer.alloc(0);
  let sizeBytes = 0;
  let fileStarted = false;
  let leftover = Buffer.alloc(0);

  return new Promise<StreamedUploadResult>((resolve, reject) => {
    let finished = false;

    const abort = async (err: Error) => {
      if (finished) return;
      finished = true;
      req.unpipe();
      req.destroy();
      writeStream.destroy();
      await cleanup();
      reject(err);
    };

    req.on("error", (err) => {
      void abort(new UploadError(`Upload network stream interrupted: ${err.message}`, "STREAM_ERROR", 500));
    });

    writeStream.on("error", (err) => {
      void abort(new UploadError(`Failed writing upload to disk: ${err.message}`, "DISK_WRITE_ERROR", 500));
    });

    req.on("data", (chunk: Buffer) => {
      if (finished) return;

      if (inHeader) {
        headerBuffer = Buffer.concat([headerBuffer, chunk]);
        const headerEnd = headerBuffer.indexOf(doubleCrlf);
        if (headerEnd !== -1) {
          const headerText = headerBuffer.subarray(0, headerEnd).toString("utf8");
          const filenameMatch = /filename="([^"]*)"/i.exec(headerText);
          if (filenameMatch && filenameMatch[1]) {
            originalFilename = filenameMatch[1].replaceAll("\\", "/").split("/").pop() || "firmware.bin";
          }
          inHeader = false;
          fileStarted = true;

          // Remainder of chunk after header is the start of file content
          const initialContent = headerBuffer.subarray(headerEnd + 4);
          headerBuffer = Buffer.alloc(0);
          if (initialContent.length > 0) {
            processFileContent(initialContent);
          }
        } else if (headerBuffer.length > 64 * 1024) {
          void abort(new UploadError("Multipart headers exceeded maximum allowable size.", "HEADER_TOO_LARGE"));
        }
      } else {
        processFileContent(chunk);
      }
    });

    function processFileContent(chunk: Buffer) {
      const data = leftover.length > 0 ? Buffer.concat([leftover, chunk]) : chunk;
      leftover = Buffer.alloc(0);

      // Check if boundary is present in data
      const boundaryIndex = data.indexOf(boundaryMarker);
      if (boundaryIndex !== -1) {
        // End of file reached! Slice up to boundary (excluding preceding CRLF)
        let endPos = boundaryIndex;
        if (endPos >= 2 && data[endPos - 2] === 0x0d && data[endPos - 1] === 0x0a) {
          endPos -= 2;
        }

        const toWrite = data.subarray(0, endPos);
        if (toWrite.length > 0) {
          sizeBytes += toWrite.length;
          if (sizeBytes > maxBytes) {
            void abort(new UploadError(`Firmware file exceeds maximum limit of ${Math.round(maxBytes / (1024 * 1024))}MB.`, "PAYLOAD_TOO_LARGE", 413));
            return;
          }
          hash.update(toWrite);
          writeStream.write(toWrite);
        }

        finished = true;
        writeStream.end(() => {
          if (sizeBytes === 0) {
            void abort(new UploadError("Uploaded firmware file is empty (0 bytes).", "FILE_EMPTY", 400));
            return;
          }
          resolve({
            tempFilePath,
            originalFilename,
            sizeBytes,
            sha256: hash.digest("hex"),
            cleanup,
          });
        });
      } else {
        // We must hold back boundaryMarker.length + 2 bytes in leftover in case
        // boundary was split across two incoming network chunks
        const safeLen = Math.max(0, data.length - (boundaryMarker.length + 4));
        const toWrite = data.subarray(0, safeLen);
        leftover = Buffer.from(data.subarray(safeLen));

        if (toWrite.length > 0) {
          sizeBytes += toWrite.length;
          if (sizeBytes > maxBytes) {
            void abort(new UploadError(`Firmware file exceeds maximum limit of ${Math.round(maxBytes / (1024 * 1024))}MB.`, "PAYLOAD_TOO_LARGE", 413));
            return;
          }
          hash.update(toWrite);
          writeStream.write(toWrite);
        }
      }
    }

    req.on("end", () => {
      if (finished) return;
      if (!fileStarted || sizeBytes === 0) {
        void abort(new UploadError("No file content was found in the upload stream.", "FILE_REQUIRED", 400));
        return;
      }
      // If we ended without seeing trailing boundary marker, flush leftover
      if (leftover.length > 0) {
        let endPos = leftover.length;
        if (endPos >= 2 && leftover[endPos - 2] === 0x0d && leftover[endPos - 1] === 0x0a) {
          endPos -= 2;
        }
        const toWrite = leftover.subarray(0, endPos);
        sizeBytes += toWrite.length;
        hash.update(toWrite);
        writeStream.write(toWrite);
        leftover = Buffer.alloc(0);
      }

      finished = true;
      writeStream.end(() => {
        resolve({
          tempFilePath,
          originalFilename,
          sizeBytes,
          sha256: hash.digest("hex"),
          cleanup,
        });
      });
    });
  });
}
