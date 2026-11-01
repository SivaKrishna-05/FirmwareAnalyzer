import { exec } from "node:child_process";
import { lstat, readFile, readdir } from "node:fs/promises";
import { join, relative } from "node:path";
import { tmpdir } from "node:os";
import { promisify } from "node:util";
import { logger } from "../../logger";
import { YARA_RULES } from "./rules";
import type { YaraMatch } from "./types";

const execAsync = promisify(exec);
const MAX_SCAN_FILES = 300;
const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB per file for text/pattern inspection

function toPosix(pathStr: string): string {
  return pathStr.replaceAll("\\", "/");
}

function regExpToYara(rx: RegExp): string {
  const isNocase = rx.flags.includes("i");
  return `/${rx.source}/${isNocase ? " nocase" : ""}`;
}

export async function scanWithYara(extractedRoot: string): Promise<YaraMatch[]> {
  const matches: YaraMatch[] = [];

  // 1. Try native YARA CLI first if available with valid rules_file argument
  try {
    const rulesFile = join(tmpdir(), "firmware_analyzer_rules.yar");
    const yaraRulesContent = YARA_RULES.map((rule) => {
      const stringLines = rule.strings.map(
        (str, idx) => `    $s${idx + 1} = "${str.replaceAll("\\", "\\\\").replaceAll('"', '\\"')}"`,
      );
      const regexLines = (rule.regexes ?? []).map(
        (rx, idx) => `    $r${idx + 1} = ${regExpToYara(rx)}`,
      );
      const allLines = [...stringLines, ...regexLines].join("\n");
      const hasCond = stringLines.length > 0 || regexLines.length > 0;
      return `rule ${rule.id} {\n  meta:\n    description = "${rule.description.replaceAll('"', '\\"')}"\n  strings:\n${allLines}\n  condition:\n    ${hasCond ? "any of ($*)" : "false"}\n}`;
    }).join("\n\n");

    const { writeFile, rm } = await import("node:fs/promises");
    await writeFile(rulesFile, yaraRulesContent, "utf8");

    try {
      const { stdout } = await execAsync(`yara -r "${rulesFile}" "${extractedRoot}"`, { timeout: 15000 });
      if (stdout && stdout.trim()) {
        const lines = stdout.split("\n").map((l) => l.trim()).filter(Boolean);
        for (const line of lines) {
          // Line format: RuleName TargetPath
          const parts = line.split(/\s+/);
          if (parts.length >= 2) {
            const ruleName = parts[0];
            const rawPath = parts.slice(1).join(" ");
            const relPath = `/${toPosix(relative(extractedRoot, rawPath))}`;
            const ruleDef = YARA_RULES.find((r) => r.id === ruleName || r.name === ruleName);
            matches.push({
              ruleId: ruleDef?.id ?? ruleName,
              ruleName: ruleDef?.name ?? ruleName,
              category: ruleDef?.category ?? "Malware Indicator",
              severity: ruleDef?.severity ?? "High",
              description: ruleDef?.description ?? `Matched YARA rule ${ruleName}`,
              filePath: relPath,
              matchedString: `YARA CLI match: ${ruleName}`,
            });
          }
        }
        if (matches.length > 0) {
          await rm(rulesFile, { force: true }).catch(() => {});
          return matches;
        }
      }
    } finally {
      await rm(rulesFile, { force: true }).catch(() => {});
    }
  } catch (cliErr) {
    logger.debug({ err: cliErr }, "Native yara CLI not present or returned non-zero exit; fallback to JS matcher");
  }

  // 2. High-speed JS YARA-subset fallback matcher
  const stack: string[] = [extractedRoot];
  let fileCount = 0;

  while (stack.length > 0 && fileCount < MAX_SCAN_FILES) {
    const current = stack.pop()!;
    let entries;
    try {
      entries = await readdir(current, { withFileTypes: true });
    } catch {
      continue;
    }

    for (const entry of entries) {
      if (fileCount >= MAX_SCAN_FILES) break;

      const fullPath = join(current, entry.name);
      let stat;
      try {
        stat = await lstat(fullPath);
      } catch {
        continue;
      }

      if (stat.isDirectory()) {
        stack.push(fullPath);
        continue;
      }

      if (!stat.isFile() || stat.size === 0 || stat.size > MAX_FILE_SIZE) continue;

      fileCount++;
      const relPath = `/${toPosix(relative(extractedRoot, fullPath))}`;

      try {
        const buffer = await readFile(fullPath);
        const contentStr = buffer.toString("latin1");

        for (const rule of YARA_RULES) {
          // Check literal string matches
          for (const str of rule.strings) {
            if (contentStr.includes(str)) {
              matches.push({
                ruleId: rule.id,
                ruleName: rule.name,
                category: rule.category,
                severity: rule.severity,
                description: rule.description,
                filePath: relPath,
                matchedString: str,
              });
              break; // One match per rule per file
            }
          }

          // Check regex matches if no string matched yet
          if (rule.regexes && !matches.some((m) => m.ruleId === rule.id && m.filePath === relPath)) {
            for (const rx of rule.regexes) {
              if (rx.test(contentStr)) {
                matches.push({
                  ruleId: rule.id,
                  ruleName: rule.name,
                  category: rule.category,
                  severity: rule.severity,
                  description: rule.description,
                  filePath: relPath,
                  matchedString: `Regex match: ${rx.source}`,
                });
                break;
              }
            }
          }
        }
      } catch {
        // Ignore file read errors
      }
    }
  }

  return matches;
}
