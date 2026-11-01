import type { CveMatch, CveProvider } from "./types";
import { logger } from "../../logger";

function cvssToSeverity(score: number | null | undefined): "Critical" | "High" | "Medium" | "Low" | "Informational" {
  if (score === null || score === undefined || Number.isNaN(score)) return "Medium";
  if (score >= 9.0) return "Critical";
  if (score >= 7.0) return "High";
  if (score >= 4.0) return "Medium";
  if (score > 0.0) return "Low";
  return "Informational";
}

function parseVersionParts(v: string): number[] {
  const parts = v.replace(/^v/i, "").split(/[-+.]/);
  const nums: number[] = [];
  for (const p of parts) {
    const n = Number.parseInt(p, 10);
    if (!Number.isNaN(n)) {
      nums.push(n);
    } else {
      break;
    }
  }
  return nums;
}

function compareVersions(v1: string, v2: string): number {
  const p1 = parseVersionParts(v1);
  const p2 = parseVersionParts(v2);
  const len = Math.max(p1.length, p2.length);
  for (let i = 0; i < len; i++) {
    const num1 = p1[i] ?? 0;
    const num2 = p2[i] ?? 0;
    if (num1 > num2) return 1;
    if (num1 < num2) return -1;
  }
  return 0;
}

export class NvdCveProvider implements CveProvider {
  name = "nvd";
  private baseUrl = "https://services.nvd.nist.gov/rest/json/cves/2.0";

  async lookupComponent(component: string, version: string | null): Promise<CveMatch[]> {
    const cleanComp = component.toLowerCase().trim();
    if (!cleanComp) return [];

    const apiKey = process.env.NVD_API_KEY;
    const headers: Record<string, string> = {
      Accept: "application/json",
      "User-Agent": "IoT-Firmware-Security-Analyzer/1.0",
    };
    if (apiKey) {
      headers.apiKey = apiKey;
    }

    const keyword = version ? `${cleanComp} ${version}` : cleanComp;
    const url = `${this.baseUrl}?keywordSearch=${encodeURIComponent(keyword)}&resultsPerPage=15`;

    try {
      const response = await fetch(url, {
        headers,
        signal: AbortSignal.timeout(9000),
      });

      if (!response.ok) {
        logger.warn({ status: response.status, component }, "NVD API returned non-OK status");
        return [];
      }

      const data = (await response.json()) as {
        vulnerabilities?: Array<{
          cve?: {
            id: string;
            descriptions?: Array<{ lang: string; value: string }>;
            metrics?: {
              cvssMetricV31?: Array<{ cvssData?: { baseScore?: number } }>;
              cvssMetricV30?: Array<{ cvssData?: { baseScore?: number } }>;
              cvssMetricV2?: Array<{ cvssData?: { baseScore?: number } }>;
            };
            published?: string;
            configurations?: Array<{
              nodes?: Array<{
                cpeMatch?: Array<{
                  criteria?: string;
                  vulnerable?: boolean;
                  versionStartIncluding?: string;
                  versionEndIncluding?: string;
                  versionEndExcluding?: string;
                }>;
              }>;
            }>;
          };
        }>;
      };

      const vulnerabilities = data.vulnerabilities ?? [];
      const matches: CveMatch[] = [];

      for (const item of vulnerabilities) {
        const cveObj = item.cve;
        if (!cveObj || !cveObj.id) continue;

        const cveId = cveObj.id.toUpperCase();
        const descObj = cveObj.descriptions?.find((d) => d.lang === "en") ?? cveObj.descriptions?.[0];
        const summary = descObj?.value ?? `Vulnerability in ${component}`;

        let cvssScore: number | null = null;
        if (cveObj.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore != null) {
          cvssScore = cveObj.metrics.cvssMetricV31[0].cvssData.baseScore;
        } else if (cveObj.metrics?.cvssMetricV30?.[0]?.cvssData?.baseScore != null) {
          cvssScore = cveObj.metrics.cvssMetricV30[0].cvssData.baseScore;
        } else if (cveObj.metrics?.cvssMetricV2?.[0]?.cvssData?.baseScore != null) {
          cvssScore = cveObj.metrics.cvssMetricV2[0].cvssData.baseScore;
        }

        let isVersionMatched = false;
        if (version && cveObj.configurations) {
          for (const config of cveObj.configurations) {
            for (const node of config.nodes ?? []) {
              for (const cpe of node.cpeMatch ?? []) {
                if (!cpe.vulnerable) continue;
                if (cpe.versionStartIncluding && compareVersions(version, cpe.versionStartIncluding) < 0) continue;
                if (cpe.versionEndIncluding && compareVersions(version, cpe.versionEndIncluding) > 0) continue;
                if (cpe.versionEndExcluding && compareVersions(version, cpe.versionEndExcluding) >= 0) continue;
                isVersionMatched = true;
                break;
              }
              if (isVersionMatched) break;
            }
            if (isVersionMatched) break;
          }
        }

        const confidence: "high" | "medium" | "low" = isVersionMatched && version ? "high" : "low";
        let severity = cvssToSeverity(cvssScore);
        if (!version || !isVersionMatched) {
          severity = "Low";
        }

        matches.push({
          cveId,
          component,
          version,
          severity,
          summary,
          publishedDate: cveObj.published,
          sourceUrl: `https://nvd.nist.gov/vuln/detail/${cveId}`,
          confidence,
        });
      }

      return matches;
    } catch (err) {
      logger.warn({ err, component }, "Failed to query NVD CVE provider");
      return [];
    }
  }
}
