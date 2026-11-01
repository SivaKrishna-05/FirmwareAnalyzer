import type { CveMatch, CveProvider } from "./types";
import { logger } from "../../logger";
import { compareVersions } from "./version-compare";

const VENDOR_PRODUCT_MAP: Record<string, { vendor: string; product: string }> = {
  busybox: { vendor: "busybox", product: "busybox" },
  dropbear: { vendor: "dropbear_ssh_project", product: "dropbear_ssh" },
  openssl: { vendor: "openssl", product: "openssl" },
  lighttpd: { vendor: "lighttpd", product: "lighttpd" },
  uhttpd: { vendor: "uhttpd", product: "uhttpd" },
  dnsmasq: { vendor: "thekelleys", product: "dnsmasq" },
  openssh: { vendor: "openbsd", product: "openssh" },
  nginx: { vendor: "f5", product: "nginx" },
  curl: { vendor: "haxx", product: "curl" },
  wolfssl: { vendor: "wolfssl", product: "wolfssl" },
  mbedtls: { vendor: "arm", product: "mbed_tls" },
  boa: { vendor: "boa", product: "boa" },
  thttpd: { vendor: "acme", product: "thttpd" },
  mini_httpd: { vendor: "acme", product: "mini_httpd" },
  samba: { vendor: "samba", product: "samba" },
  sqlite: { vendor: "sqlite", product: "sqlite" },
  mosquitto: { vendor: "eclipse", product: "mosquitto" },
  hostapd: { vendor: "w1.fi", product: "hostapd" },
  wpa_supplicant: { vendor: "w1.fi", product: "wpa_supplicant" },
  iptables: { vendor: "netfilter", product: "iptables" },
};

function cvssToSeverity(score: number | null | undefined): "Critical" | "High" | "Medium" | "Low" | "Informational" {
  if (score === null || score === undefined || Number.isNaN(score)) return "Medium";
  if (score >= 9.0) return "Critical";
  if (score >= 7.0) return "High";
  if (score >= 4.0) return "Medium";
  if (score > 0.0) return "Low";
  return "Informational";
}

interface VersionRange {
  versionStart?: string;
  versionEnd?: string;
  startInclusive?: boolean;
  endInclusive?: boolean;
}

function versionMatchesRange(targetVersion: string, range: VersionRange): boolean {
  if (range.versionStart) {
    const cmp = compareVersions(targetVersion, range.versionStart);
    if (range.startInclusive ? cmp < 0 : cmp <= 0) return false;
  }
  if (range.versionEnd) {
    const cmp = compareVersions(targetVersion, range.versionEnd);
    if (range.endInclusive ? cmp > 0 : cmp >= 0) return false;
  }
  return true;
}

export class CirclCveProvider implements CveProvider {
  name = "circl";
  private baseUrl = "https://cve.circl.lu/api";

  async lookupComponent(component: string, version: string | null): Promise<CveMatch[]> {
    const cleanComp = component.toLowerCase().trim();
    if (!cleanComp) return [];

    const mapped = VENDOR_PRODUCT_MAP[cleanComp] ?? { vendor: cleanComp, product: cleanComp };

    const urlsToTry = [
      `${this.baseUrl}/search/${encodeURIComponent(mapped.vendor)}/${encodeURIComponent(mapped.product)}`,
      `${this.baseUrl}/search/${encodeURIComponent(cleanComp)}/${encodeURIComponent(cleanComp)}`,
      `${this.baseUrl}/cvefor/${encodeURIComponent(mapped.vendor)}/${encodeURIComponent(mapped.product)}`,
    ];

    let rawData: unknown = null;
    for (const url of urlsToTry) {
      try {
        const response = await fetch(url, {
          headers: { Accept: "application/json" },
          signal: AbortSignal.timeout(8000),
        });
        if (response.ok) {
          const text = await response.text();
          if (text.trim().startsWith("{") || text.trim().startsWith("[")) {
            rawData = JSON.parse(text);
            if (rawData) break;
          }
        }
      } catch (err) {
        logger.debug({ err, url, component }, "CIRCL lookup attempt failed");
      }
    }

    if (!rawData) {
      throw new Error(`CIRCL lookup failed for ${component}: upstream service unreachable or returned no response`);
    }

    let items: unknown[] = [];
    if (typeof rawData === "object" && rawData !== null) {
      if (Array.isArray(rawData)) {
        items = rawData;
      } else if ("results" in rawData) {
        const res = (rawData as { results: unknown }).results;
        if (Array.isArray(res)) {
          items = res;
        } else if (typeof res === "object" && res !== null) {
          const resObj = res as Record<string, unknown>;
          for (const k of Object.keys(resObj)) {
            const sourceItems = resObj[k];
            if (Array.isArray(sourceItems)) {
              items.push(...sourceItems);
            }
          }
        }
      }
    }

    const matches: CveMatch[] = [];
    for (const item of items) {
      try {
        const match = this.parseItem(item, cleanComp, version);
        if (match) {
          matches.push(match);
        }
      } catch {
        // Skip unparseable item
      }
    }

    return matches;
  }

  private parseItem(item: unknown, component: string, version: string | null): CveMatch | null {
    let cveId = "";
    let summary = "";
    let cvssScore: number | null = null;
    let publishedDate: string | undefined;
    let recordObj: Record<string, unknown> | null = null;

    // Unwrap tuple [cveId, recordObj] if results item is an array tuple
    if (Array.isArray(item) && item.length >= 2) {
      cveId = String(item[0]);
      if (typeof item[1] === "object" && item[1] !== null) {
        recordObj = item[1] as Record<string, unknown>;
      }
    } else if (typeof item === "object" && item !== null) {
      recordObj = item as Record<string, unknown>;
    }

    if (!recordObj) return null;

    const ranges: VersionRange[] = [];

    // Parse CVE v5 record shape
    if (recordObj["dataType"] === "CVE_RECORD" || recordObj["containers"]) {
      const metadata = (recordObj["cveMetadata"] ?? {}) as Record<string, unknown>;
      cveId = cveId || String(metadata["cveId"] ?? "");

      const containers = (recordObj["containers"] ?? {}) as Record<string, unknown>;
      const cna = (containers["cna"] ?? {}) as Record<string, unknown>;

      const descriptions = (cna["descriptions"] ?? []) as Array<{ value?: string }>;
      if (descriptions.length > 0 && descriptions[0].value) {
        summary = descriptions[0].value;
      }

      const metrics = (cna["metrics"] ?? []) as Array<Record<string, unknown>>;
      for (const m of metrics) {
        if (m["cvssV3_1"] && typeof (m["cvssV3_1"] as Record<string, unknown>)["baseScore"] === "number") {
          cvssScore = (m["cvssV3_1"] as Record<string, unknown>)["baseScore"] as number;
          break;
        }
        if (m["cvssV3_0"] && typeof (m["cvssV3_0"] as Record<string, unknown>)["baseScore"] === "number") {
          cvssScore = (m["cvssV3_0"] as Record<string, unknown>)["baseScore"] as number;
          break;
        }
      }

      publishedDate = metadata["datePublished"] ? String(metadata["datePublished"]) : undefined;

      // Extract version ranges from affected array
      const affectedList = (cna["affected"] ?? []) as Array<Record<string, unknown>>;
      for (const aff of affectedList) {
        const versionsList = (aff["versions"] ?? []) as Array<Record<string, unknown>>;
        for (const vObj of versionsList) {
          const status = String(vObj["status"] ?? "");
          if (status.toLowerCase() === "unaffected") continue;

          const verStart = vObj["version"] ? String(vObj["version"]) : undefined;
          const verEnd = vObj["lessThanOrEqual"]
            ? String(vObj["lessThanOrEqual"])
            : vObj["lessThan"]
              ? String(vObj["lessThan"])
              : undefined;

          const startInclusive = true;
          const endInclusive = Boolean(vObj["lessThanOrEqual"]);

          if (verStart || verEnd) {
            ranges.push({
              versionStart: verStart !== "0" && verStart !== "n/a" ? verStart : undefined,
              versionEnd: verEnd !== "n/a" ? verEnd : undefined,
              startInclusive,
              endInclusive,
            });
          }
        }
      }
    } else {
      // Legacy flat cve-search shape
      cveId = cveId || String(recordObj["id"] ?? recordObj["cve"] ?? "");
      summary = String(recordObj["summary"] ?? recordObj["description"] ?? "");
      if (typeof recordObj["cvss"] === "number") {
        cvssScore = recordObj["cvss"];
      } else if (typeof recordObj["cvss"] === "string") {
        cvssScore = Number.parseFloat(recordObj["cvss"]);
      }
      publishedDate = recordObj["Published"] ? String(recordObj["Published"]) : undefined;
    }

    if (!cveId || !cveId.toUpperCase().startsWith("CVE-")) return null;

    let isVersionMatched = false;
    if (version && ranges.length > 0) {
      isVersionMatched = ranges.some((r) => versionMatchesRange(version, r));
    } else {
      // No explicit version ranges in record or no target version provided;
      // keep isVersionMatched false so confidence remains low instead of overclaiming high confidence.
      isVersionMatched = false;
    }

    let confidence: "high" | "medium" | "low" = isVersionMatched && version ? "high" : "low";
    let severity = cvssToSeverity(cvssScore);

    if (!version || !isVersionMatched) {
      severity = "Low";
      confidence = "low";
    }

    return {
      cveId: cveId.toUpperCase(),
      component,
      version,
      severity,
      summary: summary || `Vulnerability in ${component}`,
      publishedDate,
      sourceUrl: `https://cve.circl.lu/cve/${cveId.toUpperCase()}`,
      confidence,
    };
  }
}
