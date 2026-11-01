import type { CveMatch, CveProvider } from "./types";
import { CirclCveProvider } from "./circl-provider";
import { NvdCveProvider } from "./nvd-provider";
import { queryLocalCveRecords } from "./local-cve-db";

class CompositeCveProvider implements CveProvider {
  name: string;
  private upstream: CveProvider;

  constructor(upstream: CveProvider) {
    this.name = `composite-${upstream.name}`;
    this.upstream = upstream;
  }

  async lookupComponent(component: string, version: string | null): Promise<CveMatch[]> {
    const results: CveMatch[] = [];
    const seen = new Set<string>();

    let localSucceeded = false;
    let localError: unknown = null;

    // 1. Query fast local PostgreSQL CVE database first (offline capability)
    try {
      const localMatches = await queryLocalCveRecords(component, version);
      localSucceeded = true;
      for (const m of localMatches) {
        if (!seen.has(m.cveId)) {
          seen.add(m.cveId);
          results.push(m);
        }
      }
    } catch (err) {
      localError = err;
    }

    // 2. Query upstream provider (CIRCL or NVD)
    let upstreamSucceeded = false;
    let upstreamError: unknown = null;
    try {
      const upstreamMatches = await this.upstream.lookupComponent(component, version);
      upstreamSucceeded = true;
      for (const m of upstreamMatches) {
        if (!seen.has(m.cveId)) {
          seen.add(m.cveId);
          results.push(m);
        }
      }
    } catch (err) {
      upstreamError = err;
    }

    // If both local DB and upstream provider failed, report the error up
    if (!localSucceeded && !upstreamSucceeded) {
      throw upstreamError || localError || new Error(`CVE lookup failed for component ${component}: all providers failed`);
    }

    return results;
  }
}

export function getCveProvider(): CveProvider {
  const providerName = (process.env.CVE_PROVIDER ?? "circl").toLowerCase().trim();
  const upstream = providerName === "nvd" ? new NvdCveProvider() : new CirclCveProvider();
  return new CompositeCveProvider(upstream);
}
