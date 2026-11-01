import type { CveMatch } from "./types";
import { getCveProvider } from "./provider-factory";
import { logger } from "../../logger";

export interface ComponentItem {
  name: string;
  version: string | null;
  source: string;
}

export interface CveAnalysisResult {
  matches: CveMatch[];
  checkedCount: number;
  skippedCount: number;
  failedCount: number;
}

const MAX_COMPONENTS_PER_SCAN = Number.parseInt(process.env.MAX_COMPONENTS_PER_SCAN ?? "20", 10) || 20;
const CONCURRENCY = 4;

export async function matchCvesForComponents(
  components: ComponentItem[],
): Promise<CveAnalysisResult> {
  const provider = getCveProvider();

  // Dedupe components by name + version
  const seen = new Set<string>();
  const uniqueComponents: ComponentItem[] = [];

  for (const comp of components) {
    const key = `${comp.name.toLowerCase()}:${(comp.version ?? "").toLowerCase()}`;
    if (!seen.has(key)) {
      seen.add(key);
      uniqueComponents.push(comp);
    }
  }

  const toProcess = uniqueComponents.slice(0, MAX_COMPONENTS_PER_SCAN);
  const skippedCount = Math.max(0, uniqueComponents.length - MAX_COMPONENTS_PER_SCAN);

  let checkedCount = 0;
  let failedCount = 0;
  const allMatches: CveMatch[] = [];

  for (let i = 0; i < toProcess.length; i += CONCURRENCY) {
    const batch = toProcess.slice(i, i + CONCURRENCY);
    const results = await Promise.allSettled(
      batch.map(async (comp) => {
        if (!comp.version) {
          return [];
        }
        return provider.lookupComponent(comp.name, comp.version);
      }),
    );

    for (const res of results) {
      if (res.status === "fulfilled") {
        checkedCount += 1;
        allMatches.push(...res.value);
      } else {
        failedCount += 1;
        logger.warn({ err: res.reason }, "CVE component lookup failed");
      }
    }
  }

  // Dedupe CVE matches by cveId + component
  const matchSeen = new Set<string>();
  const dedupedMatches: CveMatch[] = [];
  for (const match of allMatches) {
    const mKey = `${match.cveId}:${match.component.toLowerCase()}`;
    if (!matchSeen.has(mKey)) {
      matchSeen.add(mKey);
      dedupedMatches.push(match);
    }
  }

  return {
    matches: dedupedMatches,
    checkedCount,
    skippedCount,
    failedCount,
  };
}
