export interface CveMatch {
  cveId: string;
  component: string;
  version: string | null;
  severity: "Critical" | "High" | "Medium" | "Low" | "Informational";
  summary: string;
  publishedDate?: string;
  sourceUrl?: string;
  confidence: "high" | "medium" | "low";
}

export interface CveProvider {
  name: string;
  lookupComponent(component: string, version: string | null): Promise<CveMatch[]>;
}
