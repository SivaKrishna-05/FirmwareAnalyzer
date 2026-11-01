import { CirclCveProvider } from "../artifacts/api-server/src/lib/analysis/cve/circl-provider";

async function debug() {
  const url = "https://cve.circl.lu/api/search/busybox/busybox";
  const response = await fetch(url, { headers: { Accept: "application/json" } });
  const json = await response.json();
  console.log("json type:", typeof json);
  console.log("results type:", typeof json.results);
  console.log("results isArray:", Array.isArray(json.results));
  console.log("results keys:", Object.keys(json.results ?? {}));
  console.log("Sample result item:", JSON.stringify(json.results?.[0] ?? json.results, null, 2).slice(0, 400));
}

debug().catch(console.error);
