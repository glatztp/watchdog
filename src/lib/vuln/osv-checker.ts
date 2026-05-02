import type { Dependency, Severity, Vulnerability } from "@/schemas";

const OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch";
const BATCH_SIZE = 100;

interface OsvQuery {
  package: { name: string; ecosystem: "npm" };
  version: string;
}

interface OsvVuln {
  id: string;
  aliases?: string[];
  summary?: string;
  severity?: Array<{ type: string; score: string }>;
  affected?: Array<{
    ranges?: Array<{
      type: string;
      events: Array<{ introduced?: string; fixed?: string }>;
    }>;
  }>;
}

interface OsvBatchResponse {
  results: Array<{ vulns?: OsvVuln[] }>;
}

function extractFixedVersion(vuln: OsvVuln): string | null {
  for (const affected of vuln.affected ?? []) {
    for (const range of affected.ranges ?? []) {
      if (range.type !== "ECOSYSTEM") continue;
      for (const event of range.events) {
        if (event.fixed) return event.fixed;
      }
    }
  }
  return null;
}

function parseSeverity(vuln: OsvVuln): Severity {
  const score = vuln.severity?.[0]?.score;
  if (!score) return "UNKNOWN";
  const cvss = parseFloat(score);
  if (cvss >= 9.0) return "CRITICAL";
  if (cvss >= 7.0) return "HIGH";
  if (cvss >= 4.0) return "MEDIUM";
  return "LOW";
}

async function queryBatch(deps: Dependency[]): Promise<Vulnerability[]> {
  const queries: OsvQuery[] = deps.map((d) => ({
    package: { name: d.name, ecosystem: "npm" },
    version: d.version,
  }));

  const res = await fetch(OSV_BATCH_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ queries }),
  });

  if (!res.ok) throw new Error(`OSV API error: ${res.status}`);

  const data: OsvBatchResponse = await res.json();
  const vulns: Vulnerability[] = [];

  for (let i = 0; i < deps.length; i++) {
    const dep = deps[i];
    const result = data.results[i];
    if (!result?.vulns?.length) continue;

    for (const v of result.vulns) {
      vulns.push({
        id: v.id,
        aliases: v.aliases ?? [],
        summary: v.summary ?? "No description available",
        severity: parseSeverity(v),
        fixedVersion: extractFixedVersion(v),
        dependency: dep,
      });
    }
  }

  return vulns;
}

export async function checkVulnerabilities(
  deps: Dependency[],
): Promise<Vulnerability[]> {
  const allVulns: Vulnerability[] = [];

  for (let i = 0; i < deps.length; i += BATCH_SIZE) {
    const batch = deps.slice(i, i + BATCH_SIZE);
    const batchVulns = await queryBatch(batch);
    allVulns.push(...batchVulns);
  }

  return allVulns;
}
