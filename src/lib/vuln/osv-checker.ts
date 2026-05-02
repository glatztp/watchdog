import type { Dependency, Severity, Vulnerability } from "@/schemas";

const OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch";
const BATCH_SIZE = 100;
const MAX_RETRIES = 3;
const RETRY_DELAY_MS = 1000;

// Cache vulnerabilities by "name@version"
const VULN_CACHE = new Map<string, Vulnerability[]>();

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
  if (!vuln.severity?.length) return "UNKNOWN";
  let maxScore = 0;
  for (const entry of vuln.severity) {
    if (!entry.score) continue;
    const score = parseFloat(entry.score);
    if (!isNaN(score) && score > maxScore) maxScore = score;
  }

  if (maxScore >= 9.0) return "CRITICAL";
  if (maxScore >= 7.0) return "HIGH";
  if (maxScore >= 4.0) return "MEDIUM";
  if (maxScore > 0) return "LOW";
  return "UNKNOWN";
}

async function queryBatch(
  deps: Dependency[],
  retryCount = 0,
): Promise<Vulnerability[]> {
  const queries: OsvQuery[] = deps.map((d) => ({
    package: { name: d.name, ecosystem: "npm" },
    version: d.version,
  }));

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 30000);

    try {
      const res = await fetch(OSV_BATCH_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ queries }),
        signal: controller.signal,
      });

      if (!res.ok) {
        if (res.status >= 500 && retryCount < MAX_RETRIES) {
          await new Promise((r) =>
            setTimeout(r, RETRY_DELAY_MS * (retryCount + 1)),
          );
          return queryBatch(deps, retryCount + 1);
        }
        throw new Error(`OSV API error: ${res.status}`);
      }

      const data: OsvBatchResponse = await res.json();
      const vulns: Vulnerability[] = [];

      if (!data.results || data.results.length < deps.length) {
        console.warn(
          `[osv-checker] Incomplete response: expected ${deps.length} results, got ${data.results?.length ?? 0}`,
        );
      }

      for (let i = 0; i < deps.length; i++) {
        const dep = deps[i];
        if (i >= data.results.length) {
          console.warn(
            `[osv-checker] Missing result at index ${i} for ${dep.name}@${dep.version}`,
          );
          continue;
        }
        const result = data.results[i];
        if (!result?.vulns?.length) continue;

        for (const v of result.vulns) {
          const fixedVersion = extractFixedVersion(v);
          if (fixedVersion && fixedVersion !== dep.version) {
            vulns.push({
              id: v.id,
              aliases: v.aliases ?? [],
              summary: v.summary ?? "No description available",
              severity: parseSeverity(v),
              fixedVersion,
              dependency: dep,
            });
          }
        }
      }

      return vulns;
    } finally {
      clearTimeout(timeoutId);
    }
  } catch (err: unknown) {
    const isRetryable =
      err instanceof Error &&
      (err.name === "AbortError" ||
        "code" in err ||
        err.message.includes("fetch"));

    if (retryCount < MAX_RETRIES && isRetryable) {
      await new Promise((r) =>
        setTimeout(r, RETRY_DELAY_MS * (retryCount + 1)),
      );
      return queryBatch(deps, retryCount + 1);
    }
    throw err;
  }
}

export async function checkVulnerabilities(
  deps: Dependency[],
): Promise<Vulnerability[]> {
  const allVulns: Vulnerability[] = [];
  const uncached: Dependency[] = [];

  for (const dep of deps) {
    const cacheKey = `${dep.name}@${dep.version}`;
    const cached = VULN_CACHE.get(cacheKey);
    if (cached !== undefined) {
      allVulns.push(...cached);
    } else {
      uncached.push(dep);
    }
  }

  for (let i = 0; i < uncached.length; i += BATCH_SIZE) {
    const batch = uncached.slice(i, i + BATCH_SIZE);
    const batchVulns = await queryBatch(batch);

    for (const batch_dep of batch) {
      const cacheKey = `${batch_dep.name}@${batch_dep.version}`;
      const depVulns = batchVulns.filter(
        (v) =>
          v.dependency.name === batch_dep.name &&
          v.dependency.version === batch_dep.version,
      );
      VULN_CACHE.set(cacheKey, depVulns);
    }

    allVulns.push(...batchVulns);
  }

  return allVulns;
}
