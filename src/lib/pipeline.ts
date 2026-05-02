import { scanOrg } from "./scanner/org-scanner";
import { checkVulnerabilities } from "./vuln/osv-checker";
import { analyzeSupplyChainBatch } from "./vuln/supply-chain";
import { createFixPR } from "./fix/auto-fix";
import { sendScanReport } from "./notify/email";
import { getWatchlistDependencies } from "./vuln/watchlist";
import type {
  OrgScanSummary,
  PullRequest,
  Repo,
  ScanResult,
  Severity,
  PipelineEvent,
  PipelineOptions,
  Dependency,
} from "@/schemas";

const SEVERITY_ORDER: Record<Severity, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
  UNKNOWN: 0,
};

export type { PipelineEvent, PipelineOptions };

export async function runPipeline(
  org: string,
  options: PipelineOptions = {},
): Promise<OrgScanSummary> {
  const {
    autoFix = true,
    riskThreshold = 20,
    supplyChainAnalysis = true,
    onEvent,
  } = options;

  const emit = (e: PipelineEvent) => onEvent?.(e);
  const startedAt = new Date();

  let repoDepMap: Map<Repo, Dependency[]>;
  try {
    repoDepMap = await scanOrg(org);
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    emit({ type: "error", repo: "org-scan", message });
    throw new Error(`Failed to scan organization: ${message}`);
  }
  const repos = [...repoDepMap.keys()];

  emit({ type: "start", org, totalRepos: repos.length });

  const results: ScanResult[] = [];
  const allFixedPRs: PullRequest[] = [];
  let totalDeps = 0;

  for (const repo of repos) {
    emit({ type: "repo:scanning", repo: repo.name });
    let deps = repoDepMap.get(repo) ?? [];
    const watchlistDeps = getWatchlistDependencies(repo) ?? [];
    deps = [...deps, ...watchlistDeps];

    if (deps.length === 0) {
      emit({ type: "repo:done", repo: repo.name, vulns: 0, risks: 0 });
      continue;
    }

    totalDeps += deps.length;
    const repoPRs: PullRequest[] = [];

    try {
      const vulnerabilities = await checkVulnerabilities(deps);

      const supplyChainRisks = supplyChainAnalysis
        ? (await analyzeSupplyChainBatch(deps)).filter(
            (r) => r.score >= riskThreshold,
          )
        : [];

      if (autoFix && vulnerabilities.length > 0) {
        const pr = await createFixPR(
          repo.owner,
          repo.name,
          repo.defaultBranch,
          vulnerabilities,
        ).catch((err: unknown) => {
          const message = err instanceof Error ? err.message : String(err);
          console.error(`[watchdog/autofix] ${repo.name}:`, message);
          return null;
        });
        if (pr) {
          repoPRs.push(pr);
          allFixedPRs.push(pr);
          emit({ type: "repo:fixed", repo: repo.name, prUrl: pr.url });
        }
      }

      results.push({
        repo,
        vulnerabilities,
        supplyChainRisks,
        fixedPRs: repoPRs,
        scannedAt: new Date(),
      });

      emit({
        type: "repo:done",
        repo: repo.name,
        vulns: vulnerabilities.length,
        risks: supplyChainRisks.length,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      emit({ type: "error", repo: repo.name, message });
    }
  }

  const allVulns = results.flatMap((r) => r.vulnerabilities);

  // Deduplicate vulnerabilities by unique key
  const vulnMap = new Map<string, (typeof allVulns)[0]>();
  for (const vuln of allVulns) {
    const key = `${vuln.id}@${vuln.dependency.name}@${vuln.dependency.version}`;
    if (!vulnMap.has(key)) {
      vulnMap.set(key, vuln);
    }
  }
  const deduplicatedVulns = Array.from(vulnMap.values());

  const criticalVulns = deduplicatedVulns.filter(
    (v) => v.severity === "CRITICAL",
  ).length;
  const highRiskPackages = results
    .flatMap((r) => r.supplyChainRisks)
    .filter((r) => r.score >= 60).length;

  const summary: OrgScanSummary = {
    org,
    totalRepos: repos.length,
    totalDeps,
    totalVulns: deduplicatedVulns.length,
    criticalVulns,
    highRiskPackages,
    results: results.sort((a, b) => {
      const aMax = Math.max(
        ...a.vulnerabilities.map((v) => SEVERITY_ORDER[v.severity]),
        0,
      );
      const bMax = Math.max(
        ...b.vulnerabilities.map((v) => SEVERITY_ORDER[v.severity]),
        0,
      );
      return bMax - aMax;
    }),
    startedAt,
    finishedAt: new Date(),
  };

  await sendScanReport(summary).catch((err: unknown) => {
    const message = err instanceof Error ? err.message : String(err);
    console.error("[watchdog/email]", message);
  });

  emit({ type: "done", summary });
  return summary;
}
