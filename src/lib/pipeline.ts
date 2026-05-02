import { scanOrg } from "./scanner/org-scanner";
import { checkVulnerabilities } from "./vuln/osv-checker";
import { analyzeSupplyChainBatch } from "./vuln/supply-chain";
import { createFixPR } from "./fix/auto-fix";
import { sendScanReport } from "./notify/email";
import type {
  OrgScanSummary,
  PullRequest,
  Repo,
  ScanResult,
  Severity,
  PipelineEvent,
  PipelineOptions,
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

  const repoDepMap = await scanOrg(org);
  const repos = [...repoDepMap.keys()];

  emit({ type: "start", org, totalRepos: repos.length });

  const results: ScanResult[] = [];
  let totalDeps = 0;

  for (const repo of repos) {
    emit({ type: "repo:scanning", repo: repo.name });
    const deps = repoDepMap.get(repo) ?? [];
    totalDeps += deps.length;

    const fixedPRs: PullRequest[] = [];

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
        ).catch((err) => {
          console.error(`[watchdog/autofix] ${repo.name}:`, err.message);
          return null;
        });
        if (pr) {
          fixedPRs.push(pr);
          emit({ type: "repo:fixed", repo: repo.name, prUrl: pr.url });
        }
      }

      results.push({
        repo,
        vulnerabilities,
        supplyChainRisks,
        fixedPRs,
        scannedAt: new Date(),
      });

      emit({
        type: "repo:done",
        repo: repo.name,
        vulns: vulnerabilities.length,
        risks: supplyChainRisks.length,
      });
    } catch (err: any) {
      emit({ type: "error", repo: repo.name, message: err.message });
    }
  }

  const allVulns = results.flatMap((r) => r.vulnerabilities);
  const criticalVulns = allVulns.filter(
    (v) => v.severity === "CRITICAL",
  ).length;
  const highRiskPackages = results
    .flatMap((r) => r.supplyChainRisks)
    .filter((r) => r.score >= 60).length;

  const summary: OrgScanSummary = {
    org,
    totalRepos: repos.length,
    totalDeps,
    totalVulns: allVulns.length,
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

  await sendScanReport(summary).catch((err) =>
    console.error("[watchdog/email]", err.message),
  );

  emit({ type: "done", summary });
  return summary;
}
