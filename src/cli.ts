#!/usr/bin/env tsx
import { runPipeline } from "./lib/pipeline";
import type { PipelineEvent } from "@/schemas";

const org = process.argv[2] ?? process.env.TARGET_ORG;

if (!org) {
  console.error("Usage: pnpm scan <org-name>");
  process.exit(1);
}

const SEVERITY_ICON: Record<string, string> = {
  CRITICAL: "🔴",
  HIGH: "🟠",
  MEDIUM: "🟡",
  LOW: "🔵",
  UNKNOWN: "⚪",
};

function handleEvent(event: PipelineEvent) {
  switch (event.type) {
    case "start":
      console.log(`\n▶  Scanning ${event.org} — ${event.totalRepos} repos\n`);
      break;
    case "repo:scanning":
      process.stdout.write(`  scanning ${event.repo}...`);
      break;
    case "repo:done":
      process.stdout.write(
        event.vulns > 0 || event.risks > 0
          ? ` ⚠  ${event.vulns} vulns, ${event.risks} risks\n`
          : ` ✓\n`,
      );
      break;
    case "repo:fixed":
      console.log(`  ✅ PR opened: ${event.prUrl}`);
      break;
    case "error":
      console.error(`  ✗ ${event.repo}: ${event.message}`);
      break;
    case "done": {
      const { summary } = event;
      console.log("\n──────────────────────────────────────");
      console.log(`Scan complete — ${summary.org}`);
      console.log(`  Repos:           ${summary.totalRepos}`);
      console.log(`  Dependencies:    ${summary.totalDeps}`);
      console.log(`  Vulnerabilities: ${summary.totalVulns}`);
      console.log(`  Critical:        ${summary.criticalVulns}`);
      console.log(`  High-risk pkgs:  ${summary.highRiskPackages}`);
      console.log(
        `  Duration:        ${(summary.finishedAt.getTime() - summary.startedAt.getTime()) / 1000}s`,
      );

      if (summary.totalVulns > 0) {
        console.log("\nTop vulnerabilities:");
        const vulns = summary.results
          .flatMap((r) => r.vulnerabilities)
          .sort((a, b) => (b.severity > a.severity ? 1 : -1))
          .slice(0, 10);

        for (const v of vulns) {
          const icon = SEVERITY_ICON[v.severity] ?? "⚪";
          console.log(
            `  ${icon} ${v.dependency.name}@${v.dependency.version} → ${v.fixedVersion ?? "?"} ` +
              `[${v.dependency.repo.name}] ${v.id}`,
          );
        }
      }

      const allPRs = summary.results.flatMap((r) => r.fixedPRs);
      if (allPRs.length > 0) {
        console.log("\nPull requests opened:");
        for (const pr of allPRs) console.log(`  ${pr.url}`);
      }

      console.log("\nEmail report sent.\n");
      break;
    }
  }
}

runPipeline(org, { onEvent: handleEvent }).catch((err) => {
  console.error("Pipeline failed:", err.message);
  process.exit(1);
});
