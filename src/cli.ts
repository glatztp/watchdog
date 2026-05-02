#!/usr/bin/env tsx
import chalk from "chalk";
import { runPipeline } from "./lib/pipeline";
import { getScanComparison, getHistoryPath } from "./lib/history";
import { logger } from "./lib/logger";
import type { PipelineEvent } from "@/schemas";
import {
  header,
  colors,
  section,
  success,
  error,
  info,
  severity,
  createVulnTable,
  createStatsTable,
  createProgressBar,
  divider,
  spinner,
  showWelcome,
} from "./lib/cli-formatter";

const org = process.argv[2] ?? process.env.TARGET_ORG;

showWelcome();

if (!org) {
  error("Missing organization name");
  console.log(
    chalk.gray("\nUsage: pnpm scan <org-name>\nExample: pnpm scan microsoft"),
  );
  process.exit(1);
}

const GLOBAL_TIMEOUT_MS = 30 * 60 * 1000;
const timeoutHandle = setTimeout(() => {
  error("Pipeline timeout exceeded (30 minutes)");
  process.exit(124);
}, GLOBAL_TIMEOUT_MS);

let currentSpinner: any = null;
let repoCount = 0;
let totalRepos = 0;

function handleEvent(event: PipelineEvent) {
  switch (event.type) {
    case "start": {
      console.clear();
      header("SECURITY SCAN");
      info(`Organization: ${chalk.bold.cyan(event.org)}`);
      info(
        `Total repositories: ${chalk.bold.yellow(String(event.totalRepos))}`,
      );
      divider();
      totalRepos = event.totalRepos;
      repoCount = 0;
      break;
    }

    case "repo:scanning": {
      if (currentSpinner) currentSpinner.stop();
      repoCount++;
      const text = `[${repoCount}/${totalRepos}] Scanning ${chalk.cyan(event.repo)}`;
      currentSpinner = spinner(text);
      break;
    }

    case "repo:done": {
      if (currentSpinner) currentSpinner.stop();
      repoCount++;
      const progress = createProgressBar(repoCount, totalRepos);

      if (event.vulns > 0 || event.risks > 0) {
        const vulnText =
          event.vulns > 0 ? `${colors.error(String(event.vulns))} vulns` : "";
        const riskText =
          event.risks > 0 ? `${colors.warning(String(event.risks))} risks` : "";
        const combined = [vulnText, riskText].filter(Boolean).join(", ");
        console.log(`  ${progress}\n  ${colors.warning("⚠")} ${combined}`);
      } else {
        console.log(`  ${progress}\n  ${colors.success("✓ Clean")}`);
      }
      break;
    }

    case "repo:fixed": {
      if (currentSpinner) currentSpinner.stop();
      success(`PR opened for ${event.repo}`);
      info(`${event.prUrl}`);
      break;
    }

    case "error": {
      if (currentSpinner) currentSpinner.stop();
      error(`${event.repo}: ${event.message}`);
      break;
    }

    case "email:sent": {
      success("Email report sent");
      info(`Report sent to: ${event.to}`);
      break;
    }

    case "email:failed": {
      if (currentSpinner) currentSpinner.stop();
      error(`Failed to send email: ${event.error}`);
      break;
    }

    case "done": {
      if (currentSpinner) currentSpinner.stop();
      const { summary } = event;
      const duration = (
        (summary.finishedAt.getTime() - summary.startedAt.getTime()) /
        1000
      ).toFixed(1);

      console.log("\n");
      header("SCAN SUMMARY");

      const statsTable = createStatsTable({
        totalRepos: summary.totalRepos,
        scannedRepos: summary.totalRepos,
        totalDeps: summary.totalDeps,
        vulnerabilities: summary.totalVulns,
        critical: summary.criticalVulns,
        highRisk: summary.highRiskPackages,
        duration: `${duration}s`,
      });
      console.log(statsTable.toString());

      if (summary.totalVulns > 0) {
        section("🔴 Top Vulnerabilities");
        const vulns = summary.results
          .flatMap((r) => r.vulnerabilities)
          .sort((a, b) => (b.severity > a.severity ? 1 : -1))
          .slice(0, 10);

        const vulnTable = createVulnTable();
        for (const v of vulns) {
          vulnTable.push([
            chalk.cyan(v.dependency.name),
            severity(v.severity),
            chalk.gray(v.dependency.version),
            chalk.green(v.fixedVersion ?? "—"),
            chalk.gray(v.id.substring(0, 16) + "..."),
            chalk.gray(v.dependency.repo.name),
          ]);
        }
        console.log(vulnTable.toString());
      }

      const allPRs = summary.results.flatMap((r) => r.fixedPRs);
      if (allPRs.length > 0) {
        section("✅ Pull Requests Opened");
        for (const pr of allPRs) {
          console.log(`  ${colors.success("→")} ${pr.url}`);
        }
      }

      console.log("\n");

      // Show history comparison
      const comparison = getScanComparison(summary.org, summary);
      if (comparison) {
        section("📊 Comparison vs Last Scan");
        console.log(
          `  Status: ${colors[comparison.status === "improved" ? "success" : comparison.status === "degraded" ? "error" : "warning"](comparison.status.toUpperCase())}`,
        );
        console.log(
          `  Vulnerabilities: ${comparison.totalVulnsDiff > 0 ? colors.error("+" + comparison.totalVulnsDiff) : colors.success(String(comparison.totalVulnsDiff))} (${comparison.vulnPercentageChange}%)`,
        );
        console.log(
          `  New findings: ${colors.error(String(comparison.newVulnerabilities))}`,
        );
        console.log(
          `  Fixed: ${colors.success("✓ " + comparison.fixedVulnerabilities)}`,
        );
      }

      info(`History saved to: ${getHistoryPath(summary.org)}`);
      logger.info("CLI execution completed successfully", { org: summary.org });
      divider();
      console.log("");
      break;
    }
  }
}

runPipeline(org, { onEvent: handleEvent })
  .then(() => {
    clearTimeout(timeoutHandle);
    process.exit(0);
  })
  .catch((err: unknown) => {
    clearTimeout(timeoutHandle);
    if (currentSpinner) currentSpinner.stop();
    const message = err instanceof Error ? err.message : String(err);
    console.log("\n");
    error("Pipeline failed");
    console.log(chalk.gray(`  ${message}\n`));
    process.exit(1);
  });
