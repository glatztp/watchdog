import { readFileSync, writeFileSync, existsSync, mkdirSync } from "fs";
import { resolve } from "path";
import { logger } from "./logger";
import type { OrgScanSummary, ScanComparison } from "@/schemas";

const HISTORY_DIR = resolve(process.cwd(), "scan-history");

try {
  mkdirSync(HISTORY_DIR, { recursive: true });
} catch {
  // Directory might already exist
}

function getHistoryFilePath(org: string): string {
  const filename = `${org.toLowerCase()}-history.json`;
  return resolve(HISTORY_DIR, filename);
}

interface ScanHistoryEntry {
  timestamp: string;
  date: string;
  org: string;
  summary: OrgScanSummary;
}

interface ScanHistory {
  org: string;
  scans: ScanHistoryEntry[];
}

function loadHistory(org: string): ScanHistory {
  const filePath = getHistoryFilePath(org);

  if (!existsSync(filePath)) {
    return { org, scans: [] };
  }

  try {
    const content = readFileSync(filePath, "utf-8");
    return JSON.parse(content);
  } catch (err) {
    logger.error("Failed to load scan history", {
      org,
      error: err instanceof Error ? err.message : String(err),
    });
    return { org, scans: [] };
  }
}

function saveHistory(history: ScanHistory): void {
  const filePath = getHistoryFilePath(history.org);

  try {
    writeFileSync(filePath, JSON.stringify(history, null, 2));
    logger.info("Scan history saved", {
      org: history.org,
      scans: history.scans.length,
    });
  } catch (err) {
    logger.error("Failed to save scan history", {
      org: history.org,
      error: err instanceof Error ? err.message : String(err),
    });
  }
}

function compareSummaries(
  previous: OrgScanSummary,
  current: OrgScanSummary,
): ScanComparison {
  const vulnDiff = current.totalVulns - previous.totalVulns;
  const criticalDiff = current.criticalVulns - previous.criticalVulns;
  const riskDiff = current.highRiskPackages - previous.highRiskPackages;

  const previousVulnIds = new Set(
    previous.results.flatMap((r) => r.vulnerabilities.map((v) => v.id)),
  );
  const currentVulnIds = new Set(
    current.results.flatMap((r) => r.vulnerabilities.map((v) => v.id)),
  );

  const newVulns = Array.from(currentVulnIds).filter(
    (id) => !previousVulnIds.has(id),
  );
  const fixedVulns = Array.from(previousVulnIds).filter(
    (id) => !currentVulnIds.has(id),
  );

  return {
    previousScan: previous.org,
    currentScan: current.org,
    totalVulnsDiff: vulnDiff,
    criticalVulnsDiff: criticalDiff,
    highRiskPackagesDiff: riskDiff,
    newVulnerabilities: newVulns.length,
    fixedVulnerabilities: fixedVulns.length,
    status: vulnDiff > 0 ? "degraded" : vulnDiff < 0 ? "improved" : "stable",
    vulnPercentageChange:
      previous.totalVulns > 0
        ? ((vulnDiff / previous.totalVulns) * 100).toFixed(1)
        : "0",
  };
}

export function saveScan(summary: OrgScanSummary): void {
  const history = loadHistory(summary.org);
  const now = new Date();
  const timestamp = now.toISOString();
  const date = now.toISOString().split("T")[0];

  const entry: ScanHistoryEntry = {
    timestamp,
    date,
    org: summary.org,
    summary,
  };

  history.scans.push(entry);
  if (history.scans.length > 30) {
    history.scans = history.scans.slice(-30);
  }

  saveHistory(history);
  logger.info("Scan recorded in history", { org: summary.org });
}

export function getLastScan(org: string): OrgScanSummary | null {
  const history = loadHistory(org);
  if (history.scans.length === 0) return null;
  return history.scans[history.scans.length - 1].summary;
}

export function getScanComparison(
  org: string,
  current: OrgScanSummary,
): ScanComparison | null {
  const lastScan = getLastScan(org);
  if (!lastScan) return null;
  return compareSummaries(lastScan, current);
}

export function getScanHistory(
  org: string,
  limit: number = 10,
): ScanHistoryEntry[] {
  const history = loadHistory(org);
  return history.scans.slice(-limit);
}

export function getHistoryPath(org: string): string {
  return getHistoryFilePath(org);
}
