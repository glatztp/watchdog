import { Resend } from "resend";
import { getScanComparison } from "../history";
import { logger } from "../logger";
import type { OrgScanSummary, SupplyChainRisk, Vulnerability } from "@/schemas";

let resend: Resend | null = null;

function getResend(): Resend {
  if (!resend) {
    if (!process.env.RESEND_API_KEY) {
      throw new Error("RESEND_API_KEY environment variable is not set");
    }
    resend = new Resend(process.env.RESEND_API_KEY);
  }
  return resend;
}

const FROM = process.env.DEPGUARD_EMAIL_FROM ?? "watchdog@yourdomain.com";
const TO = (process.env.DEPGUARD_EMAIL_TO ?? "")
  .split(",")
  .map((e) => e.trim())
  .filter(Boolean);

function severityBadge(s: string): string {
  const colors: Record<string, string> = {
    CRITICAL: "#dc2626",
    HIGH: "#ea580c",
    MEDIUM: "#d97706",
    LOW: "#2563eb",
    UNKNOWN: "#6b7280",
  };
  const c = colors[s] ?? "#6b7280";
  return `<span style="background:${c};color:#fff;padding:2px 7px;border-radius:4px;font-size:11px;font-weight:600">${s}</span>`;
}

function buildVulnTable(vulns: Vulnerability[]): string {
  const rows = vulns
    .map(
      (v) => `
    <tr>
      <td style="padding:8px 12px;border-bottom:1px solid #e5e7eb">${v.dependency.repo.name}</td>
      <td style="padding:8px 12px;border-bottom:1px solid #e5e7eb"><code>${v.dependency.name}@${v.dependency.version}</code></td>
      <td style="padding:8px 12px;border-bottom:1px solid #e5e7eb">${severityBadge(v.severity)}</td>
      <td style="padding:8px 12px;border-bottom:1px solid #e5e7eb"><code>${v.fixedVersion ?? "unknown"}</code></td>
      <td style="padding:8px 12px;border-bottom:1px solid #e5e7eb">${v.id}</td>
    </tr>`,
    )
    .join("");

  return `
    <table style="width:100%;border-collapse:collapse;font-size:13px">
      <thead>
        <tr style="background:#f9fafb">
          <th style="padding:8px 12px;text-align:left;border-bottom:2px solid #e5e7eb">Repo</th>
          <th style="padding:8px 12px;text-align:left;border-bottom:2px solid #e5e7eb">Package</th>
          <th style="padding:8px 12px;text-align:left;border-bottom:2px solid #e5e7eb">Severity</th>
          <th style="padding:8px 12px;text-align:left;border-bottom:2px solid #e5e7eb">Fix</th>
          <th style="padding:8px 12px;text-align:left;border-bottom:2px solid #e5e7eb">ID</th>
        </tr>
      </thead>
      <tbody>${rows}</tbody>
    </table>`;
}

function buildSupplyChainTable(risks: SupplyChainRisk[]): string {
  const rows = risks
    .map(
      (r) => `
    <tr>
      <td style="padding:8px 12px;border-bottom:1px solid #e5e7eb">${r.dependency.repo.name}</td>
      <td style="padding:8px 12px;border-bottom:1px solid #e5e7eb"><code>${r.dependency.name}@${r.dependency.version}</code></td>
      <td style="padding:8px 12px;border-bottom:1px solid #e5e7eb">
        <span style="font-weight:600;color:${r.score >= 60 ? "#dc2626" : "#d97706"}">${r.score}/100</span>
      </td>
      <td style="padding:8px 12px;border-bottom:1px solid #e5e7eb;font-size:12px;color:#6b7280">
        ${r.signals.map((s) => s.detail).join("<br>")}
      </td>
    </tr>`,
    )
    .join("");

  return `
    <table style="width:100%;border-collapse:collapse;font-size:13px">
      <thead>
        <tr style="background:#fff7ed">
          <th style="padding:8px 12px;text-align:left;border-bottom:2px solid #fed7aa">Repo</th>
          <th style="padding:8px 12px;text-align:left;border-bottom:2px solid #fed7aa">Package</th>
          <th style="padding:8px 12px;text-align:left;border-bottom:2px solid #fed7aa">Risk score</th>
          <th style="padding:8px 12px;text-align:left;border-bottom:2px solid #fed7aa">Signals</th>
        </tr>
      </thead>
      <tbody>${rows}</tbody>
    </table>`;
}

function buildHtml(summary: OrgScanSummary): string {
  const allVulns = summary.results.flatMap((r) => r.vulnerabilities);
  const allRisks = summary.results.flatMap((r) => r.supplyChainRisks);
  const allPRs = summary.results.flatMap((r) => r.fixedPRs);

  const prList = allPRs
    .map((pr) => `<li><a href="${pr.url}">${pr.title}</a> — ${pr.repo}</li>`)
    .join("");

  return `
  <div style="font-family:system-ui,sans-serif;max-width:800px;margin:0 auto;color:#111827">
    <div style="background:#111827;color:#fff;padding:24px 32px;border-radius:8px 8px 0 0">
      <h1 style="margin:0;font-size:20px">Watchdog Scan Report</h1>
      <p style="margin:4px 0 0;color:#9ca3af;font-size:13px">
        ${summary.org} · ${summary.results[0]?.scannedAt.toISOString().slice(0, 16).replace("T", " ")} UTC
      </p>
    </div>

    <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:1px;background:#e5e7eb">
      ${[
        ["Repos scanned", summary.totalRepos],
        ["Total deps", summary.totalDeps],
        ["Vulnerabilities", summary.totalVulns],
        ["Critical", summary.criticalVulns],
      ]
        .map(
          ([label, val]) => `
        <div style="background:#fff;padding:16px 20px">
          <div style="font-size:22px;font-weight:700;color:${label === "Critical" && Number(val) > 0 ? "#dc2626" : "#111827"}">${val}</div>
          <div style="font-size:12px;color:#6b7280;margin-top:2px">${label}</div>
        </div>`,
        )
        .join("")}
    </div>

    ${
      allVulns.length > 0
        ? `
    <div style="padding:24px 32px">
      <h2 style="font-size:15px;margin:0 0 12px">Known CVEs (Layer 1)</h2>
      ${buildVulnTable(allVulns)}
    </div>`
        : ""
    }

    ${
      allRisks.length > 0
        ? `
    <div style="padding:0 32px 24px">
      <h2 style="font-size:15px;margin:0 0 12px">Supply chain risks (Layer 2 — no CVE)</h2>
      ${buildSupplyChainTable(allRisks)}
    </div>`
        : ""
    }

    ${
      allPRs.length > 0
        ? `
    <div style="padding:0 32px 24px;background:#f0fdf4;border-top:1px solid #bbf7d0">
      <h2 style="font-size:15px;margin:12px 0">Pull requests opened automatically</h2>
      <ul style="margin:0;padding-left:20px;font-size:13px;line-height:2">${prList}</ul>
    </div>`
        : ""
    }

    <div style="padding:16px 32px;background:#f9fafb;border-top:1px solid #e5e7eb;font-size:12px;color:#9ca3af;border-radius:0 0 8px 8px">
      Sent by Watchdog — automated dependency security scanner
    </div>
  </div>`;
}

export async function sendScanReport(summary: OrgScanSummary): Promise<void> {
  if (TO.length === 0) {
    console.warn("[watchdog/email] DEPGUARD_EMAIL_TO not set, skipping email");
    return;
  }

  const allVulns = summary.results.flatMap((r) => r.vulnerabilities);
  const allRisks = summary.results.flatMap((r) => r.supplyChainRisks);
  const hasCritical = summary.criticalVulns > 0;
  const hasRisks = allRisks.some((r) => r.score >= 60);

  const subject = hasCritical
    ? `[Watchdog] CRITICAL — ${summary.criticalVulns} critical vuln${summary.criticalVulns > 1 ? "s" : ""} in ${summary.org}`
    : hasRisks
      ? `[Watchdog] Supply chain risk detected in ${summary.org}`
      : `[Watchdog] Scan complete — ${summary.totalVulns} vulnerabilities in ${summary.org}`;

  const emailClient = getResend();
  await emailClient.emails.send({
    from: FROM as string,
    to: TO as string[],
    subject,
    html: buildHtml(summary),
  });
}
