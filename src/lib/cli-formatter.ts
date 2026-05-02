import chalk from "chalk";
import Table from "cli-table3";
import ora from "ora";

export const colors = {
  success: chalk.greenBright,
  error: chalk.redBright,
  warning: chalk.yellowBright,
  info: chalk.cyanBright,
  muted: chalk.gray,
  bold: chalk.bold,
  critical: chalk.bgRed.whiteBright,
  high: chalk.bgYellowBright.black,
  medium: chalk.bgYellow.black,
  low: chalk.bgBlueBright.black,
  unknown: chalk.bgGray.black,
};

export function showWelcome() {
  console.clear();
  console.log(
    chalk.bold.red(`
 ▓▓   ▓▓ 
 ▓▓   ▓▓ 
 ▓▓   ▓▓ 
 ▓▓ ▓ ▓▓   
  ▓▓ ▓▓               
    `),
  );

  console.log(chalk.bold.cyan("\n   Welcome to Watchdog\n"));
  console.log(
    chalk.gray("   Security vulnerability scanner for GitHub organizations\n"),
  );
  console.log(chalk.gray("   Docs: https://github.com/glatztp/watchdog\n"));
}

export function header(title: string) {
  console.log("\n" + chalk.bold.cyan("┌" + "─".repeat(title.length + 2) + "┐"));
  console.log(chalk.bold.cyan("│ " + title + " │"));
  console.log(chalk.bold.cyan("└" + "─".repeat(title.length + 2) + "┘"));
}

export function divider(char = "─") {
  console.log(chalk.gray("─".repeat(50)));
}

export function spinner(text: string) {
  return ora(text).start();
}

export function section(title: string) {
  console.log("\n" + chalk.bold.cyan("▶ " + title));
}

export function success(message: string) {
  console.log(colors.success("✓ " + message));
}

export function error(message: string) {
  console.error(colors.error("✗ " + message));
}

export function info(message: string) {
  console.log(colors.info("ℹ " + message));
}

export function warning(message: string) {
  console.log(colors.warning("⚠ " + message));
}

export function severity(level: string): string {
  const icons: Record<string, string> = {
    CRITICAL: "🔴",
    HIGH: "🟠",
    MEDIUM: "🟡",
    LOW: "🔵",
    UNKNOWN: "⚪",
  };

  const colorMap: Record<string, (s: string) => string> = {
    CRITICAL: colors.critical,
    HIGH: colors.high,
    MEDIUM: colors.medium,
    LOW: colors.low,
    UNKNOWN: colors.unknown,
  };

  const icon = icons[level] ?? "⚪";
  const color = colorMap[level] ?? chalk.gray;
  return `${icon} ${color(level)}`;
}

export function createVulnTable() {
  return new Table({
    head: [
      chalk.bold("Package"),
      chalk.bold("Severity"),
      chalk.bold("Version"),
      chalk.bold("Fixed"),
      chalk.bold("CVE"),
      chalk.bold("Repo"),
    ],
    style: {
      head: [],
      border: ["cyan"],
      compact: false,
    },
    wordWrap: true,
    colWidths: [20, 15, 12, 12, 20, 20],
  });
}

export function createStatsTable(stats: {
  totalRepos: number;
  scannedRepos: number;
  totalDeps: number;
  vulnerabilities: number;
  critical: number;
  highRisk: number;
  duration: string;
}) {
  const table = new Table({
    style: { head: [], border: ["cyan"], compact: true },
  });

  table.push(
    ["Total Repositories", colors.info(String(stats.totalRepos))],
    ["Scanned Repos", colors.success(String(stats.scannedRepos))],
    ["Total Dependencies", colors.info(String(stats.totalDeps))],
    ["Vulnerabilities Found", colors.warning(String(stats.vulnerabilities))],
    ["Critical Issues", colors.error(String(stats.critical))],
    ["High Risk Packages", colors.warning(String(stats.highRisk))],
    ["Scan Duration", colors.muted(stats.duration)],
  );

  return table;
}

export function createProgressBar(
  current: number,
  total: number,
  width = 30,
): string {
  const percentage = (current / total) * 100;
  const filledWidth = Math.round((width * current) / total);
  const emptyWidth = width - filledWidth;

  const filled = "█".repeat(filledWidth);
  const empty = "░".repeat(emptyWidth);
  const bar = `${filled}${empty}`;

  const percentText = `${percentage.toFixed(1)}%`;
  return `${bar} ${percentText} (${current}/${total})`;
}
