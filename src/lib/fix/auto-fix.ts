import { Octokit } from "@octokit/rest";
import type { PullRequest, Vulnerability } from "@/schemas";

const octokit = new Octokit({ auth: process.env.GITHUB_TOKEN });

async function getPackageJsonSha(owner: string, repo: string, branch: string) {
  const { data } = await octokit.repos.getContent({
    owner,
    repo,
    path: "package.json",
    ref: branch,
  });
  if (!("sha" in data)) throw new Error("package.json not found");
  return {
    sha: data.sha,
    content: Buffer.from((data as any).content, "base64").toString("utf-8"),
  };
}

function bumpVersion(
  content: string,
  pkgName: string,
  fixedVersion: string,
): string {
  const pkg = JSON.parse(content);

  if (pkg.dependencies?.[pkgName]) {
    pkg.dependencies[pkgName] = fixedVersion;
  }
  if (pkg.devDependencies?.[pkgName]) {
    pkg.devDependencies[pkgName] = fixedVersion;
  }

  return JSON.stringify(pkg, null, 2) + "\n";
}

function buildPRBody(vulns: Vulnerability[]): string {
  const lines: string[] = [
    "## Automated dependency fix by Watchdog",
    "",
    "### Vulnerabilities fixed",
    "",
  ];

  for (const v of vulns) {
    const cves =
      v.aliases.filter((a) => a.startsWith("CVE")).join(", ") || "No CVE yet";
    lines.push(
      `**${v.dependency.name}** \`${v.dependency.version}\` → \`${v.fixedVersion}\``,
    );
    lines.push(`- ID: ${v.id}`);
    lines.push(`- CVE: ${cves}`);
    lines.push(`- Severity: ${v.severity}`);
    lines.push(`- Summary: ${v.summary}`);
    lines.push("");
  }

  lines.push("---");
  lines.push(
    "*Opened automatically by [Watchdog](https://github.com/your-org/watchdog)*",
  );

  return lines.join("\n");
}

export async function createFixPR(
  owner: string,
  repo: string,
  defaultBranch: string,
  vulns: Vulnerability[],
): Promise<PullRequest | null> {
  const fixable = vulns.filter((v) => v.fixedVersion !== null);
  if (fixable.length === 0) return null;

  const branchName = `watchdog/fix-${Date.now()}`;

  const { data: ref } = await octokit.git.getRef({
    owner,
    repo,
    ref: `heads/${defaultBranch}`,
  });
  const baseSha = ref.object.sha;

  await octokit.git.createRef({
    owner,
    repo,
    ref: `refs/heads/${branchName}`,
    sha: baseSha,
  });

  const { sha, content } = await getPackageJsonSha(owner, repo, defaultBranch);
  let updated = content;
  for (const v of fixable) {
    updated = bumpVersion(updated, v.dependency.name, v.fixedVersion!);
  }

  // Commit the updated package.json
  await octokit.repos.createOrUpdateFileContents({
    owner,
    repo,
    path: "package.json",
    message: `fix(deps): bump ${fixable.map((v) => v.dependency.name).join(", ")} [Watchdog]`,
    content: Buffer.from(updated).toString("base64"),
    sha,
    branch: branchName,
  });

  const pkgNames = [...new Set(fixable.map((v) => v.dependency.name))];
  const { data: pr } = await octokit.pulls.create({
    owner,
    repo,
    head: branchName,
    base: defaultBranch,
    title: `fix(deps): patch ${pkgNames.length} vulnerabilit${pkgNames.length > 1 ? "ies" : "y"} [Watchdog]`,
    body: buildPRBody(fixable),
  });

  return {
    url: pr.html_url,
    number: pr.number,
    repo: `${owner}/${repo}`,
    title: pr.title,
  };
}
