import { Octokit } from "@octokit/rest";
import type { PullRequest, Vulnerability } from "@/schemas";

const octokit = new Octokit({ auth: process.env.GITHUB_TOKEN });

interface PackageJsonResponse {
  sha: string;
  content: string;
}

async function getPackageJsonSha(
  owner: string,
  repo: string,
  branch: string,
): Promise<PackageJsonResponse> {
  const { data } = await octokit.repos.getContent({
    owner,
    repo,
    path: "package.json",
    ref: branch,
  });
  if (!("sha" in data)) throw new Error("package.json not found");
  if (!("content" in data))
    throw new Error("Could not retrieve package.json content");
  return {
    sha: data.sha,
    content: Buffer.from(data.content as string, "base64").toString("utf-8"),
  };
}

function bumpVersion(
  content: string,
  pkgName: string,
  fixedVersion: string,
): string {
  try {
    const pkg: Record<string, unknown> = JSON.parse(content);

    if (typeof pkg.dependencies === "object" && pkg.dependencies !== null) {
      (pkg.dependencies as Record<string, string>)[pkgName] = fixedVersion;
    }
    if (
      typeof pkg.devDependencies === "object" &&
      pkg.devDependencies !== null
    ) {
      (pkg.devDependencies as Record<string, string>)[pkgName] = fixedVersion;
    }

    const result = JSON.stringify(pkg, null, 2) + "\n";
    JSON.parse(result);
    return result;
  } catch (err: unknown) {
    const message =
      err instanceof Error ? err.message : String(err);
    throw new Error(
      `Failed to update package.json for ${pkgName}: ${message}`,
    );
  }}

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
  const fixable = vulns.filter(
    (v) =>
      v.fixedVersion !== null &&
      v.fixedVersion !== undefined &&
      v.fixedVersion.length > 0,
  );
  if (fixable.length === 0) return null;

  const validated = fixable.filter((v) => /^\d+(\.\d+)*/.test(v.fixedVersion!));
  if (validated.length === 0) return null;

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
  for (const v of validated) {
    updated = bumpVersion(updated, v.dependency.name, v.fixedVersion!);
  }

  // Commit the updated package.json
  await octokit.repos.createOrUpdateFileContents({
    owner,
    repo,
    path: "package.json",
    message: `fix(deps): bump ${validated.map((v) => v.dependency.name).join(", ")} [Watchdog]`,
    content: Buffer.from(updated).toString("base64"),
    sha,
    branch: branchName,
  });

  const pkgNames = [...new Set(validated.map((v) => v.dependency.name))];
  const { data: pr } = await octokit.pulls.create({
    owner,
    repo,
    head: branchName,
    base: defaultBranch,
    title: `fix(deps): patch ${pkgNames.length} vulnerabilit${pkgNames.length > 1 ? "ies" : "y"} [Watchdog]`,
    body: buildPRBody(validated),
  });

  const pullRequest: PullRequest = {
    url: pr.html_url,
    number: pr.number,
    repo: `${owner}/${repo}`,
    title: pr.title,
  };

  return pullRequest;
}
