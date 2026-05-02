import { Octokit } from "@octokit/rest";
import type { Dependency, Repo } from "@/schemas";

const octokit = new Octokit({ auth: process.env.GITHUB_TOKEN });

async function isOrg(name: string): Promise<boolean> {
  try {
    const { data } = await octokit.users.getByUsername({ username: name });
    return data.type === "Organization";
  } catch {
    return false;
  }
}

export async function listOrgRepos(owner: string): Promise<Repo[]> {
  const repos: Repo[] = [];
  let page = 1;
  const org = await isOrg(owner);

  while (true) {
    const { data } = org
      ? await octokit.repos.listForOrg({
          org: owner,
          type: "all",
          per_page: 100,
          page,
        })
      : await octokit.repos.listForUser({
          username: owner,
          type: "owner",
          per_page: 100,
          page,
        });

    if (data.length === 0) break;

    for (const r of data) {
      if (r.archived || r.disabled) continue;
      repos.push({
        name: r.name,
        fullName: r.full_name,
        owner,
        defaultBranch: r.default_branch,
      });
    }

    if (data.length < 100) break;
    page++;
  }

  return repos;
}

export async function readPackageJson(
  repo: Repo,
): Promise<Record<string, any> | null> {
  try {
    const { data } = await octokit.repos.getContent({
      owner: repo.owner,
      repo: repo.name,
      path: "package.json",
      ref: repo.defaultBranch,
    });

    if (!("content" in data)) return null;

    const raw = Buffer.from(data.content, "base64").toString("utf-8");
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

export async function extractDepsFromRepo(repo: Repo): Promise<Dependency[]> {
  const pkg = await readPackageJson(repo);
  if (!pkg) return [];

  const deps: Dependency[] = [];

  const add = (
    map: Record<string, string> | undefined,
    type: Dependency["type"],
  ) => {
    if (!map) return;
    for (const [name, version] of Object.entries(map)) {
      const cleaned = version.replace(/[\^~>=<]/g, "").split(" ")[0];
      if (!cleaned || cleaned.includes("*")) continue;
      deps.push({ name, version: cleaned, type, repo });
    }
  };

  add(pkg.dependencies, "dependency");
  add(pkg.devDependencies, "devDependency");

  return deps;
}

export async function scanOrg(org: string): Promise<Map<Repo, Dependency[]>> {
  const repos = await listOrgRepos(org);
  const result = new Map<Repo, Dependency[]>();

  await Promise.allSettled(
    repos.map(async (repo) => {
      const deps = await extractDepsFromRepo(repo);
      if (deps.length > 0) result.set(repo, deps);
    }),
  );

  return result;
}
