import { Octokit } from "@octokit/rest";
import type { Dependency, Repo } from "@/schemas";

if (!process.env.GITHUB_TOKEN) {
  console.warn(
    "⚠ GITHUB_TOKEN not set. Using unauthenticated requests (limited to 60 req/hr)",
  );
}

const octokit = new Octokit({
  auth: process.env.GITHUB_TOKEN,
  throttle: {
    onRateLimit: (retryAfter, options, octokit) => {
      octokit.log.warn(
        `Rate limit exceeded. Retrying after ${retryAfter} seconds`,
      );
      return true;
    },
    onAbuseLimit: (retryAfter, options, octokit) => {
      octokit.log.warn(
        `Abuse limit hit. Retrying after ${retryAfter} seconds`,
      );
      return true;
    },
  },
});

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

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

function resolveVersionRange(versionSpec: string): string | null {
  if (!versionSpec) return null;

  let version = versionSpec.split("-")[0].split("+")[0].trim();

  version = version
    .replace(/^[\^~>=<]+/, "")
    .split(" ")[0]
    .split("x")[0]
    .split("*")[0];

  if (!/^\d+(\.\d+)*$/.test(version)) return null;

  return version;
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
    for (const [name, versionSpec] of Object.entries(map)) {
      const resolved = resolveVersionRange(versionSpec);
      if (!resolved) continue;
      deps.push({ name, version: resolved, type, repo });
    }
  };

  add(pkg.dependencies, "dependency");
  add(pkg.devDependencies, "devDependency");

  return deps;
}

export async function scanOrg(org: string): Promise<Map<Repo, Dependency[]>> {
  const repos = await listOrgRepos(org);
  const result = new Map<Repo, Dependency[]>();

  // Reduced concurrency limit for better rate limit handling
  const CONCURRENCY_LIMIT = 3;
  const REQUEST_DELAY_MS = 100; // 100ms delay between requests
  const chunked: Repo[][] = [];

  for (let i = 0; i < repos.length; i += CONCURRENCY_LIMIT) {
    chunked.push(repos.slice(i, i + CONCURRENCY_LIMIT));
  }

  for (const chunk of chunked) {
    await Promise.allSettled(
      chunk.map(async (repo) => {
        try {
          await delay(REQUEST_DELAY_MS);
          const deps = await extractDepsFromRepo(repo);
          if (deps.length > 0) result.set(repo, deps);
        } catch (err: unknown) {
          const message = err instanceof Error ? err.message : String(err);
          console.warn(`[scanner] Failed to scan ${repo.name}: ${message}`);
        }
      }),
    );
  }

  return result;
}
