import type { Dependency, SupplyChainRisk, SupplyChainSignal } from "@/schemas";

const NPM_REGISTRY = "https://registry.npmjs.org";

const SUSPICIOUS_PATTERNS = [
  {
    re: /eval\s*\(/,
    type: "obfuscated-code" as const,
    severity: "high" as const,
    detail: "eval() call detected",
  },
  {
    re: /Buffer\.from\([^)]+,\s*['"]base64['"]\)/,
    type: "obfuscated-code" as const,
    severity: "high" as const,
    detail: "Base64 decode detected",
  },
  {
    re: /require\(['"]child_process['"]\)/,
    type: "new-network-call" as const,
    severity: "high" as const,
    detail: "child_process usage detected",
  },
  {
    re: /require\(['"]net['"]\)/,
    type: "new-network-call" as const,
    severity: "medium" as const,
    detail: "Raw net module usage detected",
  },
  {
    re: /\.ssh|\.aws\/credentials|\.gnupg/,
    type: "sensitive-fs-access" as const,
    severity: "high" as const,
    detail: "Sensitive path access detected",
  },
  {
    re: /process\.env\b/,
    type: "new-env-read" as const,
    severity: "low" as const,
    detail: "process.env access detected",
  },
];

interface NpmPackageMetadata {
  maintainers: Array<{ name: string; email: string }>;
  time: Record<string, string>;
  versions: Record<
    string,
    {
      scripts?: Record<string, string>;
      dependencies?: Record<string, string>;
    }
  >;
}

async function fetchNpmMetadata(
  name: string,
): Promise<NpmPackageMetadata | null> {
  try {
    const res = await fetch(`${NPM_REGISTRY}/${encodeURIComponent(name)}`);
    if (!res.ok) return null;
    return res.json();
  } catch {
    return null;
  }
}

async function fetchPackageTarball(
  name: string,
  version: string,
): Promise<string | null> {
  try {
    const tarballUrl = `${NPM_REGISTRY}/${encodeURIComponent(name)}/-/${name}-${version}.tgz`;
    const res = await fetch(tarballUrl);
    if (!res.ok) return null;
    const buf = await res.arrayBuffer();
    return Buffer.from(buf).toString("latin1");
  } catch {
    return null;
  }
}

function checkMaintainerSignals(
  meta: NpmPackageMetadata,
  version: string,
): SupplyChainSignal[] {
  const signals: SupplyChainSignal[] = [];
  const publishedAt = meta.time[version];
  if (!publishedAt) return signals;

  const publishDate = new Date(publishedAt);

  const versions = Object.keys(meta.versions);
  const versionIndex = versions.indexOf(version);
  if (versionIndex > 5) {
    const prevVersions = versions.slice(0, versionIndex);
    const currentMaintainers = meta.maintainers.map((m) => m.name);

    if (currentMaintainers.length > meta.maintainers.length) {
      signals.push({
        type: "new-maintainer",
        severity: "high",
        detail: `Maintainer count changed: possible ownership transfer`,
      });
    }
  }

  return signals;
}

function checkInstallScriptSignals(
  meta: NpmPackageMetadata,
  version: string,
): SupplyChainSignal[] {
  const signals: SupplyChainSignal[] = [];
  const versionData = meta.versions[version];
  if (!versionData?.scripts) return signals;

  const dangerousScripts = [
    "preinstall",
    "postinstall",
    "install",
    "preuninstall",
  ];
  for (const script of dangerousScripts) {
    if (versionData.scripts[script]) {
      signals.push({
        type: "new-install-script",
        severity: "high",
        detail: `${script} script: "${versionData.scripts[script].slice(0, 80)}"`,
      });
    }
  }

  return signals;
}

function checkCodeSignals(tarballContent: string): SupplyChainSignal[] {
  const signals: SupplyChainSignal[] = [];
  const seen = new Set<string>();

  for (const pattern of SUSPICIOUS_PATTERNS) {
    if (seen.has(pattern.detail)) continue;
    if (pattern.re.test(tarballContent)) {
      signals.push({
        type: pattern.type,
        severity: pattern.severity,
        detail: pattern.detail,
      });
      seen.add(pattern.detail);
    }
  }

  return signals;
}

function calculateScore(signals: SupplyChainSignal[]): number {
  const weights = { high: 40, medium: 20, low: 5 };
  return Math.min(
    100,
    signals.reduce((acc, s) => acc + weights[s.severity], 0),
  );
}

export async function analyzeSupplyChain(
  dep: Dependency,
): Promise<SupplyChainRisk> {
  const signals: SupplyChainSignal[] = [];

  const meta = await fetchNpmMetadata(dep.name);
  if (meta) {
    signals.push(...checkMaintainerSignals(meta, dep.version));
    signals.push(...checkInstallScriptSignals(meta, dep.version));
  }

  const tarball = await fetchPackageTarball(dep.name, dep.version);
  if (tarball) {
    signals.push(...checkCodeSignals(tarball));
  }

  return {
    score: calculateScore(signals),
    signals,
    dependency: dep,
  };
}

export async function analyzeSupplyChainBatch(
  deps: Dependency[],
): Promise<SupplyChainRisk[]> {
  const prodDeps = deps.filter((d) => d.type === "dependency");
  const results = await Promise.allSettled(prodDeps.map(analyzeSupplyChain));

  return results
    .filter(
      (r): r is PromiseFulfilledResult<SupplyChainRisk> =>
        r.status === "fulfilled",
    )
    .map((r) => r.value)
    .filter((r) => r.score > 0);
}
