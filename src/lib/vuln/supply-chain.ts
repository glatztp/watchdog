import type { Dependency, SupplyChainRisk, SupplyChainSignal } from "@/schemas";

const NPM_REGISTRY = "https://registry.npmjs.org";

interface SuspiciousPattern {
  re: RegExp;
  type: SupplyChainSignal["type"];
  severity: SupplyChainSignal["severity"];
  detail: string;
  minContext?: number;
}

const SUSPICIOUS_PATTERNS: SuspiciousPattern[] = [
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
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000);

    try {
      const res = await fetch(`${NPM_REGISTRY}/${encodeURIComponent(name)}`, {
        signal: controller.signal,
      });
      if (!res.ok) return null;
      return res.json();
    } finally {
      clearTimeout(timeoutId);
    }
  } catch (err: unknown) {
    if (err instanceof Error && err.name === "AbortError") {
      console.warn(`[supply-chain] Timeout fetching metadata for ${name}`);
    }
    return null;
  }
}

const MAX_TARBALL_SIZE = 5 * 1024 * 1024;

async function fetchPackageTarball(
  name: string,
  version: string,
): Promise<string | null> {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000);

    try {
      const tarballUrl = `${NPM_REGISTRY}/${encodeURIComponent(name)}/-/${name}-${version}.tgz`;
      const res = await fetch(tarballUrl, { signal: controller.signal });
      if (!res.ok) return null;

      const contentLength = res.headers.get("content-length");
      if (contentLength && parseInt(contentLength) > MAX_TARBALL_SIZE) {
        console.warn(`[supply-chain] Tarball too large for ${name}@${version}`);
        return null;
      }

      const buf = await res.arrayBuffer();
      if (buf.byteLength > MAX_TARBALL_SIZE) {
        console.warn(
          `[supply-chain] Tarball exceeded size limit for ${name}@${version}`,
        );
        return null;
      }

      return Buffer.from(buf).toString("latin1");
    } finally {
      clearTimeout(timeoutId);
    }
  } catch (err: unknown) {
    if (err instanceof Error && err.name === "AbortError") {
      console.warn(
        `[supply-chain] Timeout fetching tarball for ${name}@${version}`,
      );
    }
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

  const versions = Object.keys(meta.versions);
  const versionIndex = versions.indexOf(version);
  if (versionIndex <= 0) return signals;

  const prevVersion = versions[versionIndex - 1];
  const versionData = meta.versions[version];
  const prevVersionData = meta.versions[prevVersion];

  if (versionIndex > 10) {
    const oldVersions = versions.slice(0, versionIndex - 10);
    const recentVersions = versions.slice(
      Math.max(0, versionIndex - 10),
      versionIndex,
    );

    if (oldVersions.length > 0 && recentVersions.length > 0) {
      const timeBetween =
        new Date(meta.time[recentVersions[0]]).getTime() -
        new Date(meta.time[oldVersions[oldVersions.length - 1]]).getTime();

      if (timeBetween > 0 && timeBetween < 30 * 24 * 60 * 60 * 1000) {
        signals.push({
          type: "new-maintainer",
          severity: "high",
          detail: `Unusual release velocity: ${recentVersions.length} versions in short timeframe`,
        });
      }
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

    // Check if pattern matches
    const matches = pattern.re.test(tarballContent);
    if (!matches) continue;

    // Validate context size to reduce false positives
    const contextSize = pattern.minContext || 0;
    if (contextSize > 0) {
      const matchIdx = tarballContent.search(pattern.re);
      if (matchIdx > 0) {
        const context = tarballContent.substring(
          Math.max(0, matchIdx - contextSize),
          matchIdx + contextSize,
        );
        // Skip if context contains comments or strings that typically have false positives
        if (context.includes("//") || context.includes("/*")) continue;
      }
    }

    signals.push({
      type: pattern.type,
      severity: pattern.severity,
      detail: pattern.detail,
    });
    seen.add(pattern.detail);
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

  try {
    const meta = await fetchNpmMetadata(dep.name);
    if (meta) {
      signals.push(...checkMaintainerSignals(meta, dep.version));
      signals.push(...checkInstallScriptSignals(meta, dep.version));
    }
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    console.warn(
      `[supply-chain] Error analyzing npm metadata for ${dep.name}: ${message}`,
    );
  }

  try {
    const tarball = await fetchPackageTarball(dep.name, dep.version);
    if (tarball) {
      signals.push(...checkCodeSignals(tarball));
    }
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    console.warn(
      `[supply-chain] Error analyzing code for ${dep.name}@${dep.version}: ${message}`,
    );
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
