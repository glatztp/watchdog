import { z } from "zod";

export const SeveritySchema = z.enum([
  "CRITICAL",
  "HIGH",
  "MEDIUM",
  "LOW",
  "UNKNOWN",
]);
export type Severity = z.infer<typeof SeveritySchema>;

export const RepoSchema = z.object({
  name: z.string(),
  fullName: z.string(),
  owner: z.string(),
  defaultBranch: z.string(),
});
export type Repo = z.infer<typeof RepoSchema>;

export const DependencySchema = z.object({
  name: z.string(),
  version: z.string(),
  type: z.enum(["dependency", "devDependency"]),
  repo: RepoSchema,
});
export type Dependency = z.infer<typeof DependencySchema>;

export const VulnerabilitySchema = z.object({
  id: z.string(),
  aliases: z.string().array(),
  summary: z.string(),
  severity: SeveritySchema,
  fixedVersion: z.string().nullable(),
  dependency: DependencySchema,
});
export type Vulnerability = z.infer<typeof VulnerabilitySchema>;

export const SignalTypeSchema = z.enum([
  "new-maintainer",
  "new-install-script",
  "obfuscated-code",
  "new-network-call",
  "sensitive-fs-access",
  "new-env-read",
  "typosquatting",
]);
export type SignalType = z.infer<typeof SignalTypeSchema>;

export const SupplyChainSignalSchema = z.object({
  type: SignalTypeSchema,
  severity: z.enum(["high", "medium", "low"]),
  detail: z.string(),
});
export type SupplyChainSignal = z.infer<typeof SupplyChainSignalSchema>;

export const SupplyChainRiskSchema = z.object({
  score: z.number(),
  signals: SupplyChainSignalSchema.array(),
  dependency: DependencySchema,
});
export type SupplyChainRisk = z.infer<typeof SupplyChainRiskSchema>;

export const PullRequestSchema = z.object({
  url: z.string(),
  number: z.number(),
  repo: z.string(),
  title: z.string(),
});
export type PullRequest = z.infer<typeof PullRequestSchema>;

export const ScanResultSchema = z.object({
  repo: RepoSchema,
  vulnerabilities: VulnerabilitySchema.array(),
  supplyChainRisks: SupplyChainRiskSchema.array(),
  fixedPRs: PullRequestSchema.array(),
  scannedAt: z.date(),
});
export type ScanResult = z.infer<typeof ScanResultSchema>;

export const OrgScanSummarySchema = z.object({
  org: z.string(),
  totalRepos: z.number(),
  totalDeps: z.number(),
  totalVulns: z.number(),
  criticalVulns: z.number(),
  highRiskPackages: z.number(),
  results: ScanResultSchema.array(),
  startedAt: z.date(),
  finishedAt: z.date(),
});
export type OrgScanSummary = z.infer<typeof OrgScanSummarySchema>;

export const PipelineEventSchema = z.discriminatedUnion("type", [
  z.object({
    type: z.literal("start"),
    org: z.string(),
    totalRepos: z.number(),
  }),
  z.object({ type: z.literal("repo:scanning"), repo: z.string() }),
  z.object({
    type: z.literal("repo:done"),
    repo: z.string(),
    vulns: z.number(),
    risks: z.number(),
  }),
  z.object({
    type: z.literal("repo:fixed"),
    repo: z.string(),
    prUrl: z.string(),
  }),
  z.object({ type: z.literal("done"), summary: OrgScanSummarySchema }),
  z.object({ type: z.literal("error"), repo: z.string(), message: z.string() }),
]);
export type PipelineEvent = z.infer<typeof PipelineEventSchema>;

export const PipelineOptionsSchema = z
  .object({
    autoFix: z.boolean().optional().default(true),
    riskThreshold: z.number().optional().default(20),
    supplyChainAnalysis: z.boolean().optional().default(true),
    onEvent: z
      .function()
      .args(PipelineEventSchema)
      .returns(z.void())
      .optional(),
  })
  .strict();
export type PipelineOptions = Omit<
  z.infer<typeof PipelineOptionsSchema>,
  "onEvent"
> & {
  onEvent?: (event: PipelineEvent) => void;
};
