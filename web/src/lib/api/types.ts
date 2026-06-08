/**
 * Runtime-validated API contract. These zod schemas mirror the Go `pkg/api`
 * types 1:1 (and the OpenAPI document in docs/openapi.yaml). The dashboard
 * validates every API response against them, so a backend/contract drift is a
 * loud parse error rather than a silent `undefined` in the UI.
 *
 * `contract.ts` asserts (at compile time) that these inferred types are
 * assignable to the OpenAPI-generated `schema.ts` types — that is the
 * "generated client types match pkg/api" gate.
 */
import { z } from "zod";

export const SeveritySchema = z.enum(["critical", "high", "medium", "low", "info"]);
export type Severity = z.infer<typeof SeveritySchema>;

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export const ResourceRefSchema = z.object({
  kind: z.string(),
  namespace: z.string().optional(),
  name: z.string(),
});
export type ResourceRef = z.infer<typeof ResourceRefSchema>;

export const ControlRefSchema = z.object({
  framework: z.string(),
  id: z.string(),
  title: z.string().optional(),
});

export const EvidenceSchema = z.object({
  path: z.string(),
  value: z.string().optional(),
});

export const RemediationSchema = z.object({
  summary: z.string(),
  snippet: z.string().optional(),
});

export const FindingSchema = z.object({
  id: z.string(),
  title: z.string(),
  severity: SeveritySchema,
  category: z.string(),
  resource: ResourceRefSchema,
  evidence: z.array(EvidenceSchema).optional(),
  remediation: RemediationSchema,
  grants: z.array(z.string()).optional(),
  refs: z.array(ControlRefSchema).optional(),
});
export type Finding = z.infer<typeof FindingSchema>;

export const FindingPageSchema = z.object({
  findings: z.array(FindingSchema),
  total: z.number(),
  limit: z.number(),
  offset: z.number(),
});
export type FindingPage = z.infer<typeof FindingPageSchema>;

export const PostureSummarySchema = z.object({
  totalFindings: z.number(),
  bySeverity: z.record(z.string(), z.number()),
  criticalPaths: z.number(),
  controlsAssessed: z.number(),
  controlsBreached: z.number(),
  overallPassRate: z.number(),
});
export type PostureSummary = z.infer<typeof PostureSummarySchema>;

export const ControlBreachSchema = z.object({
  controlId: z.string(),
  title: z.string().optional(),
  findings: z.array(z.string()),
});

export const FrameworkResultSchema = z.object({
  framework: z.string(),
  version: z.string().optional(),
  assessed: z.number(),
  breached: z.number(),
  passed: z.number(),
  passRate: z.number(),
  breaches: z.array(ControlBreachSchema).optional(),
  disclaimer: z.string(),
});
export type FrameworkResult = z.infer<typeof FrameworkResultSchema>;

export const PostureResponseSchema = z.object({
  posture: PostureSummarySchema,
  compliance: z.array(FrameworkResultSchema),
});
export type PostureResponse = z.infer<typeof PostureResponseSchema>;

export const PathHopSchema = z.object({
  order: z.number(),
  from: z.string(),
  to: z.string(),
  enabledBy: z.string(),
  technique: z.array(z.string()),
  narrative: z.string(),
});
export type PathHop = z.infer<typeof PathHopSchema>;

export const AttackPathSchema = z.object({
  id: z.string(),
  title: z.string(),
  severity: SeveritySchema,
  entry: ResourceRefSchema,
  hops: z.array(PathHopSchema),
  summary: z.string(),
});
export type AttackPath = z.infer<typeof AttackPathSchema>;

export const AttackPathListSchema = z.object({ paths: z.array(AttackPathSchema) });
export type AttackPathList = z.infer<typeof AttackPathListSchema>;

export const ClusterSchema = z.object({
  id: z.string(),
  name: z.string(),
  environment: z.string().optional(),
  lastScanAt: z.string().optional(),
  totalFindings: z.number().optional(),
  overallPassRate: z.number().optional(),
});
export type Cluster = z.infer<typeof ClusterSchema>;

export const ClusterListSchema = z.object({ clusters: z.array(ClusterSchema) });
export type ClusterList = z.infer<typeof ClusterListSchema>;

export const ScanSchema = z.object({
  id: z.string(),
  clusterId: z.string(),
  status: z.enum(["queued", "running", "succeeded", "failed"]),
  startedAt: z.string().optional(),
  finishedAt: z.string().optional(),
  totalFindings: z.number().optional(),
});
export type Scan = z.infer<typeof ScanSchema>;

export const ScanListSchema = z.object({ scans: z.array(ScanSchema), total: z.number() });
export type ScanList = z.infer<typeof ScanListSchema>;

export const HistorySnapshotSchema = z.object({
  scanId: z.string(),
  at: z.string(),
  totalFindings: z.number(),
  controlsAssessed: z.number(),
  controlsBreached: z.number(),
  overallPassRate: z.number(),
  bySeverity: z.record(z.string(), z.number()),
});
export type HistorySnapshot = z.infer<typeof HistorySnapshotSchema>;

export const HistoryListSchema = z.object({ snapshots: z.array(HistorySnapshotSchema) });
export type HistoryList = z.infer<typeof HistoryListSchema>;

export const AuditEntrySchema = z.object({
  at: z.string(),
  subject: z.string(),
  tenant: z.string(),
  action: z.string(),
  resource: z.string().optional(),
  result: z.string(),
});
export type AuditEntry = z.infer<typeof AuditEntrySchema>;

export const AuditListSchema = z.object({ entries: z.array(AuditEntrySchema) });
export type AuditList = z.infer<typeof AuditListSchema>;

export const StreamEventSchema = z.object({
  type: z.enum(["scan_started", "scan_progress", "scan_completed", "posture_updated"]),
  clusterId: z.string().optional(),
  scanId: z.string().optional(),
  progress: z.number().optional(),
  message: z.string().optional(),
});
export type StreamEvent = z.infer<typeof StreamEventSchema>;
