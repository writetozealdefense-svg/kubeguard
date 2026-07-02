/**
 * Mock fixtures + a cluster-aware in-memory transport. Used by Vitest and by
 * `VITE_USE_MOCK=1` (dev / Playwright) so every lens renders for ≥2 clusters
 * without a live backend. prod-eu mirrors the engine's vulnerable fixture
 * (cluster-admin chain); staging is hardened (0 findings). The transport
 * implements the same server-side finding filter/sort/paginate contract the Go
 * BFF serves, so the Findings view behaves identically off mock or real data.
 */
import type { Transport } from "./client";
import type {
  AttackPathList,
  ClusterList,
  Finding,
  FindingLifecycle,
  FindingPage,
  HistoryList,
  PostureResponse,
  ScanList,
  Severity,
  StreamEvent,
} from "./types";
import { SEVERITY_ORDER } from "./types";

// In-memory event bus so the mock streams scan lifecycle events just like the
// real BFF: POST /v1/scans publishes; /v1/stream subscribers relay them.
type Listener = (ev: StreamEvent) => void;
const listeners = new Set<Listener>();
function publish(ev: StreamEvent) {
  for (const l of listeners) l(ev);
}

const DISCLAIMER =
  "Indicative control mapping only; not a certification or audit. Pass rate is passed of assessed.";

export const mockClusters: ClusterList = {
  clusters: [
    { id: "prod-eu", name: "prod-eu", environment: "production", lastScanAt: "2026-06-07T08:00:00Z", totalFindings: 19, overallPassRate: 0.19 },
    { id: "staging-us", name: "staging-us", environment: "staging", lastScanAt: "2026-06-07T07:30:00Z", totalFindings: 0, overallPassRate: 1 },
  ],
};

export const mockScans: ScanList = {
  total: 2,
  scans: [
    { id: "scan-1002", clusterId: "prod-eu", status: "succeeded", startedAt: "2026-06-07T08:00:00Z", finishedAt: "2026-06-07T08:00:04Z", totalFindings: 19 },
    { id: "scan-1001", clusterId: "prod-eu", status: "succeeded", startedAt: "2026-06-06T08:00:00Z", finishedAt: "2026-06-06T08:00:05Z", totalFindings: 22 },
  ],
};

const prodFindings: Finding[] = [
  {
    id: "KG-001", title: "Privileged container", severity: "critical", category: "workload",
    resource: { kind: "Deployment", namespace: "payments", name: "checkout" },
    evidence: [{ path: "spec.template.spec.containers[0].securityContext.privileged", value: "true" }],
    remediation: { summary: "Set securityContext.privileged=false and drop ALL capabilities.", snippet: "securityContext:\n  privileged: false\n  capabilities: { drop: [ALL] }" },
    grants: ["ContainerEscape"], refs: [{ framework: "CIS", id: "5.2.1", title: "Minimize privileged containers" }, { framework: "ATT&CK", id: "T1611" }],
  },
  {
    id: "KG-011", title: "Binding grants cluster-admin to a ServiceAccount", severity: "critical", category: "rbac",
    resource: { kind: "ClusterRoleBinding", name: "checkout-cluster-admin" },
    evidence: [{ path: "roleRef", value: "cluster-admin" }],
    remediation: { summary: "Remove the cluster-admin binding; grant least-privilege roles." },
    grants: ["ClusterAdmin"], refs: [{ framework: "NSA", id: "RBAC", title: "Least privilege" }, { framework: "ATT&CK", id: "T1078" }],
  },
  {
    id: "KG-013", title: "RBAC allows reading Secrets", severity: "high", category: "rbac",
    resource: { kind: "ClusterRole", name: "checkout-power" },
    remediation: { summary: "Scope the Role to specific named secrets, or remove secrets read." },
    grants: ["SecretRead"], refs: [{ framework: "CIS", id: "5.1.3" }],
  },
  {
    id: "KG-018", title: "Service exposed externally", severity: "high", category: "network",
    resource: { kind: "Service", namespace: "payments", name: "checkout-lb" },
    remediation: { summary: "Use ClusterIP + an ingress with authn, or restrict loadBalancerSourceRanges." },
    grants: ["InternetIngress"], refs: [{ framework: "CIS", id: "5.4.2" }],
  },
  {
    id: "KG-017", title: "Namespace has no default-deny NetworkPolicy", severity: "medium", category: "network",
    resource: { kind: "Namespace", name: "payments" },
    remediation: { summary: "Add a default-deny NetworkPolicy and allow only required flows." },
    grants: ["LateralMovement"], refs: [{ framework: "NIST SP 800-53 Rev. 5", id: "SC-7" }],
  },
  {
    id: "KG-019", title: "Image uses a mutable tag", severity: "low", category: "supply-chain",
    resource: { kind: "Deployment", namespace: "payments", name: "checkout" },
    remediation: { summary: "Pin the image to a digest (sha256:...)." },
    refs: [{ framework: "CIS", id: "5.5.1" }],
  },
];

export const mockFindings: FindingPage = { total: 3, limit: 50, offset: 0, findings: prodFindings.slice(0, 3) };

const prodPosture: PostureResponse = {
  posture: { totalFindings: prodFindings.length, bySeverity: countBySeverity(prodFindings), criticalPaths: 1, controlsAssessed: 32, controlsBreached: 26, overallPassRate: 0.19 },
  compliance: [
    { framework: "CIS Kubernetes Benchmark", version: "1.9", assessed: 9, breached: 8, passed: 1, passRate: 0.11, disclaimer: DISCLAIMER, breaches: [{ controlId: "5.2.1", title: "Minimize privileged containers", findings: ["KG-001"] }, { controlId: "5.1.3", title: "Minimize secret access", findings: ["KG-013"] }] },
    { framework: "NIST SP 800-53 Rev. 5", assessed: 6, breached: 6, passed: 0, passRate: 0.0, disclaimer: DISCLAIMER, breaches: [{ controlId: "SC-7", title: "Boundary protection", findings: ["KG-017", "KG-018"] }] },
    { framework: "PCI DSS v4.0", assessed: 5, breached: 5, passed: 0, passRate: 0.0, disclaimer: DISCLAIMER },
  ],
};

const stagingPosture: PostureResponse = {
  posture: { totalFindings: 0, bySeverity: {}, criticalPaths: 0, controlsAssessed: 32, controlsBreached: 0, overallPassRate: 1 },
  compliance: [
    { framework: "CIS Kubernetes Benchmark", version: "1.9", assessed: 9, breached: 0, passed: 9, passRate: 1, disclaimer: DISCLAIMER },
    { framework: "NIST SP 800-53 Rev. 5", assessed: 6, breached: 0, passed: 6, passRate: 1, disclaimer: DISCLAIMER },
    { framework: "PCI DSS v4.0", assessed: 5, breached: 0, passed: 5, passRate: 1, disclaimer: DISCLAIMER },
  ],
};

export const mockPosture = prodPosture;

const prodPaths: AttackPathList = {
  paths: [
    {
      id: "AP-001", title: "Cluster-admin takeover via checkout", severity: "critical",
      entry: { kind: "Service", namespace: "payments", name: "checkout-lb" },
      summary: "Internet-facing privileged workload chains to full cluster control.",
      hops: [
        { order: 1, from: "InternetIngress", to: "NetworkReachable", enabledBy: "KG-018", technique: ["T1190"], narrative: "Internet-facing Service exposes the workload." },
        { order: 2, from: "NetworkReachable", to: "ContainerEscape", enabledBy: "KG-001", technique: ["T1611"], narrative: "Privileged container allows breakout." },
        { order: 3, from: "ContainerEscape", to: "NodeAccess", enabledBy: "KG-002", technique: ["T1611"], narrative: "Breakout yields node code execution." },
        { order: 4, from: "NodeAccess", to: "ServiceAccountToken", enabledBy: "KG-015", technique: ["T1552.001"], narrative: "SA token is auto-mounted and harvestable." },
        { order: 5, from: "ServiceAccountToken", to: "ClusterAdmin", enabledBy: "KG-011", technique: ["T1078"], narrative: "SA is bound to cluster-admin." },
        { order: 6, from: "ClusterAdmin", to: "LateralMovement", enabledBy: "KG-017", technique: ["T1021"], narrative: "No default-deny enables lateral movement." },
      ],
    },
  ],
};

export const mockAttackPaths = prodPaths;

const prodHistory: HistoryList = {
  snapshots: [
    { scanId: "scan-1000", at: "2026-06-05T08:00:00Z", totalFindings: 24, controlsAssessed: 32, controlsBreached: 29, overallPassRate: 0.09, bySeverity: { critical: 5, high: 8, medium: 6, low: 5 } },
    { scanId: "scan-1001", at: "2026-06-06T08:00:00Z", totalFindings: 22, controlsAssessed: 32, controlsBreached: 28, overallPassRate: 0.13, bySeverity: { critical: 5, high: 7, medium: 5, low: 5 } },
    { scanId: "scan-1002", at: "2026-06-07T08:00:00Z", totalFindings: 19, controlsAssessed: 32, controlsBreached: 26, overallPassRate: 0.19, bySeverity: { critical: 4, high: 7, medium: 4, low: 4 } },
  ],
};

export const mockHistory = prodHistory;

function countBySeverity(fs: Finding[]): Record<string, number> {
  const out: Record<string, number> = {};
  for (const f of fs) out[f.severity] = (out[f.severity] ?? 0) + 1;
  return out;
}

function clusterFindings(cluster: string | null): Finding[] {
  if (cluster === "staging-us") return [];
  return prodFindings; // prod-eu and the "all clusters" view
}

function filterSortPage(all: Finding[], params: URLSearchParams): FindingPage {
  let fs = [...all];
  const sev = params.get("severity");
  if (sev) {
    const set = new Set(sev.split(",").map((s) => s.trim()));
    fs = fs.filter((f) => set.has(f.severity));
  }
  const cat = params.get("category");
  if (cat) fs = fs.filter((f) => f.category.toLowerCase() === cat.toLowerCase());
  const ns = params.get("namespace");
  if (ns) fs = fs.filter((f) => (f.resource.namespace ?? "").toLowerCase() === ns.toLowerCase());
  const fw = params.get("framework");
  if (fw) fs = fs.filter((f) => (f.refs ?? []).some((r) => r.framework.toLowerCase().includes(fw.toLowerCase())));
  const search = params.get("search");
  if (search) {
    const t = search.toLowerCase();
    fs = fs.filter((f) => `${f.id} ${f.title} ${f.category} ${f.resource.kind} ${f.resource.namespace ?? ""} ${f.resource.name}`.toLowerCase().includes(t));
  }
  const key = params.get("sort") ?? "severity";
  fs.sort((a, b) => {
    if (key === "id") return a.id.localeCompare(b.id);
    if (key === "category") return a.category.localeCompare(b.category) || a.id.localeCompare(b.id);
    return SEVERITY_ORDER.indexOf(a.severity as Severity) - SEVERITY_ORDER.indexOf(b.severity as Severity) || a.id.localeCompare(b.id);
  });
  if ((params.get("order") ?? "desc") === "desc" && key === "severity") {
    // SEVERITY_ORDER is already critical→info, so ascending index = most severe first.
  } else if ((params.get("order") ?? "desc") === "desc") {
    fs.reverse();
  }
  const total = fs.length;
  const limit = Number(params.get("limit") ?? "50");
  const offset = Number(params.get("offset") ?? "0");
  return { total, limit, offset, findings: fs.slice(offset, limit > 0 ? offset + limit : undefined) };
}

function json(body: unknown): Response {
  return new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } });
}

// --- findings lifecycle (K6): in-memory triage state for the mock ---
const mockKey = (f: Finding) => `prod-eu|${f.id}|${f.resource.kind}/${f.resource.namespace ?? ""}/${f.resource.name}`;
const lifecycleState = new Map<string, FindingLifecycle>();
function seedLifecycle() {
  if (lifecycleState.size > 0) return;
  for (const f of prodFindings) {
    const key = mockKey(f);
    lifecycleState.set(key, {
      key, clusterId: "prod-eu", findingId: f.id, resource: f.resource,
      state: "open", firstSeen: "2026-06-05T08:00:00Z",
    });
  }
}
function lifecycleView() {
  seedLifecycle();
  const items = [...lifecycleState.values()];
  const mttr = { open: 0, acknowledged: 0, inProgress: 0, resolved: 0, riskAccepted: 0, meanTimeToResolveHours: 0 };
  for (const it of items) {
    if (it.state === "open") mttr.open++;
    else if (it.state === "acknowledged") mttr.acknowledged++;
    else if (it.state === "in-progress") mttr.inProgress++;
    else if (it.state === "resolved") mttr.resolved++;
    else if (it.state === "risk-accepted") mttr.riskAccepted++;
  }
  return { items, mttr };
}

/** Cluster-aware in-memory transport. */
export const mockTransport: Transport = async (path, init) => {
  const [url, qs] = path.split("?");
  const params = new URLSearchParams(qs ?? "");
  const cluster = params.get("cluster");

  if (init?.method === "POST" && url === "/v1/scans") {
    let cid = cluster ?? "prod-eu";
    try {
      cid = JSON.parse(String(init.body)).clusterId ?? cid;
    } catch {
      /* keep default */
    }
    const scanId = "scan-new";
    publish({ type: "scan_started", clusterId: cid, scanId });
    publish({ type: "scan_progress", clusterId: cid, scanId, progress: 0.5 });
    setTimeout(() => {
      publish({ type: "scan_completed", clusterId: cid, scanId, progress: 1 });
      publish({ type: "posture_updated", clusterId: cid });
    }, 120);
    return new Response(JSON.stringify({ id: scanId, clusterId: cid, status: "queued" }), {
      status: 202, headers: { "Content-Type": "application/json" },
    });
  }

  // Lifecycle mutations (K6).
  if (url.startsWith("/v1/lifecycle/") && init?.method) {
    seedLifecycle();
    const parts = url.split("/"); // ["", "v1", "lifecycle", key, "state"|"waiver"]
    const key = decodeURIComponent(parts[3] ?? "");
    const action = parts[4] ?? "";
    const lc = lifecycleState.get(key);
    if (!lc) return new Response("not found", { status: 404 });
    if (action === "state" && init.method === "POST") {
      const body = JSON.parse(String(init.body));
      lc.state = body.state;
      if (body.assignee) lc.assignee = body.assignee;
      lc.waiver = undefined;
      lc.resolvedAt = body.state === "resolved" ? "2026-06-07T18:00:00Z" : undefined;
      lifecycleState.set(key, lc);
      return json(lc);
    }
    if (action === "waiver" && init.method === "POST") {
      const body = JSON.parse(String(init.body));
      lc.state = "risk-accepted";
      lc.waiver = { justification: body.justification, approvedBy: "local-admin", createdAt: "2026-06-07T08:00:00Z", expiresAt: body.expiresAt };
      lifecycleState.set(key, lc);
      return json(lc);
    }
    if (action === "waiver" && init.method === "DELETE") {
      lc.state = "open";
      lc.waiver = undefined;
      lifecycleState.set(key, lc);
      return json(lc);
    }
    return new Response("bad request", { status: 400 });
  }

  if (url === "/v1/stream") {
    let self: Listener;
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        const enc = new TextEncoder();
        self = (ev) => controller.enqueue(enc.encode(`event: ${ev.type}\ndata: ${JSON.stringify(ev)}\n\n`));
        listeners.add(self);
      },
      cancel() {
        listeners.delete(self);
      },
    });
    return new Response(stream, { status: 200, headers: { "Content-Type": "text/event-stream" } });
  }

  switch (url) {
    case "/v1/clusters": return json(mockClusters);
    case "/v1/scans": return json(mockScans);
    case "/v1/findings": return json(filterSortPage(clusterFindings(cluster), params));
    case "/v1/posture": return json(cluster === "staging-us" ? stagingPosture : prodPosture);
    case "/v1/attack-paths": return json(cluster === "staging-us" ? { paths: [] } : prodPaths);
    case "/v1/history": return json(prodHistory);
    case "/v1/lifecycle": return json(lifecycleView());
    case "/v1/audit": return json({ entries: [
      { at: "2026-06-07T08:00:04Z", subject: "local-admin", tenant: "default", action: "scan.trigger", resource: "prod-eu", result: "allowed" },
    ] });
    case "/v1/report": {
      const format = params.get("format") ?? "sarif";
      const ct = format === "pdf" ? "application/pdf" : format === "csv" ? "text/csv" : "application/sarif+json";
      const name = (cluster ?? "all-clusters") + (format === "csv" ? "-findings.csv" : format === "pdf" ? "-report.pdf" : ".sarif");
      const bodyText = format === "csv" ? "id,severity\nKG-001,critical\n" : format === "pdf" ? "%PDF-1.4 mock" : '{"version":"2.1.0","runs":[]}';
      return new Response(bodyText, { status: 200, headers: { "Content-Type": ct, "Content-Disposition": `attachment; filename="${name}"` } });
    }
    default: return new Response("not found", { status: 404 });
  }
};
