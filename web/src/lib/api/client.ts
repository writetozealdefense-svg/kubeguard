/**
 * Typed KubeGuard API client. Every call validates the response against the
 * zod contract in `types.ts`. Authorization is a bearer token (set by the auth
 * layer); the API is the single trust boundary — the client enforces nothing,
 * it only carries the token and parses responses.
 */
import { z } from "zod";
import { parseSSE } from "./sse";
import {
  AttackPathListSchema,
  AuditListSchema,
  ClusterListSchema,
  FindingPageSchema,
  HistoryListSchema,
  PostureResponseSchema,
  ScanListSchema,
  ScanSchema,
  type AttackPathList,
  type AuditList,
  type ClusterList,
  type FindingPage,
  type HistoryList,
  type PostureResponse,
  type Scan,
  type ScanList,
  type StreamEvent,
} from "./types";

export interface FindingQuery {
  cluster?: string;
  severity?: string[];
  category?: string;
  framework?: string;
  namespace?: string;
  search?: string;
  sort?: "severity" | "id" | "category";
  order?: "asc" | "desc";
  limit?: number;
  offset?: number;
}

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

/** Pluggable transport — the seam that lets tests inject a mock fetch. */
export type Transport = (path: string, init?: RequestInit) => Promise<Response>;

const defaultTransport: Transport = (path, init) => fetch(path, init);

export class ApiClient {
  constructor(
    private transport: Transport = defaultTransport,
    private tokenProvider: () => string | null = () => null,
  ) {}

  private async get<T>(path: string, schema: z.ZodType<T>): Promise<T> {
    const token = this.tokenProvider();
    const res = await this.transport(path, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    });
    if (!res.ok) {
      const body = await res.text().catch(() => "");
      throw new ApiError(res.status, body || res.statusText);
    }
    return schema.parse(await res.json());
  }

  private qs(params: Record<string, string | number | undefined>): string {
    const sp = new URLSearchParams();
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== "") sp.set(k, String(v));
    }
    const s = sp.toString();
    return s ? `?${s}` : "";
  }

  listClusters(): Promise<ClusterList> {
    return this.get("/v1/clusters", ClusterListSchema);
  }

  listScans(cluster?: string, limit = 50, offset = 0): Promise<ScanList> {
    return this.get(`/v1/scans${this.qs({ cluster, limit, offset })}`, ScanListSchema);
  }

  async triggerScan(clusterId: string): Promise<Scan> {
    // Client-side input validation (zod): a cluster id is a non-empty, bounded,
    // safe identifier. The server re-validates — this is a fast-fail, not security.
    const id = z.string().min(1).max(253).regex(/^[a-zA-Z0-9._-]+$/).parse(clusterId);
    const token = this.tokenProvider();
    const res = await this.transport("/v1/scans", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
      body: JSON.stringify({ clusterId: id }),
    });
    if (!res.ok) {
      const body = await res.text().catch(() => "");
      throw new ApiError(res.status, body || res.statusText);
    }
    return ScanSchema.parse(await res.json());
  }

  listFindings(q: FindingQuery = {}): Promise<FindingPage> {
    const path = `/v1/findings${this.qs({
      cluster: q.cluster,
      severity: q.severity?.join(","),
      category: q.category,
      framework: q.framework,
      namespace: q.namespace,
      search: q.search,
      sort: q.sort,
      order: q.order,
      limit: q.limit,
      offset: q.offset,
    })}`;
    return this.get(path, FindingPageSchema);
  }

  getPosture(cluster?: string): Promise<PostureResponse> {
    return this.get(`/v1/posture${this.qs({ cluster })}`, PostureResponseSchema);
  }

  listAttackPaths(cluster?: string): Promise<AttackPathList> {
    return this.get(`/v1/attack-paths${this.qs({ cluster })}`, AttackPathListSchema);
  }

  getHistory(cluster?: string): Promise<HistoryList> {
    return this.get(`/v1/history${this.qs({ cluster })}`, HistoryListSchema);
  }

  getAudit(): Promise<AuditList> {
    return this.get("/v1/audit", AuditListSchema);
  }

  /** Download an export (sarif | csv | pdf) for a cluster as a blob, carrying
   * the bearer token (a plain <a> link can't set Authorization). */
  async downloadReport(format: "sarif" | "csv" | "pdf", cluster?: string): Promise<{ blob: Blob; filename: string }> {
    const token = this.tokenProvider();
    const res = await this.transport(`/v1/report${this.qs({ cluster, format })}`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    });
    if (!res.ok) {
      const body = await res.text().catch(() => "");
      throw new ApiError(res.status, body || res.statusText);
    }
    const disp = res.headers.get("Content-Disposition") ?? "";
    const match = /filename="?([^"]+)"?/.exec(disp);
    const filename = match?.[1] ?? `report.${format}`;
    return { blob: await res.blob(), filename };
  }

  /** Open the /v1/stream SSE endpoint and invoke onEvent per event. Uses fetch
   * streaming (not EventSource) so the bearer token is carried. Resolves when
   * the stream ends or the signal aborts. */
  async openStream(onEvent: (e: StreamEvent) => void, signal?: AbortSignal): Promise<void> {
    const token = this.tokenProvider();
    const res = await this.transport("/v1/stream", {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
      signal,
    });
    if (!res.ok || !res.body) return;
    const reader = res.body.getReader();
    // Abort cancels the reader so the read loop ends promptly (clean teardown).
    signal?.addEventListener("abort", () => void reader.cancel().catch(() => {}));
    const decoder = new TextDecoder();
    let buffer = "";
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const { events, rest } = parseSSE(buffer);
        buffer = rest;
        for (const ev of events) onEvent(ev);
      }
    } catch {
      // aborted or network closed — caller re-subscribes if desired
    }
  }
}

export const api = new ApiClient();
