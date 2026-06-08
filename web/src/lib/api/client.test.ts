import { describe, expect, it } from "vitest";
import { ApiClient } from "./client";
import { mockTransport } from "./mock";

const client = new ApiClient(mockTransport, () => "test-token");

describe("ApiClient (contract validation)", () => {
  it("parses clusters through the zod contract", async () => {
    const { clusters } = await client.listClusters();
    expect(clusters).toHaveLength(2);
    expect(clusters[0].id).toBe("prod-eu");
  });

  it("parses a findings page and preserves pagination fields", async () => {
    const page = await client.listFindings({ limit: 50 });
    expect(page.findings.length).toBeGreaterThan(0);
    expect(page.findings[0].severity).toBe("critical"); // default sort = severity desc
    expect(page.limit).toBe(50);
  });

  it("applies server-side severity filtering (mock mirrors the BFF contract)", async () => {
    const page = await client.listFindings({ severity: ["critical"] });
    expect(page.findings.every((f) => f.severity === "critical")).toBe(true);
  });

  it("parses posture with honest compliance denominators", async () => {
    const { posture, compliance } = await client.getPosture("prod-eu");
    expect(posture.controlsAssessed).toBeGreaterThan(0);
    expect(compliance[0].assessed).toBe(9);
    expect(compliance[0].disclaimer).toMatch(/indicative/i);
  });

  it("carries the bearer token to the transport", async () => {
    let seen: string | null = null;
    const c = new ApiClient(async (_p, init) => {
      seen = (init?.headers as Record<string, string>)?.Authorization ?? null;
      return new Response(JSON.stringify({ clusters: [] }), { status: 200 });
    }, () => "abc");
    await c.listClusters();
    expect(seen).toBe("Bearer abc");
  });

  it("throws ApiError on non-2xx", async () => {
    const c = new ApiClient(async () => new Response("forbidden", { status: 403 }));
    await expect(c.listClusters()).rejects.toMatchObject({ status: 403 });
  });

  it("rejects a response that violates the contract", async () => {
    const c = new ApiClient(async () => new Response(JSON.stringify({ clusters: [{ id: 1 }] }), { status: 200 }));
    await expect(c.listClusters()).rejects.toBeTruthy();
  });
});
