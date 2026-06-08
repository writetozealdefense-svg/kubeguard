import { describe, expect, it } from "vitest";
import { parseSSE } from "./sse";

describe("parseSSE", () => {
  it("parses complete frames and returns the incomplete tail", () => {
    const buf =
      `event: scan_started\ndata: ${JSON.stringify({ type: "scan_started", clusterId: "c1" })}\n\n` +
      `event: scan_completed\ndata: ${JSON.stringify({ type: "scan_completed", progress: 1 })}\n\n` +
      `event: posture_updated\ndata: {"type":"posture_updated"`; // incomplete tail

    const { events, rest } = parseSSE(buf);
    expect(events).toHaveLength(2);
    expect(events[0].type).toBe("scan_started");
    expect(events[1].progress).toBe(1);
    expect(rest).toContain("posture_updated");
  });

  it("ignores malformed / non-data frames", () => {
    const { events } = parseSSE(":keepalive\n\nevent: x\ndata: not-json\n\n");
    expect(events).toHaveLength(0);
  });
});
