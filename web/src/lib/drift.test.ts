import { describe, expect, it } from "vitest";
import { computeDrift } from "./drift";
import type { HistorySnapshot } from "./api/types";

const a: HistorySnapshot = { scanId: "s1", at: "2026-06-05T08:00:00Z", totalFindings: 24, controlsAssessed: 32, controlsBreached: 29, overallPassRate: 0.09, bySeverity: { critical: 5, high: 8, medium: 6, low: 5 } };
const b: HistorySnapshot = { scanId: "s2", at: "2026-06-07T08:00:00Z", totalFindings: 19, controlsAssessed: 32, controlsBreached: 26, overallPassRate: 0.19, bySeverity: { critical: 4, high: 7, medium: 4, low: 4 } };

describe("computeDrift", () => {
  it("computes deltas and marks an improvement (fewer breaches, higher pass)", () => {
    const d = computeDrift(a, b);
    expect(d.totalFindingsDelta).toBe(-5);
    expect(d.breachedDelta).toBe(-3);
    expect(d.fixed).toBe(3);
    expect(d.newlyBreached).toBe(0);
    expect(d.bySeverityDelta.critical).toBe(-1);
    expect(d.improved).toBe(true);
    expect(d.passRateDelta).toBeCloseTo(0.1, 5);
  });

  it("marks a regression when breaches grow", () => {
    const d = computeDrift(b, a); // reversed: posture got worse
    expect(d.breachedDelta).toBe(3);
    expect(d.newlyBreached).toBe(3);
    expect(d.fixed).toBe(0);
    expect(d.improved).toBe(false);
  });
});
