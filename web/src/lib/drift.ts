import type { HistorySnapshot, Severity } from "./api/types";
import { SEVERITY_ORDER } from "./api/types";

export interface Drift {
  from: string; // scanId
  to: string;
  totalFindingsDelta: number;
  breachedDelta: number;
  passRateDelta: number;
  bySeverityDelta: Record<Severity, number>;
  /** Controls that newly breached between the two scans (positive breachedDelta). */
  newlyBreached: number;
  /** Controls that were fixed between the two scans (negative breachedDelta). */
  fixed: number;
  improved: boolean;
}

/** computeDrift diffs an earlier snapshot (a) against a later one (b). A drop in
 * breached controls / rise in pass rate is an improvement. */
export function computeDrift(a: HistorySnapshot, b: HistorySnapshot): Drift {
  const bySeverityDelta = {} as Record<Severity, number>;
  for (const sev of SEVERITY_ORDER) {
    bySeverityDelta[sev] = (b.bySeverity[sev] ?? 0) - (a.bySeverity[sev] ?? 0);
  }
  const breachedDelta = b.controlsBreached - a.controlsBreached;
  return {
    from: a.scanId,
    to: b.scanId,
    totalFindingsDelta: b.totalFindings - a.totalFindings,
    breachedDelta,
    passRateDelta: b.overallPassRate - a.overallPassRate,
    bySeverityDelta,
    newlyBreached: Math.max(0, breachedDelta),
    fixed: Math.max(0, -breachedDelta),
    improved: breachedDelta < 0 || b.overallPassRate > a.overallPassRate,
  };
}
