import type { Severity } from "./api/types";

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

export const SEVERITY_CLASS: Record<Severity, string> = {
  critical: "bg-sev-critical/15 text-sev-critical border-sev-critical/40",
  high: "bg-sev-high/15 text-sev-high border-sev-high/40",
  medium: "bg-sev-medium/15 text-sev-medium border-sev-medium/40",
  low: "bg-sev-low/15 text-sev-low border-sev-low/40",
  info: "bg-sev-info/15 text-fg-muted border-sev-info/40",
};

export const SEVERITY_HEX: Record<Severity, string> = {
  critical: "#dc2626",
  high: "#ea580c",
  medium: "#d97706",
  low: "#2563eb",
  info: "#6b7280",
};

/** Honest pass-rate string — always "passed of assessed", never a bare %. */
export function passRateLabel(passed: number, assessed: number): string {
  if (assessed === 0) return "no controls assessed";
  const pct = Math.round((passed / assessed) * 100);
  return `${passed} of ${assessed} passed (${pct}%)`;
}

export function breachLabel(breached: number, assessed: number): string {
  if (assessed === 0) return "no controls assessed";
  return `${breached} breached of ${assessed} assessed`;
}

export function pct(n: number): string {
  return `${Math.round(n * 100)}%`;
}
