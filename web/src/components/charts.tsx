/** Recharts trend visuals over history snapshots. */
import {
  Area,
  AreaChart,
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import type { HistorySnapshot } from "@/lib/api/types";
import { SEVERITY_HEX } from "@/lib/format";
import { SEVERITY_ORDER } from "@/lib/api/types";

function day(at: string): string {
  return at.slice(0, 10);
}

/** Stacked findings-by-severity over scans. */
export function SeverityTrend({ snapshots }: { snapshots: HistorySnapshot[] }) {
  const data = snapshots.map((s) => ({ day: day(s.at), ...s.bySeverity }));
  return (
    <div className="h-56 w-full" role="img" aria-label="Findings by severity over time">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={data}>
          <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
          <XAxis dataKey="day" stroke="#9ca3af" fontSize={11} />
          <YAxis stroke="#9ca3af" fontSize={11} allowDecimals={false} />
          <Tooltip contentStyle={{ background: "#11161f", border: "1px solid #1f2937" }} />
          {SEVERITY_ORDER.map((sev) => (
            <Area key={sev} type="monotone" dataKey={sev} stackId="1" stroke={SEVERITY_HEX[sev]} fill={SEVERITY_HEX[sev]} fillOpacity={0.5} />
          ))}
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}

/** Overall control-pass % over scans. */
export function PassRateTrend({ snapshots }: { snapshots: HistorySnapshot[] }) {
  const data = snapshots.map((s) => ({ day: day(s.at), pass: Math.round(s.overallPassRate * 100) }));
  return (
    <div className="h-56 w-full" role="img" aria-label="Control pass rate over time">
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={data}>
          <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
          <XAxis dataKey="day" stroke="#9ca3af" fontSize={11} />
          <YAxis stroke="#9ca3af" fontSize={11} domain={[0, 100]} unit="%" />
          <Tooltip contentStyle={{ background: "#11161f", border: "1px solid #1f2937" }} />
          <Line type="monotone" dataKey="pass" stroke="#3b82f6" strokeWidth={2} dot />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}
