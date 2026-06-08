import type { Severity } from "@/lib/api/types";
import { SEVERITY_CLASS, SEVERITY_LABEL } from "@/lib/format";
import { Badge } from "./ui/primitives";

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <Badge className={SEVERITY_CLASS[severity]}>
      <span aria-label={`severity ${SEVERITY_LABEL[severity]}`}>{SEVERITY_LABEL[severity]}</span>
    </Badge>
  );
}
