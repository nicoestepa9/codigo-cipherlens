import { Badge } from "@/components/ui/badge";
import { SEVERITY_BADGE } from "@/lib/severity";
import { statusLabel, type IssueStatus } from "@/types/issue";
import type { Severity } from "@/types/severity";

const ISSUE_STATUS_COLORS: Record<IssueStatus, string> = {
  open: "border-rose-500/40 bg-rose-500/15 text-rose-300",
  assigned: "border-blue-500/40 bg-blue-500/15 text-blue-300",
  in_progress: "border-amber-500/40 bg-amber-500/15 text-amber-300",
  resolved: "border-teal-500/40 bg-teal-500/15 text-teal-300",
  verified: "border-emerald-500/40 bg-emerald-500/15 text-emerald-300",
  risk_accepted: "border-violet-500/40 bg-violet-500/15 text-violet-300",
  false_positive: "border-slate-500/40 bg-slate-500/15 text-slate-300",
};

export function IssueSeverityBadge({ severity }: { severity: string }) {
  const color = Object.hasOwn(SEVERITY_BADGE, severity)
    ? SEVERITY_BADGE[severity as Severity]
    : undefined;
  return <Badge variant="outline" className={color}>{severity}</Badge>;
}

export function IssueStatusBadge({ status }: { status: string }) {
  const color = Object.hasOwn(ISSUE_STATUS_COLORS, status)
    ? ISSUE_STATUS_COLORS[status as IssueStatus]
    : undefined;
  return <Badge variant="outline" className={color}>{statusLabel(status)}</Badge>;
}
