import { Badge } from "@/components/ui/badge";
import { SEVERITY_BADGE, SEVERITY_DOT, SEVERITY_LABEL } from "@/lib/severity";
import type { Severity } from "@/types/severity";
import { cn } from "@/lib/utils";

export function SeverityBadge({
  severity,
  className,
  showDot = true,
}: {
  severity: Severity;
  className?: string;
  showDot?: boolean;
}) {
  return (
    <Badge variant="outline" className={cn("text-xs", SEVERITY_BADGE[severity], className)}>
      {showDot && <span className={cn("mr-1.5 inline-block h-1.5 w-1.5 rounded-full", SEVERITY_DOT[severity])} />}
      {SEVERITY_LABEL[severity]}
    </Badge>
  );
}
