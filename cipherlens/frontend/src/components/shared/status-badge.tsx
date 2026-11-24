import { Badge } from "@/components/ui/badge";
import { STATUS_BADGE, STATUS_LABEL } from "@/lib/severity";
import type { SecurityStatus } from "@/types/severity";
import { cn } from "@/lib/utils";

export function StatusBadge({
  status,
  className,
  showIcon = true,
}: {
  status: SecurityStatus;
  className?: string;
  showIcon?: boolean;
}) {
  const dot =
    status === "secure" ? "bg-emerald-500" : status === "warning" ? "bg-amber-500" : "bg-red-500";
  return (
    <Badge variant="outline" className={cn("font-mono text-xs", STATUS_BADGE[status], className)}>
      {showIcon && <span className={cn("mr-1.5 inline-block h-1.5 w-1.5 rounded-full", dot)} />}
      {STATUS_LABEL[status]}
    </Badge>
  );
}
