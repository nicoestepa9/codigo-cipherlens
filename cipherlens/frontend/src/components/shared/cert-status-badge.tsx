import { Badge } from "@/components/ui/badge";
import { CERT_STATUS_BADGE, CERT_STATUS_LABEL } from "@/lib/severity";
import type { CertificateStatus } from "@/types/severity";
import { cn } from "@/lib/utils";

export function CertStatusBadge({
  status,
  className,
}: {
  status: CertificateStatus;
  className?: string;
}) {
  return (
    <Badge variant="outline" className={cn("font-mono text-xs", CERT_STATUS_BADGE[status], className)}>
      {CERT_STATUS_LABEL[status]}
    </Badge>
  );
}
