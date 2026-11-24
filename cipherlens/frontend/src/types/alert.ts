import type { Severity } from "./severity";

export type AlertType = "expiration" | "vulnerability" | "compliance" | "discovery" | "system";

export type AlertStatus = "unread" | "read" | "resolved" | "ignored";

export interface Alert {
  id: string;
  severity: Severity;
  type: AlertType;
  title: string;
  description: string;
  createdAt: string;
  status: AlertStatus;
  relatedTarget?: string;
  relatedCertificateId?: string;
  relatedScanId?: string;
  actionLabel?: string;
  actionHref?: string;
}
