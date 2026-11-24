export type IssueStatus =
  | "open"
  | "assigned"
  | "in_progress"
  | "resolved"
  | "verified"
  | "risk_accepted"
  | "false_positive";

export type IssueSeverity = "low" | "medium" | "high" | "critical";

export interface IssueHistoryEntry {
  id: string;
  ts: string | null;
  actorUserId: string | null;
  actorType: string;
  eventType: string;
  fromValue: string | null;
  toValue: string | null;
  comment: string | null;
  scanId: string | null;
}

export interface Issue {
  id: string;
  serviceId: string | null;
  serviceHost?: string | null;
  servicePort?: number | null;
  agentId?: string | null;
  siteLabel?: string | null;
  sourceDocument: string | null;
  ruleId: string;
  title: string;
  severity: IssueSeverity | string;
  status: IssueStatus | string;
  ownerUserId: string | null;
  ownerTeamId: string | null;
  effectiveOwnerUserId: string | null;
  effectiveOwnerTeamId: string | null;
  ownerName: string | null;
  firstSeenAt: string | null;
  lastSeenAt: string | null;
  dueAt: string | null;
  isOverdue: boolean;
  resolvedAt: string | null;
  resolvedBy: string | null;
  verifiedAt: string | null;
  cleanScansSinceResolved: number;
  riskAcceptedBy: string | null;
  riskAcceptanceReason: string | null;
  riskAcceptedUntil: string | null;
  reopenedCount: number;
  lastCertificateFingerprint: string | null;
  history?: IssueHistoryEntry[] | null;
}

export interface IssueSummary {
  byStatus: Record<string, number>;
  bySeverity: Record<string, number>;
  overdue: number;
  unassigned: number;
  total: number;
}

export const ISSUE_STATUSES: IssueStatus[] = [
  "open",
  "assigned",
  "in_progress",
  "resolved",
  "verified",
  "risk_accepted",
  "false_positive",
];

export const ISSUE_SEVERITIES: IssueSeverity[] = ["critical", "high", "medium", "low"];

export const OPEN_STATUSES: IssueStatus[] = ["open", "assigned", "in_progress"];

const TRANSITIONS: Record<string, IssueStatus[]> = {
  open: ["assigned", "in_progress", "resolved", "verified", "risk_accepted", "false_positive"],
  assigned: ["in_progress", "resolved", "verified", "risk_accepted", "false_positive"],
  in_progress: ["resolved", "verified", "risk_accepted", "false_positive"],
  resolved: ["verified", "risk_accepted", "false_positive"],
  verified: ["assigned", "in_progress", "resolved"],
  risk_accepted: ["assigned", "in_progress", "resolved", "verified", "false_positive"],
  false_positive: [],
};

export function allowedTransitions(status: string): IssueStatus[] {
  return TRANSITIONS[status] ?? [];
}

export const UI_TRANSITIONS: Record<string, IssueStatus[]> = {
  open: ["assigned", "in_progress", "resolved", "risk_accepted", "false_positive"],
  assigned: ["in_progress", "resolved", "risk_accepted", "false_positive"],
  in_progress: ["resolved", "risk_accepted", "false_positive"],
  resolved: ["verified", "risk_accepted", "false_positive"],
  verified: [],
  risk_accepted: ["in_progress", "resolved", "false_positive"],
  false_positive: [],
};

export const REOPENABLE_STATUSES = ["resolved", "verified"];

export function uiTransitions(status: string): IssueStatus[] {
  return UI_TRANSITIONS[status] ?? [];
}

export function actionOptions(status: string): string[] {
  const opts: string[] = [status, ...uiTransitions(status)];
  if (REOPENABLE_STATUSES.includes(status)) opts.push("reopened");
  return opts;
}

export function isTerminal(status: string): boolean {
  return status === "false_positive" || status === "verified";
}

export function statusLabel(status: string): string {
  const labels: Record<string, string> = {
    open: "Abierto",
    assigned: "Asignado",
    in_progress: "En progreso",
    resolved: "Resuelto",
    verified: "Verificado",
    risk_accepted: "Riesgo aceptado",
    false_positive: "Falso positivo",
    reopened: "Reabrir",
  };
  return labels[status] ?? status;
}

export function eventTypeLabel(eventType: string): string {
  const labels: Record<string, string> = {
    created: "Creado",
    status_changed: "Cambio de estado",
    owner_changed: "Cambio de asignación",
    comment: "Comentario",
    risk_accept: "Aceptación de riesgo",
    false_positive: "Marcado como falso positivo",
    auto_resolved: "Auto-resuelto",
    auto_verified: "Auto-verificado",
    reopened: "Reabierto",
    severity_changed: "Cambio de severidad",
    sla_changed: "Cambio de SLA",
    owner_removed: "Asignación removida",
    risk_acceptance_expired: "Aceptación de riesgo expirada",
  };
  return labels[eventType] ?? eventType;
}
