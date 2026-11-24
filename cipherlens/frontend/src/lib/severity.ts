import type { CertificateStatus, SecurityStatus, Severity } from "@/types/severity";

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

export const SEVERITY_BADGE: Record<Severity, string> = {
  critical:
    "border-red-500/40 bg-red-500/10 text-red-400 hover:bg-red-500/20",
  high: "border-orange-500/40 bg-orange-500/10 text-orange-400 hover:bg-orange-500/20",
  medium:
    "border-amber-500/40 bg-amber-500/10 text-amber-400 hover:bg-amber-500/20",
  low: "border-sky-500/40 bg-sky-500/10 text-sky-400 hover:bg-sky-500/20",
  info: "border-slate-500/40 bg-slate-500/10 text-slate-400 hover:bg-slate-500/20",
};

export const SEVERITY_DOT: Record<Severity, string> = {
  critical: "bg-red-500",
  high: "bg-orange-500",
  medium: "bg-amber-500",
  low: "bg-sky-500",
  info: "bg-slate-400",
};

export const SEVERITY_HEX: Record<Severity, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#f59e0b",
  low: "#0ea5e9",
  info: "#94a3b8",
};

export const STATUS_BADGE: Record<SecurityStatus, string> = {
  secure:
    "border-emerald-500/40 bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500/20",
  warning:
    "border-amber-500/40 bg-amber-500/10 text-amber-400 hover:bg-amber-500/20",
  critical:
    "border-red-500/40 bg-red-500/10 text-red-400 hover:bg-red-500/20",
};

export const STATUS_LABEL: Record<SecurityStatus, string> = {
  secure: "Secure",
  warning: "Warning",
  critical: "Critical",
};

export const CERT_STATUS_BADGE: Record<CertificateStatus, string> = {
  valid: "border-emerald-500/40 bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500/20",
  expiring_soon:
    "border-amber-500/40 bg-amber-500/10 text-amber-400 hover:bg-amber-500/20",
  expired: "border-red-500/40 bg-red-500/10 text-red-400 hover:bg-red-500/20",
  unknown: "border-slate-500/40 bg-slate-500/10 text-slate-400 hover:bg-slate-500/20",
};

export const CERT_STATUS_LABEL: Record<CertificateStatus, string> = {
  valid: "Valid",
  expiring_soon: "Expiring Soon",
  expired: "Expired",
  unknown: "Unknown",
};
