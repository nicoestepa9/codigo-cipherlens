import type { Severity } from "./severity";

export interface DashboardSummary {
  totalServices: number;
  totalCertificates: number;
  certificatesExpiringSoon: number;
  criticalVulnerabilities: number;
  highVulnerabilities: number;
  shadowItDetected: number;
  lastScanAt: string | null;
  securityScore: number;
  secure: number;
  warning: number;
  critical: number;
  unreadAlerts: number;
  certificateCriticalDays?: number;
  certificateWarningDays?: number;
}

export interface VulnerabilityStats {
  bySeverity: Record<Severity, number>;
  overTime: { date: string; count: number }[];
  mostCommon: { title: string; count: number; severity: Severity }[];
  byService: { service: string; critical: number; high: number; medium: number }[];
}
