export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type SecurityStatus = "secure" | "warning" | "critical";

export type CertificateStatus = "valid" | "expiring_soon" | "expired" | "unknown";

export type Origin = "discovered" | "manual";

export type Scope = "internal" | "external";

export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}
