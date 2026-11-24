export interface OrganizationSettings {
  id: number;
  name: string;
  slug: string;
  status: "active" | "disabled" | string;
  aiMode: "external" | "template";
  maxAgents: number;
  maxCloudScansPerHour: number;
  maxRecurringScans: number;
  slaDaysCritical: number;
  slaDaysHigh: number;
  slaDaysMedium: number;
}

export interface ComplianceWindow {
  id: string;
  name: string;
  framework: string;
  auditDate: string;
  scopeFilter: string[];
}

export type ComplianceWindowInput = Omit<ComplianceWindow, "id">;

export interface AlertThresholdSettings {
  daysBeforeExpiry: number[];
  notifyOnCriticalFinding: boolean;
  notifyOnCompliance: boolean;
  criticalDays: number;
  warningDays: number;
}
