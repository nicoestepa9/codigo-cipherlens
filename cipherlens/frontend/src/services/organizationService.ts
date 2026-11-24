import { isMock } from "./config";
import { api } from "./apiClient";
import type {
  AlertThresholdSettings,
  ComplianceWindow,
  ComplianceWindowInput,
  OrganizationSettings,
} from "@/types/organization";
import { mocked } from "./mock/utils";

const mockOrganization: OrganizationSettings = {
  id: 1,
  name: "Company Corp",
  slug: "company-corp",
  status: "active",
  aiMode: "template",
  maxAgents: 0,
  maxCloudScansPerHour: 0,
  maxRecurringScans: 0,
  slaDaysCritical: 7,
  slaDaysHigh: 14,
  slaDaysMedium: 30,
};

let mockWindows: ComplianceWindow[] = [
  {
    id: "cw_demo_1",
    name: "PCI-DSS quarterly audit",
    framework: "PCI-DSS",
    auditDate: new Date(Date.now() + 86_400_000 * 30).toISOString().slice(0, 10),
    scopeFilter: ["payments.example.com"],
  },
];

let mockThresholds: AlertThresholdSettings = {
  daysBeforeExpiry: [30, 15, 7],
  notifyOnCriticalFinding: true,
  notifyOnCompliance: true,
  criticalDays: 7,
  warningDays: 30,
};

export async function getOrganization(): Promise<OrganizationSettings> {
  if (isMock()) return mocked(mockOrganization);
  return api.get<OrganizationSettings>("/settings/organization");
}

export async function setAiMode(
  mode: OrganizationSettings["aiMode"],
): Promise<{ mode: OrganizationSettings["aiMode"] }> {
  if (isMock()) {
    mockOrganization.aiMode = mode;
    return mocked({ mode });
  }
  return api.put<{ mode: OrganizationSettings["aiMode"] }>(
    "/settings/ai-mode",
    { body: { mode } },
  );
}

export async function updateSlaSettings(input: {
  criticalDays: number;
  highDays: number;
  mediumDays: number;
}): Promise<OrganizationSettings> {
  if (isMock()) {
    mockOrganization.slaDaysCritical = input.criticalDays;
    mockOrganization.slaDaysHigh = input.highDays;
    mockOrganization.slaDaysMedium = input.mediumDays;
    return mocked(mockOrganization);
  }
  return api.put<OrganizationSettings>("/settings/sla", { body: input });
}

export async function getThresholds(): Promise<AlertThresholdSettings> {
  if (isMock()) return mocked(mockThresholds);
  return api.get<AlertThresholdSettings>("/settings/thresholds");
}

export async function updateThresholds(
  input: AlertThresholdSettings,
): Promise<AlertThresholdSettings> {
  if (isMock()) {
    mockThresholds = { ...mockThresholds, ...input };
    return mocked(mockThresholds);
  }
  return api.put<AlertThresholdSettings>("/settings/thresholds", {
    body: input,
  });
}

export async function getComplianceWindows(): Promise<ComplianceWindow[]> {
  if (isMock()) return mocked(mockWindows);
  return api.get<ComplianceWindow[]>("/settings/compliance-windows");
}

export async function replaceComplianceWindows(
  windows: ComplianceWindowInput[],
): Promise<ComplianceWindow[]> {
  if (isMock()) {
    mockWindows = windows.map((window, index) => ({
      ...window,
      id: `cw_demo_${index + 1}`,
    }));
    return mocked(mockWindows);
  }
  return api.put<ComplianceWindow[]>("/settings/compliance-windows", {
    body: windows,
  });
}
