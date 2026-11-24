import { isMock } from "./config";
import { api } from "./apiClient";
import type { Finding } from "@/types/finding";
import type { VulnerabilityStats } from "@/types/dashboard";
import { getVulnerabilityStats, listMockFindings, type FindingFilter } from "./mock/vulnerabilities";
import { mocked } from "./mock/utils";

export async function getVulnerabilityStatsService(): Promise<VulnerabilityStats> {
  if (isMock()) return mocked(getVulnerabilityStats());
  return api.get<VulnerabilityStats>("/vulnerabilities/stats");
}

export async function getFindings(filter: FindingFilter = {}): Promise<{ items: Finding[]; total: number }> {
  if (isMock()) return mocked(listMockFindings(filter));
  return api.get<{ items: Finding[]; total: number }>("/vulnerabilities", { query: { ...filter } });
}
