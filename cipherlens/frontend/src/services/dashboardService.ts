import { isMock } from "./config";
import { api } from "./apiClient";
import type { DashboardSummary } from "@/types/dashboard";
import { getDashboardSummary } from "./mock/dashboard";
import { mocked } from "./mock/utils";

export async function getDashboardSummaryService(): Promise<DashboardSummary> {
  if (isMock()) return mocked(getDashboardSummary());
  return api.get<DashboardSummary>("/dashboard");
}
