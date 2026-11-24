import { isMock } from "./config";
import { api } from "./apiClient";
import type { HistoryEntry } from "@/types/history";
import type { RecurringScanDetail, RecurringScanInput } from "@/types/recurringScan";
import {
  createRecurringScanMock,
  deleteRecurringScanMock,
  getRecurringScanRunsMock,
  getRecurringScansMock,
  runNowMock,
  updateRecurringScanMock,
} from "./mock/recurringScans";
import { mocked } from "./mock/utils";
import { cloudAuthorizationFields } from "./cloudAuthorization";

export interface RecurringScanRuns {
  items: HistoryEntry[];
  total: number;
  page: number;
  pageSize: number;
}

export async function getRecurringScans(): Promise<RecurringScanDetail[]> {
  if (isMock()) return mocked(getRecurringScansMock());
  return api.get<RecurringScanDetail[]>("/recurring-scans");
}

export async function getRecurringScanRuns(
  id: number,
  page = 1,
  pageSize = 20,
): Promise<RecurringScanRuns> {
  if (isMock()) return mocked(getRecurringScanRunsMock(id, page, pageSize));
  return api.get<RecurringScanRuns>(`/recurring-scans/${id}/scans`, {
    query: { page, pageSize },
  });
}

export async function getRecurringScan(id: number): Promise<RecurringScanDetail> {
  if (isMock()) {
    const row = getRecurringScansMock().find((r) => r.id === id);
    if (!row) throw new Error("Recurring scan not found");
    return mocked(row);
  }
  return api.get<RecurringScanDetail>(`/recurring-scans/${id}`);
}

export async function createRecurringScan(input: RecurringScanInput): Promise<RecurringScanDetail> {
  if (isMock()) return mocked(createRecurringScanMock(input));
  return api.post<RecurringScanDetail>("/recurring-scans", {
    body: { ...input, ...(input.agentId ? {} : await cloudAuthorizationFields()) },
  });
}

export async function updateRecurringScan(id: number, input: RecurringScanInput): Promise<RecurringScanDetail> {
  if (isMock()) return mocked(updateRecurringScanMock(id, input));
  return api.patch<RecurringScanDetail>(`/recurring-scans/${id}`, {
    body: { ...input, ...(input.agentId ? {} : await cloudAuthorizationFields()) },
  });
}

export async function deleteRecurringScan(id: number): Promise<void> {
  if (isMock()) {
    deleteRecurringScanMock(id);
    return undefined;
  }
  return api.delete<void>(`/recurring-scans/${id}`);
}

export async function runRecurringScanNow(id: number): Promise<RecurringScanDetail> {
  if (isMock()) return mocked(runNowMock(id));
  return api.post<RecurringScanDetail>(`/recurring-scans/${id}/run-now`);
}
