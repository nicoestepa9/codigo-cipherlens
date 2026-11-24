import { isMock } from "./config";
import { api } from "./apiClient";
import type { HistoryEntry } from "@/types/history";
import type { ScanResult } from "@/types/scan";
import { getHistoryEntries, getStoredScanResult } from "./mock/scans";
import { mocked } from "./mock/utils";

export async function getHistory(): Promise<HistoryEntry[]> {
  if (isMock()) return mocked(getHistoryEntries());
  const data = await api.get<{ items: HistoryEntry[] }>("/history", { query: { pageSize: 100 } });
  return data.items;
}

export async function getHistoryScan(id: string): Promise<ScanResult | null> {
  if (isMock()) {
    const result = getStoredScanResult(id);
    return mocked(result);
  }
  return api.get<ScanResult>(`/history/${id}/result`);
}
