import { isMock } from "./config";
import { api } from "./apiClient";
import { parseTarget } from "@/lib/target";
import type { ScanOptions, ScanResult } from "@/types/scan";
import type { HistoryEntry } from "@/types/history";
import { executeScan, getStoredScanResult } from "./mock/scans";
import { mocked } from "./mock/utils";
import {
  cloudAuthorizationFields,
  type CloudAuthorizationFields,
} from "./cloudAuthorization";
import { waitForAgentTask } from "./agentTasksService";
import type { AgentTaskAccepted, ExecutorSelection } from "@/types/agent";

export async function runScan(
  targetInput: string,
  options: ScanOptions = {},
  executor?: ExecutorSelection,
  authorization?: CloudAuthorizationFields,
): Promise<ScanResult> {
  const { host, port } = parseTarget(targetInput);
  if (isMock()) {
    const result = await executeScan(host, port, options);
    await mocked(null, 150, 350);
    return result;
  }

  if (executor?.type === "agent") {
    if (!executor.agentId) throw new Error("Select an agent to run this scan.");
    const accepted = await api.post<AgentTaskAccepted>("/scans", {
      body: {
        target: targetInput,
        options,
        executor: { type: "agent", agentId: executor.agentId },
      },
    });
    const task = await waitForAgentTask(accepted.taskId);
    if (task.status !== "done" || !task.resultScanId) {
      throw new Error(task.error ?? `Agent scan ${task.status}.`);
    }
    return api.get<ScanResult>(`/scans/${task.resultScanId}`);
  }

  return api.post<ScanResult>("/scans", {
    body: {
      target: targetInput,
      options,
      ...(authorization ?? (await cloudAuthorizationFields({ alwaysPrompt: true }))),
    },
  });
}

export async function getScanResult(id: string): Promise<ScanResult | null> {
  if (isMock()) {
    return mocked(getStoredScanResult(id));
  }
  return api.get<ScanResult>(`/scans/${id}`);
}

export async function listScans(): Promise<HistoryEntry[]> {
  if (isMock()) {
    return mocked<HistoryEntry[]>([]);
  }
  const data = await api.get<{ items: HistoryEntry[] }>("/history", { query: { pageSize: 100 } });
  return data.items;
}
