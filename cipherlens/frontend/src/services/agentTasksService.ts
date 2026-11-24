import { isMock } from "./config";
import { api } from "./apiClient";
import type { AgentTask, AgentTaskStatus } from "@/types/agent";
import { mocked } from "./mock/utils";

const POLL_INTERVAL_MS = 1500;
const POLL_TIMEOUT_MS = 10 * 60_000;

export const TERMINAL_AGENT_TASK_STATUSES: AgentTaskStatus[] = [
  "done",
  "failed",
  "rejected",
  "expired",
  "cancelled",
];

export interface AgentTaskListOptions {
  status?: AgentTaskStatus;
  agentId?: string;
  limit?: number;
}

export async function listAgentTasks(
  options: AgentTaskListOptions = {},
): Promise<AgentTask[]> {
  if (isMock()) return mocked([]);
  return api.get<AgentTask[]>("/agent-tasks", {
    query: {
      status: options.status,
      agentId: options.agentId,
      limit: options.limit,
    },
  });
}

export async function getAgentTask(id: string): Promise<AgentTask> {
  if (isMock()) throw new Error("Agent tasks are unavailable in mock mode");
  return api.get<AgentTask>(`/agent-tasks/${id}`);
}

export async function cancelAgentTask(id: string): Promise<AgentTask> {
  if (isMock()) throw new Error("Agent tasks are unavailable in mock mode");
  return api.delete<AgentTask>(`/agent-tasks/${id}`);
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export async function waitForAgentTask(
  taskId: string,
  onUpdate?: (task: AgentTask) => void,
): Promise<AgentTask> {
  const deadline = Date.now() + POLL_TIMEOUT_MS;
  for (;;) {
    const task = await getAgentTask(taskId);
    onUpdate?.(task);
    if (TERMINAL_AGENT_TASK_STATUSES.includes(task.status)) return task;
    if (Date.now() > deadline) throw new Error("Agent task timed out");
    await sleep(POLL_INTERVAL_MS);
  }
}
