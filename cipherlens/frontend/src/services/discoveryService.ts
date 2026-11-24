import { isMock } from "./config";
import { api } from "./apiClient";
import type { DiscoveryJob, DiscoveryRequest, DiscoveryResult, DiscoverySummary } from "@/types/discovery";
import type { AgentTaskAccepted } from "@/types/agent";
import { getDiscoveryResults, getDiscoverySummary, runDiscoveryMock } from "./mock/discovery";
import { mocked } from "./mock/utils";
import {
  cloudAuthorizationFields,
  type CloudAuthorizationFields,
} from "./cloudAuthorization";
import { waitForAgentTask } from "./agentTasksService";

const POLL_INTERVAL_MS = 1500;
const POLL_TIMEOUT_MS = 10 * 60_000;

export interface DiscoveryProgress {
  status: DiscoveryJob["status"];
  progress: number;
  totalFound: number;
  done: boolean;
}

export interface RunDiscoveryOptions {
  onProgress?: (progress: DiscoveryProgress) => void;
  /** Se invoca apenas el backend crea el job, para poder cancelarlo. */
  onJobCreated?: (jobId: string) => void;
  signal?: AbortSignal;
}

export class DiscoveryCancelledError extends Error {
  constructor() {
    super("Discovery cancelled");
    this.name = "DiscoveryCancelledError";
  }
}

/**
 * Espera POLL_INTERVAL_MS, pero se despierta antes si la pestana vuelve a primer
 * plano. Chrome congela los timers de una pestana en background (y los limita a
 * ~1 por minuto a los 5 min), asi que un scan rapido puede parecer congelado
 * aunque el backend haya terminado hace rato. Con este despertar temprano el
 * siguiente poll ve el job ya completado en vez de seguir esperando.
 */
function waitForNextPoll(signal?: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    let settled = false;

    const cleanup = () => {
      clearTimeout(timer);
      document.removeEventListener("visibilitychange", onWake);
      window.removeEventListener("focus", onWake);
      signal?.removeEventListener("abort", finish);
    };

    const finish = () => {
      if (settled) return;
      settled = true;
      cleanup();
      resolve();
    };

    const onWake = () => {
      if (document.visibilityState === "visible") finish();
    };

    const timer = setTimeout(finish, POLL_INTERVAL_MS);
    document.addEventListener("visibilitychange", onWake);
    window.addEventListener("focus", onWake);
    signal?.addEventListener("abort", finish);
  });
}

async function waitForCompletion(
  jobId: string,
  onProgress?: (progress: DiscoveryProgress) => void,
  signal?: AbortSignal,
): Promise<DiscoveryJob> {
  const deadline = Date.now() + POLL_TIMEOUT_MS;
  for (;;) {
    if (signal?.aborted) throw new DOMException("Aborted", "AbortError");
    const job = await api.get<DiscoveryJob>(`/discovery/${jobId}`, { signal });
    const done =
      job.status === "completed" ||
      job.status === "failed" ||
      job.status === "cancelled";
    onProgress?.({ status: job.status, progress: job.progress, totalFound: job.totalFound, done });
    if (done) return job;
    if (Date.now() > deadline) throw new Error("Discovery timed out");
    await waitForNextPoll(signal);
  }
}

export async function runDiscovery(
  request: DiscoveryRequest,
  options: RunDiscoveryOptions = {},
  authorization?: CloudAuthorizationFields,
): Promise<DiscoveryResult[]> {
  if (isMock()) {
    const results = runDiscoveryMock();
    return mocked(results, 1200, 2000);
  }

  if (request.executor?.type === "agent") {
    if (!request.executor.agentId) throw new Error("Select an agent to run this discovery.");
    const accepted = await api.post<AgentTaskAccepted>("/discovery", {
      body: { ...request, executor: { type: "agent", agentId: request.executor.agentId } },
      signal: options.signal,
    });
    options.onJobCreated?.(accepted.taskId);
    const task = await waitForAgentTask(accepted.taskId);
    const progressByStatus: Record<string, number> = {
      queued: 5,
      claimed: 15,
      running: 60,
      done: 100,
    };
    options.onProgress?.({
      status: task.status === "done" ? "completed" : task.status === "running" || task.status === "claimed" ? "running" : "queued",
      progress: progressByStatus[task.status] ?? 0,
      totalFound: 0,
      done: task.status === "done",
    });
    if (task.status === "cancelled") throw new DiscoveryCancelledError();
    if (task.status !== "done") throw new Error(task.error ?? `Agent discovery ${task.status}.`);
    if (!task.resultJobId) throw new Error("Agent discovery finished without a result.");
    return api.get<DiscoveryResult[]>(`/discovery/${task.resultJobId}/results`, {
      signal: options.signal,
    });
  }

  const job = await api.post<DiscoveryJob>("/discovery", {
    body: {
      ...request,
      executor: { type: "cloud" },
      ...(authorization ?? (await cloudAuthorizationFields({ alwaysPrompt: true }))),
    },
    signal: options.signal,
  });
  options.onJobCreated?.(job.id);
  const finished = await waitForCompletion(job.id, options.onProgress, options.signal);
  if (finished.status === "cancelled") {
    throw new DiscoveryCancelledError();
  }
  if (finished.status === "failed") {
    throw new Error(finished.error ?? "Discovery failed");
  }
  return api.get<DiscoveryResult[]>(`/discovery/${job.id}/results`, { signal: options.signal });
}

/**
 * Le pide al backend que frene el job. Sin esto, abortar el polling solo deja de
 * mirar: el worker seguiría escaneando los hosts restantes en background.
 */
export async function cancelDiscovery(jobId: string): Promise<void> {
  try {
    await api.delete<DiscoveryJob>(`/discovery/${jobId}`);
    return;
  } catch {
    // Job may be an agent task id; fall through to the agent task endpoint.
  }
  try {
    await api.delete(`/agent-tasks/${jobId}`);
  } catch {
    // If it already finished or the backend does not know it, local abort is enough.
  }
}

export async function getDiscoveryResultsService(): Promise<DiscoveryResult[]> {
  if (isMock()) return mocked(getDiscoveryResults());
  return api.get<DiscoveryResult[]>("/discovery/results");
}

export async function getDiscoverySummaryService(): Promise<DiscoverySummary> {
  if (isMock()) return mocked(getDiscoverySummary());
  return api.get<DiscoverySummary>("/discovery/summary");
}
