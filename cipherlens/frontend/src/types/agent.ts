export type AgentStatus = "active" | "revoked";

export interface AgentCapabilities {
  allowRemoteTasks?: boolean;
  networkCount?: number;
  portCount?: number;
  allowedNetworks?: string[];
  allowedPorts?: number[];
}

export interface Agent {
  id: string;
  name: string;
  siteLabel: string;
  status: AgentStatus | string;
  version: string | null;
  lastSeenAt: string | null;
  lastIp: string | null;
  createdAt: string;
  revokedAt: string | null;
  schemaVersion: number | null;
  rulesVersion: string | null;
  serviceCount: number;
  keyPrefix: string | null;
  isOnline: boolean;
  reportedCapabilities: AgentCapabilities | null;
}

export interface AgentCreated extends Agent {
  apiKey: string;
}

export interface AgentRecentScan {
  id: string;
  target: string;
  status: string;
  score: number | null;
  origin: string | null;
  startedAt: string | null;
  uploadLevel: string | null;
}

export interface AgentDetail {
  agent: Agent;
  recentScans: AgentRecentScan[];
}

export type AgentTaskStatus =
  | "queued"
  | "claimed"
  | "running"
  | "done"
  | "failed"
  | "rejected"
  | "expired"
  | "cancelled";

export interface AgentTask {
  id: string;
  agentId: string;
  type: "scan" | "discovery" | string;
  status: AgentTaskStatus;
  payload: Record<string, unknown>;
  createdAt: string;
  expiresAt: string;
  claimedAt: string | null;
  leaseExpiresAt: string | null;
  finishedAt: string | null;
  attempts: number;
  error: string | null;
  resultScanId: string | null;
  resultJobId: string | null;
  recurringScanId: number | null;
}

export interface AgentTaskAccepted {
  taskId: string;
  status: string;
}

export interface ExecutorSelection {
  type: "cloud" | "agent";
  agentId?: string;
}
