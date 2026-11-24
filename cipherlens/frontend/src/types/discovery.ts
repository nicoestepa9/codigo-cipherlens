import type { Scope } from "./severity";
import type { ExecutorSelection } from "./agent";

export interface DiscoveryResult {
  id: string;
  ipAddress: string;
  hostname: string | null;
  port: number;
  service: string;
  serviceName: string;
  hasTls: boolean;
  tlsVersion: string | null;
  osFingerprint: string | null;
  inventoried: boolean;
  shadowIt: boolean;
  scope: Scope;
  firstSeen: string;
  lastSeen: string;
  agentId?: string | null;
  siteLabel?: string | null;
}

export interface DiscoveryRequest {
  ipRange: string;
  ports: number[];
  domains: string[];
  scanInternal: boolean;
  executor?: ExecutorSelection;
}

export interface DiscoveryJob {
  id: string;
  status: "queued" | "running" | "completed" | "failed" | "cancelled";
  progress: number;
  totalFound: number;
  shadowItCount: number;
  startedAt: string | null;
  completedAt: string | null;
  error: string | null;
}

export interface DiscoverySummary {
  total: number;
  inventoried: number;
  shadowIt: number;
  withTls: number;
  internal: number;
  external: number;
}

export interface DiscoveryProgressStep {
  label: string;
  detail: string;
  state: "pending" | "running" | "done" | "error";
}
