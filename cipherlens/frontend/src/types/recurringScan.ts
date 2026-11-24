export interface RecurringScan {
  id: number;
  host: string;
  port: number;
  alternatePorts: number[];
  profile: string;
  intervalHours: number;
  enabled: boolean;
  isRunning: boolean;
  consecutiveFailures: number;
  lastRunAt: string | null;
  nextRunAt: string;
  serviceId: string | null;
  agentId: string | null;
}

export interface RecurringScanDetail extends RecurringScan {
  recentScans: Array<{
    id: string;
    target: string;
    host: string;
    port: number;
    kind: string;
    date: string;
    score: number | null;
    durationMs: number;
    status: string;
    profile: string;
  }>;
}

export interface RecurringScanInput {
  host: string;
  port?: number;
  alternatePorts?: number[];
  profile?: string;
  intervalHours?: number;
  enabled?: boolean;
  agentId?: string | null;
  authorizationAccepted?: boolean;
  authorizationVersion?: string;
}
