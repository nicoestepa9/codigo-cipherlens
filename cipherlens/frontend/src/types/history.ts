export interface HistoryEntry {
  id: string;
  target: string;
  host: string;
  port: number;
  kind: "tls_scan" | "discovery";
  date: string;
  score: number | null;
  durationMs: number;
  status: "completed" | "failed" | "running";
  profile: string;
  agentId?: string | null;
  siteLabel?: string | null;
}
