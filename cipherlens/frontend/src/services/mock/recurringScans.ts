import type { RecurringScan, RecurringScanDetail } from "@/types/recurringScan";
import { daysAgo, daysFromNow } from "@/lib/format";
import { randInt, uuid } from "./utils";
import { getHistoryEntries } from "./scans";
import type { HistoryEntry } from "@/types/history";

export interface RecurringScanSeed {
  host: string;
  port: number;
  alternatePorts: number[];
  profile: string;
  intervalHours: number;
  enabled: boolean;
}

const SEED: RecurringScanSeed[] = [
  { host: "example.com", port: 443, alternatePorts: [], profile: "citizen-facing", intervalHours: 24, enabled: true },
  { host: "api.internal.company.com", port: 443, alternatePorts: [8443], profile: "internal", intervalHours: 8, enabled: true },
  { host: "legacy.internal.company.com", port: 443, alternatePorts: [], profile: "internal", intervalHours: 168, enabled: true },
  { host: "cloudflare.com", port: 443, alternatePorts: [], profile: "citizen-facing", intervalHours: 24, enabled: false },
  { host: "payments.internal.company.com", port: 443, alternatePorts: [4443], profile: "critical", intervalHours: 4, enabled: true },
];

let seeded = false;
let store: RecurringScanDetail[] = [];

function nextRunFor(host: string, intervalHours: number, enabled: boolean): string {
  if (!enabled) return "";
  const seed = Math.abs([...host].reduce((a, c) => a + c.charCodeAt(0), 0)) % 4;
  return daysAgo(-(seed + 1)); // próxima corrida en 1..4 días (simplificado)
}

function seedRecurringScans(): RecurringScanDetail[] {
  if (seeded) return store;
  seeded = true;
  const history = getHistoryEntries();

  store = SEED.map((s, index) => {
    const recentCount = s.enabled ? 1 + (index % 3) : 0;
    const recentScans = history.length
      ? Array.from({ length: recentCount }, (_, i) => history[(index * 3 + i) % history.length])
      : [];
    const lastRunAt = s.enabled ? recentScans[0]?.date ?? daysAgo(1) : daysAgo(6);
    const serviceId = s.enabled ? `svc_${index + 1}` : null;

    return {
      id: index + 1,
      host: s.host,
      port: s.port,
      alternatePorts: s.alternatePorts,
      profile: s.profile,
      intervalHours: s.intervalHours,
      enabled: s.enabled,
      isRunning: false,
      consecutiveFailures: s.enabled && index === 2 ? 2 : 0,
      lastRunAt,
      nextRunAt: nextRunFor(s.host, s.intervalHours, s.enabled),
      serviceId,
      agentId: null,
      recentScans,
    };
  });

  return store;
}

export function getRecurringScansMock(): RecurringScanDetail[] {
  return seedRecurringScans();
}

export function getRecurringScanRunsMock(
  id: number,
  page: number,
  pageSize: number,
): { items: HistoryEntry[]; total: number; page: number; pageSize: number } {
  const rows = seedRecurringScans();
  const row = rows.find((r) => r.id === id);
  if (!row) throw new Error("Recurring scan not found");
  const all = row.recentScans as HistoryEntry[];
  const start = (page - 1) * pageSize;
  return {
    items: all.slice(start, start + pageSize),
    total: all.length,
    page,
    pageSize,
  };
}

export function createRecurringScanMock(input: {
  host: string;
  port?: number;
  alternatePorts?: number[];
  profile?: string;
  intervalHours?: number;
  enabled?: boolean;
  agentId?: string | null;
}): RecurringScanDetail {
  const rows = seedRecurringScans();
  const row: RecurringScanDetail = {
    id: rows.length ? Math.max(...rows.map((r) => r.id)) + 1 : 1,
    host: input.host,
    port: input.port ?? 443,
    alternatePorts: input.alternatePorts ?? [],
    profile: input.profile ?? "citizen-facing",
    intervalHours: input.intervalHours ?? 24,
    enabled: input.enabled ?? true,
    isRunning: false,
    consecutiveFailures: 0,
    lastRunAt: null,
    nextRunAt: input.enabled === false ? "" : daysFromNow(1),
    serviceId: null,
    agentId: input.agentId ?? null,
    recentScans: [],
  };
  rows.push(row);
  return row;
}

export function updateRecurringScanMock(
  id: number,
  patch: Partial<Pick<RecurringScan, "host" | "port" | "alternatePorts" | "profile" | "intervalHours" | "enabled" | "agentId">>,
): RecurringScanDetail {
  const rows = seedRecurringScans();
  const row = rows.find((r) => r.id === id);
  if (!row) throw new Error("Recurring scan not found");
  Object.assign(row, patch);
  row.nextRunAt = row.enabled === false ? "" : daysFromNow(1);
  return row;
}

export function deleteRecurringScanMock(id: number): void {
  seedRecurringScans();
  store = store.filter((r) => r.id !== id);
}

export function runNowMock(id: number): RecurringScanDetail {
  const rows = seedRecurringScans();
  const row = rows.find((r) => r.id === id);
  if (!row) throw new Error("Recurring scan not found");
  row.isRunning = true;
  setTimeout(() => {
    row.isRunning = false;
    row.lastRunAt = new Date().toISOString();
    row.nextRunAt = daysFromNow(1);
    row.consecutiveFailures = 0;
    row.recentScans.unshift({
      id: uuid("scan"),
      target: `${row.host}:${row.port}`,
      host: row.host,
      port: row.port,
      kind: "tls_scan",
      date: new Date().toISOString(),
      score: randInt(72, 100),
      durationMs: randInt(900, 4800),
      status: "completed",
      profile: row.profile,
    });
  }, 1200);
  return row;
}
