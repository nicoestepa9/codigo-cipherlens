import type { Finding } from "@/types/finding";
import type { VulnerabilityStats } from "@/types/dashboard";
import type { Severity } from "@/types/severity";
import { getGlobalFindings } from "./findings";
import { daysAgo } from "@/lib/format";
import { mulberry32 } from "./utils";

export interface FindingFilter {
  search?: string;
  severity?: Severity | "all";
  category?: string;
  service?: string;
  page?: number;
  pageSize?: number;
}

const rnd = mulberry32(20260505);

export function getVulnerabilityStats(): VulnerabilityStats {
  const findings = getGlobalFindings();

  const bySeverity: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  for (const f of findings) bySeverity[f.severity]++;

  const titleCounts = new Map<string, { count: number; severity: Severity }>();
  for (const f of findings) {
    const current = titleCounts.get(f.title);
    if (current) current.count++;
    else titleCounts.set(f.title, { count: 1, severity: f.severity });
  }
  const mostCommon = Array.from(titleCounts.entries())
    .map(([title, meta]) => ({ title, count: meta.count, severity: meta.severity }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 6);

  const serviceMap = new Map<string, { critical: number; high: number; medium: number }>();
  for (const f of findings) {
    const service = f.affectedService ?? "Unknown";
    const current = serviceMap.get(service) ?? { critical: 0, high: 0, medium: 0 };
    if (f.severity === "critical") current.critical++;
    else if (f.severity === "high") current.high++;
    else if (f.severity === "medium") current.medium++;
    serviceMap.set(service, current);
  }
  const byService = Array.from(serviceMap.entries())
    .map(([service, counts]) => ({ service, ...counts }))
    .sort((a, b) => b.critical + b.high - (a.critical + a.high))
    .slice(0, 8);

  const overTime = Array.from({ length: 12 }, (_, i) => {
    const weeksAgo = 11 - i;
    const base = bySeverity.critical + bySeverity.high;
    const growth = Math.max(2, Math.round(base * (0.35 + i * 0.06)));
    const noise = Math.floor(rnd() * 5);
    return {
      date: daysAgo(weeksAgo * 7),
      count: growth + noise,
    };
  });

  return { bySeverity, overTime, mostCommon, byService };
}

export function listMockFindings(filter: FindingFilter): { items: Finding[]; total: number } {
  let items = getGlobalFindings();

  if (filter.search) {
    const q = filter.search.toLowerCase();
    items = items.filter(
      (f) =>
        f.title.toLowerCase().includes(q) ||
        f.ruleId.toLowerCase().includes(q) ||
        f.affectedHost.toLowerCase().includes(q) ||
        f.category.toLowerCase().includes(q),
    );
  }
  if (filter.severity && filter.severity !== "all") {
    items = items.filter((f) => f.severity === filter.severity);
  }
  if (filter.category) {
    items = items.filter((f) => f.category === filter.category);
  }
  if (filter.service) {
    items = items.filter((f) => f.affectedService === filter.service);
  }

  const page = filter.page ?? 1;
  const pageSize = filter.pageSize ?? 15;
  const start = (page - 1) * pageSize;
  return { items: items.slice(start, start + pageSize), total: items.length };
}
