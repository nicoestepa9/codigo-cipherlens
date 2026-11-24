"use client";

import { Suspense, useMemo, useState } from "react";
import { useSearchParams } from "next/navigation";
import { Bug, ChevronLeft, ChevronRight, Search } from "lucide-react";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Legend,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { SeverityBadge } from "@/components/shared/severity-badge";
import { StatCard } from "@/components/shared/stat-card";
import { TableSkeleton } from "@/components/shared/skeletons";
import { EmptyState } from "@/components/shared/empty-state";
import { formatDate } from "@/lib/format";
import { useAsync } from "@/hooks/use-async";
import { useDebouncedValue } from "@/hooks/use-debounce";
import { getFindings, getVulnerabilityStatsService } from "@/services/vulnerabilitiesService";
import type { Finding } from "@/types/finding";
import type { Severity } from "@/types/severity";

const PAGE_SIZE = 15;

export default function VulnerabilitiesPage() {
  return (
    <Suspense fallback={<TableSkeleton columns={6} rows={10} />}>
      <VulnerabilitiesContent />
    </Suspense>
  );
}

function VulnerabilitiesContent() {
  const searchParams = useSearchParams();
  const initialHost = searchParams.get("host") ?? "";

  const [search, setSearch] = useState(initialHost);
  const debouncedSearch = useDebouncedValue(search);
  const [severity, setSeverity] = useState<Severity | "all">("all");
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState<Finding | null>(null);

  const { data: stats, loading: statsLoading, error: statsError } = useAsync(
    getVulnerabilityStatsService,
    [],
  );

  const { data: pageData, loading: listLoading, error: listError } = useAsync(
    () => getFindings({ search: debouncedSearch || undefined, severity, page, pageSize: PAGE_SIZE }),
    [debouncedSearch, severity, page],
  );

  const totalPages = useMemo(
    () => (pageData ? Math.max(1, Math.ceil(pageData.total / PAGE_SIZE)) : 1),
    [pageData],
  );

  const byServiceData = useMemo(
    () => (stats?.byService ?? []).map((s) => ({ name: s.service, Critical: s.critical, High: s.high, Medium: s.medium })),
    [stats],
  );

  const chartTooltipStyle = {
    background: "var(--popover)",
    border: "1px solid var(--border)",
    borderRadius: 8,
    fontSize: 12,
  };

  return (
    <div>
      <div className="mb-6 flex flex-col gap-2">
        <h1 className="text-2xl font-semibold tracking-tight text-foreground">Vulnerabilities</h1>
        <p className="text-sm text-muted-foreground">
          Security findings aggregated across the platform, mapped to NIST SP 800-52 controls.
        </p>
      </div>

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
        <StatCard label="Critical" value={stats?.bySeverity.critical ?? 0} icon={<Bug className="h-4 w-4" />} accent="red" />
        <StatCard label="High" value={stats?.bySeverity.high ?? 0} accent="amber" />
        <StatCard label="Medium" value={stats?.bySeverity.medium ?? 0} accent="sky" />
        <StatCard label="Low" value={stats?.bySeverity.low ?? 0} accent="emerald" />
        <StatCard
          label="Total"
          value={
            stats
              ? stats.bySeverity.critical + stats.bySeverity.high + stats.bySeverity.medium + stats.bySeverity.low + stats.bySeverity.info
              : 0
          }
        />
      </div>

      <div className="mt-4 grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Findings Trend</CardTitle>
            <CardDescription>Open findings over the last 12 weeks.</CardDescription>
          </CardHeader>
          <CardContent className="h-60">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={stats?.overTime ?? []} margin={{ top: 8, right: 8, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="trendFill" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#f43f5e" stopOpacity={0.4} />
                    <stop offset="100%" stopColor="#f43f5e" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" className="stroke-border" vertical={false} />
                <XAxis
                  dataKey="date"
                  tick={{ fontSize: 11 }}
                  tickLine={false}
                  axisLine={false}
                  tickFormatter={(v) => formatDate(v)}
                  interval={1}
                />
                <YAxis tick={{ fontSize: 11 }} tickLine={false} axisLine={false} allowDecimals={false} />
                <Tooltip contentStyle={chartTooltipStyle} labelFormatter={(v) => formatDate(v as string)} />
                <Area type="monotone" dataKey="count" name="Findings" stroke="#f43f5e" strokeWidth={2} fill="url(#trendFill)" />
              </AreaChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Findings by Service</CardTitle>
            <CardDescription>Critical, high, and medium findings per affected service.</CardDescription>
          </CardHeader>
          <CardContent className="h-60">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={byServiceData} margin={{ top: 8, right: 8, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" className="stroke-border" vertical={false} />
                <XAxis
                  dataKey="name"
                  tick={{ fontSize: 10 }}
                  tickLine={false}
                  axisLine={false}
                  interval={0}
                  angle={-18}
                  textAnchor="end"
                  height={48}
                />
                <YAxis tick={{ fontSize: 11 }} tickLine={false} axisLine={false} allowDecimals={false} />
                <Tooltip contentStyle={chartTooltipStyle} />
                <Legend wrapperStyle={{ fontSize: 11 }} />
                <Bar dataKey="Critical" stackId="a" fill="#f43f5e" radius={[0, 0, 0, 0]} />
                <Bar dataKey="High" stackId="a" fill="#f97316" />
                <Bar dataKey="Medium" stackId="a" fill="#f59e0b" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
      </div>

      <div className="mt-4">
        <div className="mb-3 flex flex-wrap items-center gap-2">
          <div className="relative">
            <Search className="absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              value={search}
              onChange={(e) => { setSearch(e.target.value); setPage(1); }}
              placeholder="Search title, rule, host..."
              className="h-8 w-64 pl-8"
            />
          </div>
          <Select value={severity} onValueChange={(v) => { setSeverity(v as Severity | "all"); setPage(1); }}>
            <SelectTrigger className="h-8 w-36">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">Severity: All</SelectItem>
              <SelectItem value="critical">Critical</SelectItem>
              <SelectItem value="high">High</SelectItem>
              <SelectItem value="medium">Medium</SelectItem>
              <SelectItem value="low">Low</SelectItem>
              <SelectItem value="info">Info</SelectItem>
            </SelectContent>
          </Select>
        </div>

        {listLoading || statsLoading ? (
          <TableSkeleton columns={6} rows={10} />
        ) : listError || statsError ? (
          <EmptyState title="Could not load vulnerabilities." />
        ) : pageData && pageData.items.length === 0 ? (
          <EmptyState icon={<Bug className="h-6 w-6" />} title="No findings match the current filters." />
        ) : (
          <>
            <div className="overflow-x-auto rounded-lg border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Finding</TableHead>
                    <TableHead>Rule</TableHead>
                    <TableHead>Severity</TableHead>
                    <TableHead>Category</TableHead>
                    <TableHead>Affected Host</TableHead>
                    <TableHead>Service</TableHead>
                    <TableHead>Detected</TableHead>
                    <TableHead className="w-8" />
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {(pageData?.items ?? []).map((f) => (
                    <TableRow key={f.id} className="cursor-pointer hover:bg-accent/40" onClick={() => setSelected(f)}>
                      <TableCell className="max-w-[260px]">
                        <p className="truncate text-sm font-medium text-foreground">{f.title}</p>
                      </TableCell>
                      <TableCell className="font-mono text-xs text-muted-foreground">{f.ruleId}</TableCell>
                      <TableCell><SeverityBadge severity={f.severity} /></TableCell>
                      <TableCell className="text-xs text-muted-foreground">{f.category}</TableCell>
                      <TableCell className="font-mono text-xs text-muted-foreground">{f.affectedHost}</TableCell>
                      <TableCell className="max-w-[160px] truncate text-xs text-muted-foreground">
                        {f.affectedService ?? "—"}
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">{formatDate(f.detectionDate)}</TableCell>
                      <TableCell>
                        <Badge
                          variant="outline"
                          className="border-muted text-muted-foreground"
                        >
                          Details
                        </Badge>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>

            <div className="mt-3 flex items-center justify-between">
              <p className="text-xs text-muted-foreground">
                {pageData ? `Showing ${pageData.items.length} of ${pageData.total} findings` : " "}
              </p>
              <div className="flex items-center gap-2">
                <Button variant="outline" size="sm" disabled={page <= 1} onClick={() => setPage((p) => p - 1)} className="gap-1">
                  <ChevronLeft className="h-4 w-4" /> Prev
                </Button>
                <span className="text-xs text-muted-foreground">Page {page} / {totalPages}</span>
                <Button variant="outline" size="sm" disabled={page >= totalPages} onClick={() => setPage((p) => p + 1)} className="gap-1">
                  Next <ChevronRight className="h-4 w-4" />
                </Button>
              </div>
            </div>
          </>
        )}
      </div>

      <Dialog open={!!selected} onOpenChange={(open) => !open && setSelected(null)}>
        <DialogContent className="max-h-[80vh] overflow-y-auto">
          {selected && (
            <>
              <DialogHeader>
                <DialogTitle className="flex flex-wrap items-center gap-2">
                  <span className="font-mono text-sm text-muted-foreground">{selected.ruleId}</span>
                  {selected.title}
                </DialogTitle>
                <DialogDescription>
                  <span className="mt-2 flex flex-wrap items-center gap-2">
                    <SeverityBadge severity={selected.severity} />
                    <Badge variant="outline" className="text-xs">{selected.category}</Badge>
                    <span className="font-mono text-xs text-muted-foreground">{selected.affectedHost}</span>
                  </span>
                </DialogDescription>
              </DialogHeader>
              <div className="space-y-4 text-sm">
                <div>
                  <p className="mb-1 text-xs font-medium uppercase tracking-wide text-muted-foreground">Description</p>
                  <p className="text-muted-foreground">{selected.description}</p>
                </div>
                <div>
                  <p className="mb-1 text-xs font-medium uppercase tracking-wide text-muted-foreground">Evidence</p>
                  <p className="font-mono text-xs text-muted-foreground">{selected.evidence}</p>
                </div>
                <div>
                  <p className="mb-1 text-xs font-medium uppercase tracking-wide text-muted-foreground">Recommendation</p>
                  <p className="text-muted-foreground">{selected.recommendation}</p>
                </div>
                {selected.reference && (
                  <div>
                    <p className="mb-1 text-xs font-medium uppercase tracking-wide text-muted-foreground">Reference</p>
                    <p className="font-mono text-xs text-sky-400">{selected.reference}</p>
                  </div>
                )}
                <div className="flex flex-wrap gap-2">
                  <Button size="sm" asChild>
                    <a href={`/scanner?target=${encodeURIComponent(selected.affectedHost)}`}>Rescan host</a>
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => setSelected(null)}>
                    Close
                  </Button>
                </div>
              </div>
            </>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
