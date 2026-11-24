"use client";

import { useMemo } from "react";
import Link from "next/link";
import {
  AlertTriangle,
  ArchiveX,
  Clock,
  ShieldCheck,
  TimerOff,
} from "lucide-react";
import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { StatCard } from "@/components/shared/stat-card";
import { CertStatusBadge } from "@/components/shared/cert-status-badge";
import { TableSkeleton } from "@/components/shared/skeletons";
import { EmptyState, ErrorState } from "@/components/shared/empty-state";
import { formatDate } from "@/lib/format";
import { useAsync } from "@/hooks/use-async";
import { useSettings } from "@/context/settings-context";
import { getCertificates, getExpirationStatsService } from "@/services/certificatesService";

const WINDOW_COLORS = ["#f43f5e", "#f59e0b", "#38bdf8", "#34d399"];

export default function ExpirationPage() {
  const { settings } = useSettings();
  const configuredCriticalDays = settings.thresholds.criticalDays;
  const configuredWarningDays = settings.thresholds.warningDays;

  const { data: stats, loading: statsLoading, error: statsError, refetch: refetchStats } = useAsync(
    () => getExpirationStatsService(configuredCriticalDays, configuredWarningDays),
    [configuredCriticalDays, configuredWarningDays],
  );

  const criticalDays = stats?.criticalDays ?? configuredCriticalDays;
  const warningDays = stats?.warningDays ?? configuredWarningDays;

  const { data: page, loading: listLoading, error: listError, refetch: refetchList } = useAsync(
    () => getCertificates({ pageSize: 1000 }),
    [],
  );

  const atRisk = useMemo(() => {
    if (!page) return [];
    return page.items
      .filter((c) => c.daysUntilExpiry <= warningDays)
      .sort((a, b) => a.daysUntilExpiry - b.daysUntilExpiry);
  }, [page, warningDays]);

  const chartData = useMemo(
    () => stats?.byWindow.map((w) => ({ name: w.label, count: w.count })) ?? [],
    [stats],
  );

  if (statsLoading || listLoading) {
    return (
      <div className="space-y-4">
        <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
          <TableSkeleton columns={1} rows={1} />
          <TableSkeleton columns={1} rows={1} />
          <TableSkeleton columns={1} rows={1} />
          <TableSkeleton columns={1} rows={1} />
        </div>
        <TableSkeleton columns={6} rows={6} />
      </div>
    );
  }

  if (statsError || listError) {
    return <ErrorState message="Could not load expiration statistics." onRetry={() => { refetchStats(); refetchList(); }} />;
  }

  return (
    <div>
      <PageHeader
        title="Expiration Monitoring"
        subtitle="Certificate lifecycle at a glance. Thresholds are configured in Settings."
        actions={
          <Button variant="outline" size="sm" asChild>
            <Link href="/settings">Configure thresholds</Link>
          </Button>
        }
      />

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <StatCard label="Expired" value={stats?.expired ?? 0} icon={<TimerOff className="h-4 w-4" />} accent="red" />
        <StatCard
          label={`Critical (< ${criticalDays}d)`}
          value={stats?.critical ?? 0}
          icon={<AlertTriangle className="h-4 w-4" />}
          accent="amber"
          sub="Immediate attention"
        />
        <StatCard
          label={`Warning (${criticalDays}-${warningDays}d)`}
          value={stats?.warning ?? 0}
          icon={<Clock className="h-4 w-4" />}
          accent="sky"
          sub="Plan renewal"
        />
        <StatCard label="Healthy" value={stats?.healthy ?? 0} icon={<ShieldCheck className="h-4 w-4" />} accent="emerald" sub={`of ${stats?.total ?? 0} total`} />
      </div>

      <div className="mt-4 grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Expiration Windows</CardTitle>
            <CardDescription>Certificates grouped by remaining validity.</CardDescription>
          </CardHeader>
          <CardContent className="h-72">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={chartData} margin={{ top: 8, right: 8, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" className="stroke-border" vertical={false} />
                <XAxis dataKey="name" tick={{ fontSize: 11 }} tickLine={false} axisLine={false} interval={0} angle={-12} textAnchor="end" height={56} />
                <YAxis tick={{ fontSize: 11 }} tickLine={false} axisLine={false} allowDecimals={false} />
                <Tooltip
                  cursor={{ fill: "rgba(148,163,184,0.08)" }}
                  contentStyle={{ background: "var(--popover)", border: "1px solid var(--border)", borderRadius: 8, fontSize: 12 }}
                />
                <Bar dataKey="count" name="Certificates" radius={[4, 4, 0, 0]}>
                  {chartData.map((_, i) => (
                    <Cell key={i} fill={WINDOW_COLORS[i % WINDOW_COLORS.length]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <ArchiveX className="h-4 w-4 text-muted-foreground" />
              At Risk ({atRisk.length})
            </CardTitle>
            <CardDescription>
              Expired or expiring within the warning threshold of {warningDays} days.
            </CardDescription>
          </CardHeader>
          <CardContent className="max-h-72 overflow-y-auto p-0">
            {atRisk.length === 0 ? (
              <div className="px-4 pb-4">
                <EmptyState icon={<ShieldCheck className="h-6 w-6" />} title="Nothing at risk right now." />
              </div>
            ) : (
              <Table>
                <TableHeader className="sticky top-0 bg-background">
                  <TableRow>
                    <TableHead>Certificate</TableHead>
                    <TableHead>Expires</TableHead>
                    <TableHead>Days Left</TableHead>
                    <TableHead>Status</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {atRisk.map((c) => (
                    <TableRow key={c.id}>
                      <TableCell>
                        <Link href={`/certificates/${c.id}`} className="font-mono text-xs font-medium hover:underline">
                          {c.domain}
                        </Link>
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">{formatDate(c.notAfter)}</TableCell>
                      <TableCell>
                        <Badge
                          variant="outline"
                          className={
                            c.daysUntilExpiry < 0
                              ? "border-red-500/40 bg-red-500/10 text-red-400"
                              : c.daysUntilExpiry <= criticalDays
                                ? "border-amber-500/40 bg-amber-500/10 text-amber-400"
                                : "border-sky-500/40 bg-sky-500/10 text-sky-400"
                          }
                        >
                          {c.daysUntilExpiry < 0 ? `-${Math.abs(c.daysUntilExpiry)}` : c.daysUntilExpiry}d
                        </Badge>
                      </TableCell>
                      <TableCell><CertStatusBadge status={c.status} /></TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
