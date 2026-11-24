"use client";

import Link from "next/link";
import {
  AlertTriangle,
  ArrowRight,
  Bug,
  Layers,
  Radar,
  Server,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Zap,
} from "lucide-react";
import { Bar, BarChart, CartesianGrid, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ScoreGauge } from "@/components/shared/score-gauge";
import { StatCard } from "@/components/shared/stat-card";
import { SeverityBadge } from "@/components/shared/severity-badge";
import { TableSkeleton } from "@/components/shared/skeletons";
import { EmptyState } from "@/components/shared/empty-state";
import { relativeTime } from "@/lib/format";
import { useAsync } from "@/hooks/use-async";
import { getDashboardSummaryService } from "@/services/dashboardService";
import { getExpirationStatsService } from "@/services/certificatesService";
import { getAlerts } from "@/services/alertsService";

const EXP_COLORS = ["#fb7185", "#fbbf24", "#4da3ff", "#34d399"];
const STATUS_COLORS = ["#34d399", "#fbbf24", "#fb7185"];

export default function DashboardPage() {
  const { data: summary, loading: summaryLoading, error: summaryError } = useAsync(
    getDashboardSummaryService,
    [],
  );
  const { data: expStats, loading: expLoading, error: expError } = useAsync(
    () => getExpirationStatsService(),
    [],
  );
  const { data: alerts, loading: alertsLoading, error: alertsError } = useAsync(getAlerts, []);

  const criticalDays = expStats?.criticalDays ?? summary?.certificateCriticalDays ?? 7;
  const warningDays = expStats?.warningDays ?? summary?.certificateWarningDays ?? 30;
  const loading = summaryLoading || expLoading || alertsLoading;

  if (loading) {
    return (
      <div className="space-y-4">
        <div className="grid grid-cols-2 gap-3 lg:grid-cols-3">
          <TableSkeleton columns={1} rows={1} />
          <TableSkeleton columns={1} rows={1} />
          <TableSkeleton columns={1} rows={1} />
        </div>
        <TableSkeleton columns={4} rows={4} />
      </div>
    );
  }

  if (summaryError || expError || alertsError) {
    return (
      <EmptyState
        title="Could not load the dashboard."
        description="Something went wrong while fetching the overview."
      />
    );
  }

  const expChart = expStats?.byWindow.map((w) => ({ name: w.label, count: w.count })) ?? [];

  const statusChart = [
    { name: "Secure", value: summary?.secure ?? 0 },
    { name: "Warning", value: summary?.warning ?? 0 },
    { name: "Critical", value: summary?.critical ?? 0 },
  ];

  const recentAlerts = (alerts ?? []).sort((a, b) => b.createdAt.localeCompare(a.createdAt)).slice(0, 5);

  return (
    <div>
      <div className="mb-6 flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className="text-[23px] font-bold tracking-tight text-foreground">Security Overview</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            {summary?.lastScanAt ? (
              <>Last TLS analysis {relativeTime(summary.lastScanAt)}.</>
            ) : (
              "No scans recorded yet — run your first analysis to get started."
            )}
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Button variant="outline" size="sm" asChild>
            <Link href="/discovery">
              <Radar className="mr-2 h-4 w-4" />
              Run Discovery
            </Link>
          </Button>
          <Button size="sm" asChild>
            <Link href="/scanner">
              <Zap className="mr-2 h-4 w-4" />
              New TLS Scan
            </Link>
          </Button>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4 xl:grid-cols-6">
        <Card className="col-span-2 flex items-center justify-center py-3">
          <CardContent>
            <ScoreGauge score={summary?.securityScore ?? 0} size={140} />
          </CardContent>
        </Card>
        <StatCard
          label="Certificates"
          value={summary?.totalCertificates ?? 0}
          icon={<Layers className="h-4 w-4" />}
          accent="sky"
          sub={`${summary?.certificatesExpiringSoon ?? 0} expiring <= ${warningDays}d`}
          onClick={undefined}
        />
        <StatCard
          label="Services"
          value={summary?.totalServices ?? 0}
          icon={<Server className="h-4 w-4" />}
          accent="violet"
          sub={`${summary?.secure ?? 0} secure · ${summary?.critical ?? 0} critical`}
        />
        <StatCard
          label="Shadow IT"
          value={summary?.shadowItDetected ?? 0}
          icon={<AlertTriangle className="h-4 w-4" />}
          accent="red"
          sub="Undocumented assets"
        />
        <StatCard
          label="Unread Alerts"
          value={summary?.unreadAlerts ?? 0}
          icon={<ShieldAlert className="h-4 w-4" />}
          accent="amber"
        />
      </div>

      <div className="mt-4 grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Certificate Expiration</CardTitle>
            <CardDescription>Distribution across expiration windows ({criticalDays} / {warningDays} day thresholds).</CardDescription>
          </CardHeader>
          <CardContent className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={expChart} margin={{ top: 8, right: 8, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" className="stroke-border" vertical={false} />
                <XAxis dataKey="name" tick={{ fontSize: 11 }} tickLine={false} axisLine={false} interval={0} angle={-12} textAnchor="end" height={56} />
                <YAxis tick={{ fontSize: 11 }} tickLine={false} axisLine={false} allowDecimals={false} />
                <Tooltip
                  cursor={{ fill: "rgba(148,163,184,0.08)" }}
                  contentStyle={{ background: "var(--popover)", border: "1px solid var(--border)", borderRadius: 8, fontSize: 12 }}
                />
                <Bar dataKey="count" name="Certificates" radius={[4, 4, 0, 0]}>
                  {expChart.map((_, i) => (
                    <Cell key={i} fill={EXP_COLORS[i % EXP_COLORS.length]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Services by TLS Posture</CardTitle>
            <CardDescription>Share of services per security status.</CardDescription>
          </CardHeader>
          <CardContent className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={statusChart}
                  dataKey="value"
                  nameKey="name"
                  innerRadius={60}
                  outerRadius={90}
                  paddingAngle={3}
                  label={(p) => `${p.name} (${p.value})`}
                  labelLine={false}
                  fontSize={11}
                >
                  {statusChart.map((_, i) => (
                    <Cell key={i} fill={STATUS_COLORS[i % STATUS_COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ background: "var(--popover)", border: "1px solid var(--border)", borderRadius: 8, fontSize: 12 }}
                />
              </PieChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
      </div>

      <div className="mt-4 grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader className="flex-row items-center justify-between space-y-0">
            <div>
              <CardTitle className="flex items-center gap-2 text-base">
                <ShieldAlert className="h-4 w-4 text-muted-foreground" />
                Recent Alerts
              </CardTitle>
              <CardDescription>Latest security and lifecycle notifications.</CardDescription>
            </div>
            <Button variant="ghost" size="sm" asChild>
              <Link href="/alerts" className="text-muted-foreground">
                View all <ArrowRight className="ml-1 h-3.5 w-3.5" />
              </Link>
            </Button>
          </CardHeader>
          <CardContent className="p-0">
            {recentAlerts.length === 0 ? (
              <EmptyState icon={<ShieldCheck className="h-6 w-6" />} title="No alerts." />
            ) : (
              <div className="divide-y divide-border/60">
                {recentAlerts.map((a) => (
                  <div key={a.id} className="flex items-center gap-3 px-4 py-3">
                    <SeverityBadge severity={a.severity} showDot />
                    <div className="min-w-0 flex-1">
                      <p className="truncate text-sm text-foreground">{a.title}</p>
                      <p className="truncate text-xs text-muted-foreground">{a.description}</p>
                    </div>
                    <span className="shrink-0 text-xs text-muted-foreground">{relativeTime(a.createdAt)}</span>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <Sparkles className="h-4 w-4 text-muted-foreground" />
              Quick Actions
            </CardTitle>
          </CardHeader>
          <CardContent className="flex flex-col gap-2">
            <Button variant="outline" className="justify-start" asChild>
              <Link href="/scanner">
                <Zap className="mr-2 h-4 w-4" /> Run a TLS analysis
              </Link>
            </Button>
            <Button variant="outline" className="justify-start" asChild>
              <Link href="/discovery">
                <Radar className="mr-2 h-4 w-4" /> Discover network assets
              </Link>
            </Button>
            <Button variant="outline" className="justify-start" asChild>
              <Link href="/certificates">
                <Layers className="mr-2 h-4 w-4" /> Review certificate expiry
              </Link>
            </Button>
            <Button variant="outline" className="justify-start" asChild>
              <Link href="/vulnerabilities">
                <Bug className="mr-2 h-4 w-4" /> Inspect vulnerabilities
              </Link>
            </Button>
            <Button variant="outline" className="justify-start" asChild>
              <Link href="/settings">
                <ShieldCheck className="mr-2 h-4 w-4" /> Configure thresholds
              </Link>
            </Button>
            <div className="mt-2 rounded-lg border border-dashed p-3">
              <p className="flex items-center gap-1.5 text-xs text-muted-foreground">
                <Badge variant="outline" className="border-emerald-500/40 bg-emerald-500/10 text-emerald-400">
                  {summary?.securityScore ?? 0}/100
                </Badge>
                Current overall posture
              </p>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
