"use client";

import { useMemo, useState } from "react";
import Link from "next/link";
import { useAsync } from "@/hooks/use-async";
import { BellOff, CheckCheck, ExternalLink, ShieldAlert } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { SeverityBadge } from "@/components/shared/severity-badge";
import { TableSkeleton } from "@/components/shared/skeletons";
import { EmptyState } from "@/components/shared/empty-state";
import { relativeTime } from "@/lib/format";
import { cn } from "@/lib/utils";
import { getAlerts, setAlertStatusService } from "@/services/alertsService";
import type { Alert, AlertStatus, AlertType } from "@/types/alert";
import type { Severity } from "@/types/severity";

const TYPE_LABEL: Record<AlertType, string> = {
  expiration: "Expiration",
  vulnerability: "Vulnerability",
  compliance: "Compliance",
  discovery: "Discovery",
  system: "System",
};

const TYPE_CLS: Record<AlertType, string> = {
  expiration: "border-amber-500/40 bg-amber-500/10 text-amber-400",
  vulnerability: "border-red-500/40 bg-red-500/10 text-red-400",
  compliance: "border-violet-500/40 bg-violet-500/10 text-violet-400",
  discovery: "border-sky-500/40 bg-sky-500/10 text-sky-400",
  system: "border-muted text-muted-foreground",
};

const STATUS_ORDER: AlertStatus[] = ["unread", "read", "resolved", "ignored"];

export default function AlertsPage() {
  const [tab, setTab] = useState<string>("all");
  const [severity, setSeverity] = useState<Severity | "all">("all");
  const [type, setType] = useState<AlertType | "all">("all");

  const { data: alerts, loading, error, refetch } = useAsync(getAlerts, []);

  const filtered = useMemo(() => {
    return (alerts ?? [])
      .filter((a) => (tab === "all" ? true : a.status === tab))
      .filter((a) => (severity === "all" ? true : a.severity === severity))
      .filter((a) => (type === "all" ? true : a.type === type))
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  }, [alerts, tab, severity, type]);

  const counts = useMemo(() => {
    const c: Record<string, number> = { all: alerts?.length ?? 0, unread: 0, read: 0, resolved: 0, ignored: 0 };
    for (const a of alerts ?? []) c[a.status] = (c[a.status] ?? 0) + 1;
    return c;
  }, [alerts]);

  function setStatus(alert: Alert, status: AlertStatus) {
    setAlertStatusService(alert.id, status).then(refetch);
  }

  function markAllRead() {
    const unread = (alerts ?? []).filter((a) => a.status === "unread");
    Promise.all(unread.map((a) => setAlertStatusService(a.id, "read"))).then(refetch);
  }

  return (
    <div>
      <Card className="mb-4 border-0 bg-transparent p-0 shadow-none">
        <CardHeader className="p-0">
          <CardTitle className="flex items-center gap-2 text-2xl">
            <ShieldAlert className="h-6 w-6 text-muted-foreground" />
            Alerts
          </CardTitle>
          <CardDescription className="text-sm text-muted-foreground">
            Security and lifecycle notifications across the platform.
          </CardDescription>
        </CardHeader>
      </Card>

      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <Tabs value={tab} onValueChange={setTab}>
          <TabsList>
            {(["all", ...STATUS_ORDER] as const).map((s) => (
              <TabsTrigger key={s} value={s} className="capitalize">
                {s}
                <span className="ml-1.5 text-xs text-muted-foreground">{counts[s] ?? 0}</span>
              </TabsTrigger>
            ))}
          </TabsList>
        </Tabs>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={markAllRead} disabled={!counts.unread}>
            <CheckCheck className="mr-2 h-4 w-4" />
            Mark all read
          </Button>
          <Select value={severity} onValueChange={(v) => setSeverity(v as Severity | "all")}>
            <SelectTrigger className="h-8 w-32">
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
          <Select value={type} onValueChange={(v) => setType(v as AlertType | "all")}>
            <SelectTrigger className="h-8 w-36">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">Type: All</SelectItem>
              {(Object.keys(TYPE_LABEL) as AlertType[]).map((t) => (
                <SelectItem key={t} value={t}>{TYPE_LABEL[t]}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </div>

      {loading ? (
        <TableSkeleton columns={4} rows={8} />
      ) : error ? (
        <EmptyState title="Could not load alerts." />
      ) : filtered.length === 0 ? (
        <EmptyState icon={<BellOff className="h-6 w-6" />} title="No alerts match the current filters." />
      ) : (
        <div className="space-y-2">
          {filtered.map((a) => (
            <Card
              key={a.id}
              className={cn(
                "transition-colors hover:border-primary/40",
                a.status === "unread" && "border-l-2 border-l-sky-500",
              )}
            >
              <CardContent className="flex flex-col gap-3 p-4 sm:flex-row sm:items-start sm:justify-between">
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <SeverityBadge severity={a.severity} />
                    <Badge variant="outline" className={TYPE_CLS[a.type]}>{TYPE_LABEL[a.type]}</Badge>
                    {a.status === "unread" && (
                      <span className="inline-block h-1.5 w-1.5 rounded-full bg-sky-500" title="Unread" />
                    )}
                    <span className="text-xs text-muted-foreground">{relativeTime(a.createdAt)}</span>
                  </div>
                  <p className={cn("mt-1.5 text-sm", a.status === "unread" ? "font-medium text-foreground" : "text-muted-foreground")}>
                    {a.title}
                  </p>
                  <p className="mt-1 text-xs text-muted-foreground">{a.description}</p>
                  {a.relatedTarget && <p className="mt-1 font-mono text-[11px] text-muted-foreground">{a.relatedTarget}</p>}
                </div>
                <div className="flex shrink-0 flex-wrap items-center gap-2">
                  {a.actionHref && (
                    <Button variant="outline" size="sm" className="h-8 text-xs" asChild>
                      <Link href={a.actionHref}>
                        {a.actionLabel ?? "View"} <ExternalLink className="ml-1.5 h-3 w-3" />
                      </Link>
                    </Button>
                  )}
                  {a.status !== "resolved" && (
                    <Button variant="ghost" size="sm" className="h-8 text-xs" onClick={() => setStatus(a, "resolved")}>
                      Resolve
                    </Button>
                  )}
                  {a.status === "unread" && (
                    <Button variant="ghost" size="sm" className="h-8 text-xs text-muted-foreground" onClick={() => setStatus(a, "read")}>
                      Mark read
                    </Button>
                  )}
                  {a.status !== "ignored" && (
                    <Button variant="ghost" size="sm" className="h-8 text-xs text-muted-foreground" onClick={() => setStatus(a, "ignored")}>
                      Ignore
                    </Button>
                  )}
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
