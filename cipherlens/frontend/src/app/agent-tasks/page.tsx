"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { EmptyState, ErrorState } from "@/components/shared/empty-state";
import { PageHeader } from "@/components/shared/page-header";
import { useRole } from "@/components/auth/AuthContext";
import { useAsync } from "@/hooks/use-async";
import { relativeTime } from "@/lib/format";
import { cancelAgentTask, listAgentTasks } from "@/services/agentTasksService";
import type { AgentTask, AgentTaskStatus } from "@/types/agent";
import { ListChecks, Loader2, RefreshCw, X } from "lucide-react";

const STATUS_OPTIONS: Array<{ value: "all" | AgentTaskStatus; label: string }> = [
  { value: "all", label: "All statuses" },
  { value: "queued", label: "Queued" },
  { value: "claimed", label: "Claimed" },
  { value: "running", label: "Running" },
  { value: "done", label: "Done" },
  { value: "failed", label: "Failed" },
  { value: "rejected", label: "Rejected" },
  { value: "expired", label: "Expired" },
  { value: "cancelled", label: "Cancelled" },
];

function statusVariant(status: AgentTaskStatus): "default" | "secondary" | "destructive" | "outline" {
  if (status === "done") return "default";
  if (status === "failed" || status === "rejected") return "destructive";
  if (status === "queued" || status === "claimed" || status === "running") return "secondary";
  return "outline";
}

function taskName(task: AgentTask): string {
  if (task.type === "scan") {
    const target = task.payload.target as { host?: string; port?: number } | undefined;
    if (!target?.host) return "TLS scan";
    const host = target.host.includes(":") ? `[${target.host}]` : target.host;
    return `TLS scan · ${host}${target.port ? `:${target.port}` : ""}`;
  }
  if (task.type === "discovery") {
    const { ipRange, domains } = task.payload;
    const target = typeof ipRange === "string" && ipRange
      ? ipRange
      : Array.isArray(domains) ? domains.join(", ") : "";
    return target ? `Network discovery · ${target}` : "Network discovery";
  }
  return task.type;
}

export default function AgentTasksPage() {
  const router = useRouter();
  const { canAssign } = useRole();
  const [statusFilter, setStatusFilter] = useState<"all" | AgentTaskStatus>("all");
  const { data, loading, error, refetch } = useAsync(
    () => listAgentTasks({ status: statusFilter === "all" ? undefined : statusFilter, limit: 100 }),
    [statusFilter],
  );

  useEffect(() => {
    if (!canAssign) router.push("/dashboard");
  }, [canAssign, router]);

  useEffect(() => {
    const timer = setInterval(() => void refetch(), 5000);
    return () => clearInterval(timer);
  }, [refetch]);

  if (!canAssign) return null;

  const tasks = data ?? [];

  async function handleCancel(id: string) {
    try {
      await cancelAgentTask(id);
      await refetch();
    } catch (err) {
      alert(err instanceof Error ? err.message : "Could not cancel the task.");
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Agent Tasks"
        subtitle="Remote scan and discovery jobs dispatched to enrolled on-prem agents."
      />

      <Card>
        <CardHeader className="flex flex-row items-center justify-between gap-3">
          <CardTitle className="text-base">Task queue</CardTitle>
          <div className="flex items-center gap-2">
            <Select
              value={statusFilter}
              onValueChange={(value) => setStatusFilter(value as "all" | AgentTaskStatus)}
            >
              <SelectTrigger className="w-40">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {STATUS_OPTIONS.map((option) => (
                  <SelectItem key={option.value} value={option.value}>
                    {option.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Button variant="ghost" size="sm" onClick={() => void refetch()} className="gap-2">
              <RefreshCw className="h-3.5 w-3.5" />
              Refresh
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          {loading && tasks.length === 0 ? (
            <div className="flex justify-center py-10">
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
            </div>
          ) : error ? (
            <ErrorState message={error.message} onRetry={() => void refetch()} />
          ) : tasks.length === 0 ? (
            <EmptyState
              icon={<ListChecks className="h-8 w-8" />}
              title="No agent tasks"
              description="Scans and discoveries dispatched to on-prem agents will appear here."
            />
          ) : (
            <div className="overflow-x-auto rounded-lg border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Task</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Agent</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead>Attempts</TableHead>
                  <TableHead>Result</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {tasks.map((task) => (
                  <TableRow key={task.id}>
                    <TableCell>
                      <p className="max-w-72 truncate font-medium" title={taskName(task)}>{taskName(task)}</p>
                      <p className="font-mono text-xs text-muted-foreground" title={task.id}>{task.id.slice(0, 8)}</p>
                    </TableCell>
                    <TableCell>
                      <Badge variant={statusVariant(task.status)}>{task.status}</Badge>
                      {task.error && (
                        <div className="mt-1 max-w-56 truncate text-xs text-destructive" title={task.error}>
                          {task.error}
                        </div>
                      )}
                    </TableCell>
                    <TableCell className="font-mono text-xs">{task.agentId}</TableCell>
                    <TableCell className="text-sm">{relativeTime(task.createdAt)}</TableCell>
                    <TableCell className="text-sm">{task.attempts}</TableCell>
                    <TableCell className="text-sm">
                      {task.resultScanId ? (
                        <Link href={`/scanner/${task.resultScanId}`} className="text-primary underline underline-offset-4">
                          Open scan
                        </Link>
                      ) : task.resultJobId ? (
                        <Link href="/discovery" className="text-primary underline underline-offset-4">
                          View discovery
                        </Link>
                      ) : (
                        <span className="text-muted-foreground">—</span>
                      )}
                    </TableCell>
                    <TableCell className="text-right">
                      {(task.status === "queued" || task.status === "claimed" || task.status === "running") && (
                        <Button size="sm" variant="ghost" onClick={() => void handleCancel(task.id)}>
                          <X className="h-4 w-4" />
                        </Button>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
