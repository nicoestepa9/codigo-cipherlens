"use client";

import { useState } from "react";
import Link from "next/link";
import { CalendarClock, ChevronRight, Loader2, Pencil, Play, Plus, RefreshCw, Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { TableSkeleton } from "@/components/shared/skeletons";
import { EmptyState } from "@/components/shared/empty-state";
import { RecurringScanFormDialog } from "@/components/features/recurring-scans/recurring-scan-form-dialog";
import { formatDateTime, relativeTime } from "@/lib/format";
import { cn } from "@/lib/utils";
import { useAsync } from "@/hooks/use-async";
import {
  createRecurringScan,
  deleteRecurringScan,
  getRecurringScan,
  getRecurringScans,
  runRecurringScanNow,
  updateRecurringScan,
} from "@/services/recurringScansService";
import { CloudAuthorizationCancelledError } from "@/services/cloudAuthorization";
import type { RecurringScan, RecurringScanDetail, RecurringScanInput } from "@/types/recurringScan";

export default function RecurringScansPage() {
  const { data, loading, error, refetch } = useAsync<RecurringScanDetail[]>(getRecurringScans, []);

  const [dialogOpen, setDialogOpen] = useState(false);
  const [editing, setEditing] = useState<RecurringScan | null>(null);
  const [saving, setSaving] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const [runningId, setRunningId] = useState<number | null>(null);
  const [detail, setDetail] = useState<RecurringScanDetail | null>(null);

  function openCreate() {
    setEditing(null);
    setFormError(null);
    setDialogOpen(true);
  }

  function openEdit(scan: RecurringScan) {
    setEditing(scan);
    setFormError(null);
    setDialogOpen(true);
  }

  async function openDetail(scan: RecurringScan) {
    try {
      setDetail(await getRecurringScan(scan.id));
    } catch {
      setDetail(scan as unknown as RecurringScanDetail);
    }
  }

  async function handleSubmit(input: RecurringScanInput) {
    setSaving(true);
    setFormError(null);
    try {
      if (editing) {
        await updateRecurringScan(editing.id, input);
      } else {
        await createRecurringScan(input);
      }
      setDialogOpen(false);
      setEditing(null);
      await refetch();
    } catch (e) {
      if (e instanceof CloudAuthorizationCancelledError) {
        setFormError("Not saved: accept the authorization statement to continue.");
      } else {
        setFormError(e instanceof Error ? e.message : "Failed to save recurring scan.");
      }
    } finally {
      setSaving(false);
    }
  }

  async function handleRunNow(scan: RecurringScan) {
    setRunningId(scan.id);
    try {
      const updated = await runRecurringScanNow(scan.id);
      setDetail((d) => (d && d.id === scan.id ? updated : d));
      await refetch();
    } finally {
      setRunningId(null);
    }
  }

  async function handleToggleEnabled(scan: RecurringScan) {
    await updateRecurringScan(scan.id, {
      host: scan.host,
      port: scan.port,
      alternatePorts: scan.alternatePorts,
      profile: scan.profile,
      intervalHours: scan.intervalHours,
      enabled: !scan.enabled,
      agentId: scan.agentId,
    });
    await refetch();
  }

  async function handleDelete(scan: RecurringScan) {
    if (!window.confirm(`Delete recurring scan for ${scan.host}? This will not delete past scan results.`)) return;
    await deleteRecurringScan(scan.id);
    if (detail?.id === scan.id) setDetail(null);
    await refetch();
  }

  return (
    <div>
      <div className="mb-6 flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-foreground">Recurring Scans</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Schedule automated TLS scans that run periodically and compare results against the previous run.
          </p>
        </div>
        <Button onClick={openCreate} className="gap-2">
          <Plus className="h-4 w-4" /> New recurring scan
        </Button>
      </div>

      {loading ? (
        <TableSkeleton columns={6} rows={6} />
      ) : error ? (
        <EmptyState title="Could not load recurring scans." />
      ) : !data || data.length === 0 ? (
        <Card>
          <EmptyState
            icon={<CalendarClock className="h-6 w-6" />}
            title="No recurring scans yet"
            description="Create a schedule to automatically scan a target on a fixed interval."
          />
        </Card>
      ) : (
        <div className="overflow-x-auto rounded-lg border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Target</TableHead>
                <TableHead>Profile</TableHead>
                <TableHead>Frequency</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Last run</TableHead>
                <TableHead>Next run</TableHead>
                <TableHead className="w-40 text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {(data ?? []).map((s) => (
                <TableRow
                  key={s.id}
                  className="cursor-pointer hover:bg-accent/40"
                  onClick={() => openDetail(s)}
                >
                  <TableCell>
                    <p className="font-mono text-sm font-medium text-foreground">{s.host}:{s.port}</p>
                    {s.alternatePorts.length > 0 && (
                      <p className="text-[11px] text-muted-foreground">
                        alt: {s.alternatePorts.join(", ")}
                      </p>
                    )}
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">{s.profile}</TableCell>
                  <TableCell className="text-sm text-muted-foreground">Every {s.intervalHours}h</TableCell>
                  <TableCell>
                    {s.isRunning ? (
                      <Badge variant="outline" className="gap-1 border-sky-500/40 bg-sky-500/10 text-sky-400">
                        <Loader2 className="h-3 w-3 animate-spin" /> Running
                      </Badge>
                    ) : (
                      <Badge
                        variant={s.enabled ? "default" : "outline"}
                        className={cn(!s.enabled && "border-muted text-muted-foreground")}
                      >
                        {s.enabled ? "Enabled" : "Disabled"}
                      </Badge>
                    )}
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">
                    {s.lastRunAt ? relativeTime(s.lastRunAt) : "Never"}
                    {s.consecutiveFailures > 0 && (
                      <span className="ml-1 text-red-400">({s.consecutiveFailures} fails)</span>
                    )}
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">
                    {s.nextRunAt ? formatDateTime(s.nextRunAt) : "—"}
                  </TableCell>
                  <TableCell onClick={(e) => e.stopPropagation()}>
                    <div className="flex items-center justify-end gap-1">
                      <Button
                        variant="ghost"
                        size="sm"
                        title="Run now"
                        onClick={() => handleRunNow(s)}
                        disabled={s.isRunning || runningId === s.id}
                      >
                        {runningId === s.id ? (
                          <Loader2 className="h-4 w-4 animate-spin" />
                        ) : (
                          <Play className="h-4 w-4" />
                        )}
                        <span className="sr-only">Run now</span>
                      </Button>
                      <Button variant="ghost" size="sm" title="Edit" onClick={() => openEdit(s)}>
                        <Pencil className="h-4 w-4" />
                        <span className="sr-only">Edit</span>
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        title={s.enabled ? "Disable" : "Enable"}
                        onClick={() => handleToggleEnabled(s)}
                      >
                        <RefreshCw className="h-4 w-4" />
                        <span className="sr-only">Toggle</span>
                      </Button>
                      <Button variant="ghost" size="sm" title="Delete" onClick={() => handleDelete(s)}>
                        <Trash2 className="h-4 w-4 text-red-400" />
                        <span className="sr-only">Delete</span>
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}

      <RecurringScanFormDialog
        open={dialogOpen}
        scan={editing}
        saving={saving}
        error={formError}
        onClose={() => setDialogOpen(false)}
        onSubmit={handleSubmit}
      />

      <Dialog open={!!detail} onOpenChange={(o) => !o && setDetail(null)}>
        <DialogContent className="max-h-[80vh] overflow-y-auto sm:max-w-lg">
          {detail && (
            <>
              <DialogHeader>
                <DialogTitle className="font-mono text-base">
                  {detail.host}:{detail.port}
                </DialogTitle>
                <DialogDescription>
                  Scans generated by this recurring schedule.
                </DialogDescription>
              </DialogHeader>
              <div className="text-sm">
                <div className="mb-3 grid grid-cols-2 gap-3 text-xs">
                  <div>
                    <span className="text-muted-foreground">Profile: </span>
                    <span className="text-foreground">{detail.profile}</span>
                  </div>
                  <div>
                    <span className="text-muted-foreground">Frequency: </span>
                    <span className="text-foreground">Every {detail.intervalHours}h</span>
                  </div>
                  <div>
                    <span className="text-muted-foreground">Last run: </span>
                    <span className="text-foreground">{detail.lastRunAt ? relativeTime(detail.lastRunAt) : "Never"}</span>
                  </div>
                  <div>
                    <span className="text-muted-foreground">Next run: </span>
                    <span className="text-foreground">{detail.nextRunAt ? formatDateTime(detail.nextRunAt) : "—"}</span>
                  </div>
                </div>

                {detail.recentScans?.length === 0 ? (
                  <p className="text-sm text-muted-foreground">No scan runs recorded yet.</p>
                ) : (
                  <>
                    <ul className="space-y-2">
                      {detail.recentScans.slice(0, 8).map((h) => (
                        <li
                          key={h.id}
                          className="flex items-center justify-between rounded-lg border px-3 py-2"
                        >
                          <div>
                            <p className="text-xs text-muted-foreground">{formatDateTime(h.date)}</p>
                            <p className="font-mono text-xs text-foreground">{h.target}</p>
                          </div>
                          <div className="flex items-center gap-2">
                            {h.score !== null && (
                              <Badge
                                variant="outline"
                                className={cn(
                                  h.score >= 85
                                    ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-400"
                                    : h.score >= 65
                                      ? "border-amber-500/40 bg-amber-500/10 text-amber-400"
                                      : "border-red-500/40 bg-red-500/10 text-red-400",
                                )}
                              >
                                {h.score}
                              </Badge>
                            )}
                            <Link
                              href={`/scanner/${h.id}`}
                              className="text-muted-foreground transition-colors hover:text-foreground"
                              title="Open full analysis"
                            >
                              <ChevronRight className="h-4 w-4" />
                            </Link>
                          </div>
                        </li>
                      ))}
                    </ul>
                    {detail.recentScans.length > 8 && (
                      <Link
                        href={`/recurring-scans/${detail.id}`}
                        className="mt-3 inline-flex items-center gap-1 text-xs font-medium text-foreground underline-offset-4 hover:underline"
                      >
                        View all {detail.recentScans.length} runs
                        <ChevronRight className="h-3 w-3" />
                      </Link>
                    )}
                  </>
                )}
              </div>
            </>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
