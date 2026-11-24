"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useState } from "react";
import { ArrowLeft, ChevronLeft, ChevronRight } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { TableSkeleton } from "@/components/shared/skeletons";
import { EmptyState } from "@/components/shared/empty-state";
import { formatDateTime, formatDuration } from "@/lib/format";
import { useAsync } from "@/hooks/use-async";
import { getRecurringScan, getRecurringScanRuns } from "@/services/recurringScansService";
import { cn } from "@/lib/utils";

const PAGE_SIZE = 20;

function ScoreBadge({ score }: { score: number }) {
  return (
    <Badge
      variant="outline"
      className={cn(
        score >= 85
          ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-400"
          : score >= 65
            ? "border-amber-500/40 bg-amber-500/10 text-amber-400"
            : "border-red-500/40 bg-red-500/10 text-red-400",
      )}
    >
      {score}
    </Badge>
  );
}

export default function RecurringScanRunsPage() {
  const params = useParams<{ id: string }>();
  const id = Number(params.id);
  const [page, setPage] = useState(1);

  const { data: schedule } = useAsync(() => getRecurringScan(id), [id]);
  const {
    data: runs,
    loading,
    error,
  } = useAsync(() => getRecurringScanRuns(id, page, PAGE_SIZE), [id, page]);

  if (!schedule && !loading && !error) {
    return <EmptyState title="Schedule not found" description="This recurring scan may have been deleted." />;
  }

  const totalPages = runs ? Math.max(1, Math.ceil(runs.total / PAGE_SIZE)) : 1;

  return (
    <div>
      <div className="mb-6">
        <Link
          href="/recurring-scans"
          className="mb-3 inline-flex items-center gap-1 text-xs font-medium text-muted-foreground hover:text-foreground"
        >
          <ArrowLeft className="h-3.5 w-3.5" /> Back to Recurring Scans
        </Link>
        <h1 className="text-2xl font-semibold tracking-tight text-foreground">
          {schedule ? `${schedule.host}:${schedule.port}` : "Scan runs"}
        </h1>
        {schedule && (
          <p className="mt-1 text-sm text-muted-foreground">
            {schedule.profile} • every {schedule.intervalHours}h •{" "}
            {runs ? `${runs.total} run${runs.total === 1 ? "" : "s"}` : "…"}
          </p>
        )}
      </div>

      {loading ? (
        <TableSkeleton columns={5} rows={8} />
      ) : error ? (
        <EmptyState title="Could not load scan runs." />
      ) : !runs || runs.items.length === 0 ? (
        <Card>
          <CardContent className="py-10 text-center text-sm text-muted-foreground">
            No scan runs recorded yet for this schedule.
          </CardContent>
        </Card>
      ) : (
        <div className="overflow-x-auto rounded-lg border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Date</TableHead>
                <TableHead>Target</TableHead>
                <TableHead>Duration</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Score</TableHead>
                <TableHead className="w-12" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {runs.items.map((h) => (
                <TableRow key={h.id} className="hover:bg-accent/40">
                  <TableCell className="text-xs text-muted-foreground whitespace-nowrap">
                    {formatDateTime(h.date)}
                  </TableCell>
                  <TableCell className="font-mono text-sm text-foreground">{h.target}</TableCell>
                  <TableCell className="text-xs text-muted-foreground">
                    {formatDuration(h.durationMs)}
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">{h.status}</TableCell>
                  <TableCell>
                    {h.score !== null ? (
                      <ScoreBadge score={h.score} />
                    ) : (
                      <span className="text-xs text-muted-foreground">—</span>
                    )}
                  </TableCell>
                  <TableCell>
                    <Link
                      href={`/scanner/${h.id}`}
                      className="text-muted-foreground transition-colors hover:text-foreground"
                      title="Open full analysis"
                    >
                      <ChevronRight className="h-4 w-4" />
                    </Link>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}

      {runs && runs.total > PAGE_SIZE && (
        <div className="mt-4 flex items-center justify-between">
          <Button
            variant="outline"
            size="sm"
            disabled={page <= 1}
            onClick={() => setPage((p) => Math.max(1, p - 1))}
          >
            <ChevronLeft className="h-4 w-4" /> Previous
          </Button>
          <span className="text-xs text-muted-foreground">
            Page {page} of {totalPages}
          </span>
          <Button
            variant="outline"
            size="sm"
            disabled={page >= totalPages}
            onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
          >
            Next <ChevronRight className="h-4 w-4" />
          </Button>
        </div>
      )}
    </div>
  );
}
