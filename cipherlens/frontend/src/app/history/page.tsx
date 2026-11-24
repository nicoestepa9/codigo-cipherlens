"use client";

import { useMemo, useState } from "react";
import Link from "next/link";
import { useAsync } from "@/hooks/use-async";
import { Activity, ChevronLeft, ChevronRight, Clock, Radar, Search } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { TableSkeleton } from "@/components/shared/skeletons";
import { EmptyState } from "@/components/shared/empty-state";
import { formatDateTime, formatDuration } from "@/lib/format";
import { getHistory } from "@/services/historyService";
import type { HistoryEntry } from "@/types/history";

const PAGE_SIZE = 12;

function kindBadge(kind: HistoryEntry["kind"]) {
  return kind === "tls_scan" ? (
    <Badge variant="outline" className="border-sky-500/40 bg-sky-500/10 text-sky-400">
      <Activity className="mr-1 h-3 w-3" /> TLS Scan
    </Badge>
  ) : (
    <Badge variant="outline" className="border-violet-500/40 bg-violet-500/10 text-violet-400">
      <Radar className="mr-1 h-3 w-3" /> Discovery
    </Badge>
  );
}

function statusBadge(status: HistoryEntry["status"]) {
  if (status === "completed") {
    return <Badge variant="outline" className="border-emerald-500/40 bg-emerald-500/10 text-emerald-400">Completed</Badge>;
  }
  if (status === "running") {
    return <Badge variant="outline" className="border-amber-500/40 bg-amber-500/10 text-amber-400">Running</Badge>;
  }
  return <Badge variant="outline" className="border-red-500/40 bg-red-500/10 text-red-400">Failed</Badge>;
}

function scoreBadge(score: number) {
  const cls =
    score >= 85
      ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-400"
      : score >= 65
        ? "border-amber-500/40 bg-amber-500/10 text-amber-400"
        : "border-red-500/40 bg-red-500/10 text-red-400";
  return (
    <Badge variant="outline" className={`font-mono text-xs ${cls}`}>
      {score}
    </Badge>
  );
}

export default function HistoryPage() {
  const [search, setSearch] = useState("");
  const [kind, setKind] = useState<"all" | "tls_scan" | "discovery">("all");
  const [page, setPage] = useState(1);

  const { data: entries, loading, error } = useAsync(getHistory, []);

  const filtered = useMemo(() => {
    const q = search.toLowerCase();
    return (entries ?? [])
      .filter((e) => (kind === "all" ? true : e.kind === kind))
      .filter((e) => (q ? e.target.toLowerCase().includes(q) || e.host.toLowerCase().includes(q) : true))
      .sort((a, b) => b.date.localeCompare(a.date));
  }, [entries, search, kind]);

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const pageItems = filtered.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);

  return (
    <div>
      <PageHeader
        title="Analysis History"
        subtitle="Past TLS analyses and network discovery runs."
      />

      <div className="mb-4 flex flex-wrap items-center gap-2">
        <div className="relative">
          <Search className="absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            value={search}
            onChange={(e) => { setSearch(e.target.value); setPage(1); }}
            placeholder="Search target or host..."
            className="h-8 w-64 pl-8"
          />
        </div>
        {(["all", "tls_scan", "discovery"] as const).map((k) => (
          <Button
            key={k}
            size="sm"
            variant={kind === k ? "default" : "outline"}
            className="h-8 text-xs capitalize"
            onClick={() => { setKind(k); setPage(1); }}
          >
            {k === "all" ? "All" : k === "tls_scan" ? "TLS Scans" : "Discoveries"}
          </Button>
        ))}
      </div>

      {loading ? (
        <TableSkeleton columns={6} rows={8} />
      ) : error ? (
        <EmptyState title="Could not load history." />
      ) : filtered.length === 0 ? (
        <EmptyState icon={<Clock className="h-6 w-6" />} title="No history entries found." />
      ) : (
        <>
          <div className="overflow-x-auto rounded-lg border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Type</TableHead>
                  <TableHead>Target</TableHead>
                  <TableHead>Date</TableHead>
                  <TableHead>Score</TableHead>
                  <TableHead>Duration</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="w-8" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {pageItems.map((e) => (
                  <TableRow key={e.id} className="hover:bg-accent/40">
                    <TableCell>{kindBadge(e.kind)}</TableCell>
                    <TableCell>
                      <Link
                        href={e.kind === "tls_scan" ? `/scanner/${e.id}` : `/discovery?scan=${e.id}`}
                        className="font-mono text-xs font-medium text-foreground hover:underline"
                      >
                        {e.target}
                      </Link>
                      <p className="text-[11px] text-muted-foreground">{e.profile}</p>
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">{formatDateTime(e.date)}</TableCell>
                    <TableCell>
                      {e.score != null ? (
                        scoreBadge(e.score)
                      ) : (
                        <span className="text-xs text-muted-foreground">—</span>
                      )}
                    </TableCell>
                    <TableCell className="font-mono text-xs text-muted-foreground">{formatDuration(e.durationMs)}</TableCell>
                    <TableCell>{statusBadge(e.status)}</TableCell>
                    <TableCell>
                      <Button variant="ghost" size="sm" asChild>
                        <Link href={e.kind === "tls_scan" ? `/scanner/${e.id}` : `/discovery?scan=${e.id}`}>
                          View
                        </Link>
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>

          <div className="flex items-center justify-between">
            <p className="text-xs text-muted-foreground">Showing {pageItems.length} of {filtered.length} entries</p>
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
  );
}
