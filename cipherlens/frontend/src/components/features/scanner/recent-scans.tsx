"use client";

import Link from "next/link";
import { ChevronRight, History } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { getHistory } from "@/services/historyService";
import { useAsync } from "@/hooks/use-async";
import { formatDateTime } from "@/lib/format";
import { StatusBadge } from "@/components/shared/status-badge";
import { TableSkeleton } from "@/components/shared/skeletons";
import { EmptyState } from "@/components/shared/empty-state";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";

export function RecentScans() {
  const { data, loading, error } = useAsync(getHistory, []);

  if (loading) return <TableSkeleton columns={4} rows={5} />;
  if (error) return <EmptyState title="Could not load recent scans." />;

  const scans = (data ?? []).filter((h) => h.kind === "tls_scan").slice(0, 5);

  if (scans.length === 0) {
    return (
      <EmptyState
        icon={<History className="h-6 w-6" />}
        title="No analyses yet"
        description="Run your first TLS analysis with the form above."
      />
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Recent Analyses</CardTitle>
      </CardHeader>
      <CardContent className="p-0">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Target</TableHead>
              <TableHead>Date</TableHead>
              <TableHead className="text-right">Score</TableHead>
              <TableHead className="w-8" />
            </TableRow>
          </TableHeader>
          <TableBody>
            {scans.map((scan) => (
              <TableRow key={scan.id} className="cursor-pointer hover:bg-accent/40">
                <TableCell className="font-mono text-sm">{scan.target}</TableCell>
                <TableCell className="text-sm text-muted-foreground">{formatDateTime(scan.date)}</TableCell>
                <TableCell className="text-right">
                  {scan.score !== null ? (
                    <Badge
                      variant="outline"
                      className={
                        scan.score >= 85
                          ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-400"
                          : scan.score >= 65
                            ? "border-amber-500/40 bg-amber-500/10 text-amber-400"
                            : "border-red-500/40 bg-red-500/10 text-red-400"
                      }
                    >
                      {scan.score}/100
                    </Badge>
                  ) : (
                    <StatusBadge status="warning" showIcon={false} />
                  )}
                </TableCell>
                <TableCell>
                  <Link href={`/scanner/${scan.id}`} aria-label={`Open analysis ${scan.id}`}>
                    <ChevronRight className="h-4 w-4 text-muted-foreground" />
                  </Link>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  );
}
