"use client";

import { useState, useEffect, useCallback } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { useAuth } from "@/components/auth/AuthContext";
import { listIssues, updateIssue } from "@/services/issuesService";
import { statusLabel, actionOptions } from "@/types/issue";
import type { Issue } from "@/types/issue";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { IssueSeverityBadge, IssueStatusBadge } from "@/components/shared/issue-badges";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Loader2 } from "lucide-react";

export default function MyIssuesPage() {
  const { isAuthenticated, user } = useAuth();
  const router = useRouter();
  const [issues, setIssues] = useState<Issue[]>([]);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const pageSize = 25;
  const [total, setTotal] = useState(0);

  useEffect(() => {
    if (!isAuthenticated) {
      router.push("/login?next=/my-issues");
    }
  }, [isAuthenticated, router]);

  const loadIssues = useCallback(async () => {
    if (!user) return;
    setLoading(true);
    try {
      const data = await listIssues({
        mine: true,
        page,
        pageSize,
      });
      setIssues(data.items);
      setTotal(data.total);
    } catch {
      // ignore
    } finally {
      setLoading(false);
    }
  }, [page, user]);

  useEffect(() => {
    if (isAuthenticated && user) {
      void loadIssues();
    }
  }, [isAuthenticated, user, loadIssues]);

  const updateStatus = async (issueId: string, status: string) => {
    try {
      await updateIssue(issueId, { status });
      await loadIssues();
    } catch (err) {
      alert(err instanceof Error ? err.message : "Error updating issue");
    }
  };

  if (!isAuthenticated) return null;

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between">
        <CardTitle>My Issues</CardTitle>
        <span className="text-sm text-muted-foreground">{total} total</span>
      </CardHeader>
      <CardContent>
        {loading ? (
          <div className="flex justify-center py-8">
            <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
          </div>
        ) : issues.length === 0 ? (
          <p className="py-8 text-center text-muted-foreground">
            No issues assigned to you or your teams.
          </p>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Título</TableHead>
                <TableHead>Host</TableHead>
                <TableHead>Severidad</TableHead>
                <TableHead>Estado</TableHead>
                <TableHead>Owner</TableHead>
                <TableHead>Vencido</TableHead>
                <TableHead>Acciones</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {issues.map((issue) => (
                <TableRow key={issue.id}>
                  <TableCell className="max-w-md truncate font-medium">
                    <Link
                      href={`/issues/${issue.id}`}
                      className="hover:underline"
                    >
                      {issue.title}
                    </Link>
                  </TableCell>
                  <TableCell className="whitespace-nowrap text-sm text-muted-foreground">
                    {issue.serviceHost
                      ? `${issue.serviceHost}${issue.servicePort ? `:${issue.servicePort}` : ""}`
                      : "—"}
                  </TableCell>
                  <TableCell>
                    <IssueSeverityBadge severity={issue.severity} />
                  </TableCell>
                  <TableCell>
                    <IssueStatusBadge status={issue.status} />
                  </TableCell>
                  <TableCell>
                    {issue.ownerName || (
                      <span className="text-muted-foreground">—</span>
                    )}
                  </TableCell>
                  <TableCell>
                    {issue.isOverdue ? (
                      <Badge variant="destructive">Overdue</Badge>
                    ) : (
                      <span className="text-muted-foreground">—</span>
                    )}
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      <Select
                        value={issue.status}
                        onValueChange={(v) => void updateStatus(issue.id, v)}
                      >
                        <SelectTrigger className="h-8 w-40">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          {actionOptions(issue.status).map((s) => (
                            <SelectItem key={s} value={s}>
                              {statusLabel(s)}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                      <Button size="sm" variant="ghost" asChild>
                        <Link href={`/issues/${issue.id}`}>Detalle</Link>
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}

        {total > pageSize && (
          <div className="mt-4 flex items-center justify-between">
            <Button
              size="sm"
              variant="outline"
              disabled={page <= 1}
              onClick={() => setPage(page - 1)}
            >
              Previous
            </Button>
            <span className="text-sm text-muted-foreground">
              Page {page} of {Math.ceil(total / pageSize)}
            </span>
            <Button
              size="sm"
              variant="outline"
              disabled={page >= Math.ceil(total / pageSize)}
              onClick={() => setPage(page + 1)}
            >
              Next
            </Button>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
