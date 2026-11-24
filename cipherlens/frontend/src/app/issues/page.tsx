"use client";

import { useState, useEffect, useCallback } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { useRole } from "@/components/auth/AuthContext";
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
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Loader2 } from "lucide-react";

const STATUS_VALUES = [
  "open",
  "assigned",
  "in_progress",
  "resolved",
  "verified",
  "risk_accepted",
  "false_positive",
];

export default function IssuesPage() {
  const { canAssign } = useRole();
  const router = useRouter();
  const [issues, setIssues] = useState<Issue[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState<string>("");
  const [severityFilter, setSeverityFilter] = useState<string>("");
  const [tab, setTab] = useState<"all" | "mine">("all");
  const pageSize = 25;

  useEffect(() => {
    if (!canAssign) {
      router.push("/dashboard");
      return;
    }
  }, [canAssign, router]);

  const loadIssues = useCallback(async () => {
    setLoading(true);
    try {
      const data = await listIssues({
        status: statusFilter || undefined,
        severity: severityFilter || undefined,
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
  }, [page, statusFilter, severityFilter]);

  useEffect(() => {
    if (canAssign) {
      void loadIssues();
    }
  }, [canAssign, loadIssues]);

  const updateStatus = async (issueId: string, status: string) => {
    try {
      await updateIssue(issueId, { status });
      await loadIssues();
    } catch (err) {
      alert(err instanceof Error ? err.message : "Error updating issue");
    }
  };

  if (!canAssign) return null;

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between">
        <CardTitle>Issues</CardTitle>
        <span className="text-sm text-muted-foreground">{total} total</span>
      </CardHeader>
      <CardContent>
        <Tabs value={tab} onValueChange={(v) => { setTab(v as "all" | "mine"); setPage(1); }}>
          <TabsList className="mb-4">
            <TabsTrigger value="all">Todas</TabsTrigger>
          </TabsList>

          <TabsContent value="all">
            <Filters statusFilter={statusFilter} setStatusFilter={setStatusFilter} setPage={setPage} severityFilter={severityFilter} setSeverityFilter={setSeverityFilter} />
            <IssuesTable issues={issues} loading={loading} total={total} page={page} setPage={setPage} pageSize={pageSize} updateStatus={updateStatus} />
          </TabsContent>
        </Tabs>
      </CardContent>
    </Card>
  );
}

function Filters({
  statusFilter,
  setStatusFilter,
  setPage,
  severityFilter,
  setSeverityFilter,
}: {
  statusFilter: string;
  setStatusFilter: (v: string) => void;
  setPage: (p: number) => void;
  severityFilter: string;
  setSeverityFilter: (v: string) => void;
}) {
  return (
    <div className="mb-4 flex gap-2">
      <Select
        value={statusFilter || "all"}
        onValueChange={(v) => {
          setStatusFilter(v === "all" ? "" : v);
          setPage(1);
        }}
      >
        <SelectTrigger className="w-40">
          <SelectValue placeholder="Status" />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="all">All Status</SelectItem>
          {STATUS_VALUES.map((s) => (
            <SelectItem key={s} value={s}>
              {statusLabel(s)}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      <Select
        value={severityFilter || "all"}
        onValueChange={(v) => {
          setSeverityFilter(v === "all" ? "" : v);
          setPage(1);
        }}
      >
        <SelectTrigger className="w-40">
          <SelectValue placeholder="Severity" />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="all">All Severity</SelectItem>
          <SelectItem value="critical">Critical</SelectItem>
          <SelectItem value="high">High</SelectItem>
          <SelectItem value="medium">Medium</SelectItem>
          <SelectItem value="low">Low</SelectItem>
        </SelectContent>
      </Select>
    </div>
  );
}

function IssuesTable({
  issues,
  loading,
  total,
  page,
  setPage,
  pageSize,
  updateStatus,
}: {
  issues: Issue[];
  loading: boolean;
  total: number;
  page: number;
  setPage: (p: number) => void;
  pageSize: number;
  updateStatus: (id: string, status: string) => Promise<void>;
}) {
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  return (
    <>
      {loading ? (
        <div className="flex justify-center py-8">
          <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
        </div>
      ) : issues.length === 0 ? (
        <p className="py-8 text-center text-muted-foreground">No issues found.</p>
      ) : (
        <div className="overflow-x-auto rounded-lg border">
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
        </div>
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
            Page {page} of {totalPages}
          </span>
          <Button
            size="sm"
            variant="outline"
            disabled={page >= totalPages}
            onClick={() => setPage(page + 1)}
          >
            Next
          </Button>
        </div>
      )}
    </>
  );
}
