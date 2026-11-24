"use client";

import { useMemo, useState } from "react";
import Link from "next/link";
import { ArrowUpDown, ChevronLeft, ChevronRight, Server } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { StatusBadge } from "@/components/shared/status-badge";
import { TableSkeleton } from "@/components/shared/skeletons";
import { EmptyState } from "@/components/shared/empty-state";
import { relativeTime } from "@/lib/format";
import { cn } from "@/lib/utils";
import { useAsync } from "@/hooks/use-async";
import { useDebouncedValue } from "@/hooks/use-debounce";
import { getServices } from "@/services/servicesService";
import type { SecurityStatus } from "@/types/severity";

type SortKey = "name" | "host" | "port" | "tlsVersion" | "vulnerabilityCount";

function SortHeader({
  label,
  k,
  sortBy,
  onToggle,
}: {
  label: string;
  k: SortKey;
  sortBy: SortKey;
  onToggle: (key: SortKey) => void;
}) {
  return (
    <button className="flex items-center gap-1 hover:text-foreground" onClick={() => onToggle(k)}>
      {label}
      <ArrowUpDown className={sortBy === k ? "h-3 w-3 text-primary" : "h-3 w-3 text-muted-foreground/50"} />
    </button>
  );
}

export function ServicesTable() {
  const [search, setSearch] = useState("");
  const debouncedSearch = useDebouncedValue(search);
  const [status, setStatus] = useState<SecurityStatus | "all">("all");
  const [scope, setScope] = useState<"internal" | "external" | "all">("all");
  const [tlsVersion, setTlsVersion] = useState<string>("all");
  const [sortBy, setSortBy] = useState<SortKey>("name");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("asc");
  const [page, setPage] = useState(1);
  const pageSize = 10;

  const { data, loading, error } = useAsync(
    () =>
      getServices({
        search: debouncedSearch || undefined,
        status,
        scope,
        tlsVersion: tlsVersion === "all" ? undefined : tlsVersion,
        page,
        pageSize,
      }),
    [debouncedSearch, status, scope, tlsVersion, page],
  );

  const tlsVersions = useMemo(() => ["TLS 1.3", "TLS 1.2", "TLS 1.1", "TLS 1.0"], []);

  const totalPages = useMemo(() => (data ? Math.max(1, Math.ceil(data.total / pageSize)) : 1), [data]);

  function toggleSort(key: SortKey) {
    if (sortBy === key) setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    else {
      setSortBy(key);
      setSortDir("asc");
    }
  }

  function sorted(items: NonNullable<typeof data>["items"]) {
    return [...items].sort((a, b) => {
      let cmp = 0;
      if (sortBy === "name") cmp = a.name.localeCompare(b.name);
      else if (sortBy === "host") cmp = a.host.localeCompare(b.host);
      else if (sortBy === "port") cmp = a.port - b.port;
      else if (sortBy === "tlsVersion") cmp = b.tlsVersion.localeCompare(a.tlsVersion);
      else cmp = a.vulnerabilityCount - b.vulnerabilityCount;
      return sortDir === "asc" ? cmp : -cmp;
    });
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <Input
          value={search}
          onChange={(e) => {
            setSearch(e.target.value);
            setPage(1);
          }}
          placeholder="Search host, name, IP..."
          className="h-8 w-64"
        />
        <Select value={status} onValueChange={(v) => { setStatus(v as SecurityStatus | "all"); setPage(1); }}>
          <SelectTrigger className="h-8 w-36">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">Status: All</SelectItem>
            <SelectItem value="secure">Secure</SelectItem>
            <SelectItem value="warning">Warning</SelectItem>
            <SelectItem value="critical">Critical</SelectItem>
          </SelectContent>
        </Select>
        <Select value={scope} onValueChange={(v) => { setScope(v as typeof scope); setPage(1); }}>
          <SelectTrigger className="h-8 w-32">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">Scope: All</SelectItem>
            <SelectItem value="internal">Internal</SelectItem>
            <SelectItem value="external">External</SelectItem>
          </SelectContent>
        </Select>
        <Select value={tlsVersion} onValueChange={(v) => { setTlsVersion(v); setPage(1); }}>
          <SelectTrigger className="h-8 w-32">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">TLS: All</SelectItem>
            {tlsVersions.map((v) => (
              <SelectItem key={v} value={v}>{v}</SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {loading ? (
        <TableSkeleton columns={6} rows={8} />
      ) : error ? (
        <EmptyState title="Could not load services." />
      ) : data && data.items.length === 0 ? (
        <EmptyState
          icon={<Server className="h-6 w-6" />}
          title="No services found"
          description="Adjust the filters or run a discovery to populate the inventory."
        />
      ) : (
        <div className="overflow-x-auto rounded-lg border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead><SortHeader label="Service" k="name" sortBy={sortBy} onToggle={toggleSort} /></TableHead>
                <TableHead><SortHeader label="Host" k="host" sortBy={sortBy} onToggle={toggleSort} /></TableHead>
                <TableHead>Endpoint</TableHead>
                <TableHead><SortHeader label="TLS" k="tlsVersion" sortBy={sortBy} onToggle={toggleSort} /></TableHead>
                <TableHead>Certificate</TableHead>
                <TableHead>Vulnerabilities</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Last Seen</TableHead>
                <TableHead className="w-8" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {sorted(data?.items ?? []).map((s) => (
                <TableRow key={s.id} className="hover:bg-accent/40">
                  <TableCell>
                    <div className="flex items-center gap-2">
                      <Link href={`/services/${s.id}`} className="text-sm font-medium hover:underline">
                        {s.name}
                      </Link>
                      <Badge
                        variant="outline"
                        className={
                          s.scope === "internal"
                            ? "border-amber-500/40 bg-amber-500/10 text-amber-500"
                            : "border-sky-500/40 bg-sky-500/10 text-sky-400"
                        }
                      >
                        {s.scope === "internal" ? "Internal" : "External"}
                      </Badge>
                    </div>
                    <p className="text-[11px] text-muted-foreground">{s.service}</p>
                  </TableCell>
                  <TableCell className="font-mono text-xs text-muted-foreground">{s.host}</TableCell>
                  <TableCell className="font-mono text-xs text-muted-foreground">
                    {s.ipAddress}:{s.port}
                  </TableCell>
                  <TableCell>
                    <Badge
                      variant="outline"
                      className={cn(
                        s.tlsVersion === "TLS 1.3"
                          ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-400"
                          : s.tlsVersion === "TLS 1.2"
                            ? "border-sky-500/40 bg-sky-500/10 text-sky-400"
                            : "border-red-500/40 bg-red-500/10 text-red-400",
                      )}
                    >
                      {s.tlsVersion}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <Link
                      href={`/certificates/${s.certificateId}`}
                      className="max-w-[180px] truncate font-mono text-xs text-muted-foreground hover:text-foreground hover:underline"
                    >
                      {s.certificateDomain}
                    </Link>
                  </TableCell>
                  <TableCell className="text-sm text-muted-foreground">{s.vulnerabilityCount}</TableCell>
                  <TableCell><StatusBadge status={s.securityStatus} /></TableCell>
                  <TableCell className="text-xs text-muted-foreground">{relativeTime(s.lastSeen)}</TableCell>
                  <TableCell>
                    <Button variant="ghost" size="sm" asChild>
                      <Link href={`/services/${s.id}`}>View</Link>
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}

      <div className="flex items-center justify-between">
        <p className="text-xs text-muted-foreground">
          {data ? `Showing ${data.items.length} of ${data.total} services` : " "}
        </p>
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
    </div>
  );
}
