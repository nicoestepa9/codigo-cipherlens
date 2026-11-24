"use client";

import { useMemo, useState } from "react";
import Link from "next/link";
import { ArrowUpDown, ChevronLeft, ChevronRight, ShieldCheck } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { CertStatusBadge } from "@/components/shared/cert-status-badge";
import { TableSkeleton } from "@/components/shared/skeletons";
import { EmptyState } from "@/components/shared/empty-state";
import { formatDate } from "@/lib/format";
import { useAsync } from "@/hooks/use-async";
import { useDebouncedValue } from "@/hooks/use-debounce";
import { useSettings } from "@/context/settings-context";
import { getCertificates, getIssuerOptionsService } from "@/services/certificatesService";
import type { CertificateStatus, Origin } from "@/types/severity";

type SortKey = "domain" | "daysUntilExpiry" | "notAfter" | "issuerName";

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
    <button className="flex items-center gap-1 hover:text-foreground" onClick={() => onToggle(k)} aria-label={`Sort by ${label}`}>
      {label}
      <ArrowUpDown className={sortBy === k ? "h-3 w-3 text-primary" : "h-3 w-3 text-muted-foreground/50"} />
    </button>
  );
}

export function CertificatesTable() {
  const { settings } = useSettings();
  const { criticalDays, warningDays } = settings.thresholds;
  const [search, setSearch] = useState("");
  const debouncedSearch = useDebouncedValue(search);
  const [status, setStatus] = useState<CertificateStatus | "all">("all");
  const [issuer, setIssuer] = useState<string>("all");
  const [origin, setOrigin] = useState<Origin | "all">("all");
  const [scope, setScope] = useState<"internal" | "external" | "all">("all");
  const [sortBy, setSortBy] = useState<SortKey>("daysUntilExpiry");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("asc");
  const [page, setPage] = useState(1);

  const pageSize = 12;

  const { data: issuers } = useAsync(getIssuerOptionsService, []);

  const { data, loading, error } = useAsync(
    () =>
      getCertificates({
        search: debouncedSearch || undefined,
        status,
        issuer: issuer === "all" ? undefined : issuer,
        origin,
        scope,
        sortBy,
        sortDir,
        page,
        pageSize,
      }),
    [debouncedSearch, status, issuer, origin, scope, sortBy, sortDir, page],
  );

  const totalPages = useMemo(() => (data ? Math.max(1, Math.ceil(data.total / pageSize)) : 1), [data]);

  function toggleSort(key: SortKey) {
    if (sortBy === key) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortBy(key);
      setSortDir("asc");
    }
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
          placeholder="Search domain, issuer, serial..."
          className="h-8 w-64"
        />
        <Select value={status} onValueChange={(v) => { setStatus(v as CertificateStatus | "all"); setPage(1); }}>
          <SelectTrigger className="h-8 w-36">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">Status: All</SelectItem>
            <SelectItem value="valid">Valid</SelectItem>
            <SelectItem value="expiring_soon">Expiring Soon</SelectItem>
            <SelectItem value="expired">Expired</SelectItem>
          </SelectContent>
        </Select>
        <Select value={issuer} onValueChange={(v) => { setIssuer(v); setPage(1); }}>
          <SelectTrigger className="h-8 w-44">
            <SelectValue placeholder="Issuer" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">Issuer: All</SelectItem>
            {(issuers ?? []).map((i) => (
              <SelectItem key={i} value={i}>{i}</SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={origin} onValueChange={(v) => { setOrigin(v as Origin | "all"); setPage(1); }}>
          <SelectTrigger className="h-8 w-36">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">Origin: All</SelectItem>
            <SelectItem value="discovered">Discovered</SelectItem>
            <SelectItem value="manual">Manual load</SelectItem>
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
      </div>

      {loading ? (
        <TableSkeleton columns={7} rows={8} />
      ) : error ? (
        <EmptyState title="Could not load certificates." />
      ) : data && data.items.length === 0 ? (
        <EmptyState
          icon={<ShieldCheck className="h-6 w-6" />}
          title="No certificates found"
          description="Adjust the filters or run a discovery to populate the inventory."
        />
      ) : (
        <div className="overflow-x-auto rounded-lg border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead><SortHeader label="Certificate" k="domain" sortBy={sortBy} onToggle={toggleSort} /></TableHead>
                <TableHead>Issuer</TableHead>
                <TableHead>Expires</TableHead>
                <TableHead className="text-right"><SortHeader label="Days Left" k="daysUntilExpiry" sortBy={sortBy} onToggle={toggleSort} /></TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Origin</TableHead>
                <TableHead className="w-8" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {(data?.items ?? []).map((cert) => (
                <TableRow key={cert.id} className="hover:bg-accent/40">
                  <TableCell>
                    <Link href={`/certificates/${cert.id}`} className="block max-w-[240px]">
                      <p className="truncate font-mono text-sm font-medium text-foreground hover:underline">{cert.domain}</p>
                      <p className="truncate font-mono text-[11px] text-muted-foreground">{cert.san.length} SANs</p>
                    </Link>
                  </TableCell>
                  <TableCell className="max-w-[200px] truncate text-sm text-muted-foreground">{cert.issuerName}</TableCell>
                  <TableCell className="text-sm text-muted-foreground">{formatDate(cert.notAfter)}</TableCell>
                  <TableCell className="text-right">
                    <Badge
                      variant="outline"
                      className={
                        cert.daysUntilExpiry < 0
                          ? "border-red-500/40 bg-red-500/10 text-red-400"
                          : cert.daysUntilExpiry <= criticalDays
                            ? "border-amber-500/40 bg-amber-500/10 text-amber-400"
                            : cert.daysUntilExpiry <= warningDays
                              ? "border-sky-500/40 bg-sky-500/10 text-sky-400"
                              : "border-muted text-muted-foreground"
                      }
                    >
                      {cert.daysUntilExpiry < 0 ? `${cert.daysUntilExpiry}d` : `${cert.daysUntilExpiry}d`}
                    </Badge>
                  </TableCell>
                  <TableCell><CertStatusBadge status={cert.status} /></TableCell>
                  <TableCell>
                    <Badge
                      variant="outline"
                      className={
                        cert.origin === "discovered"
                          ? "border-sky-500/40 bg-sky-500/10 text-sky-400"
                          : "border-violet-500/40 bg-violet-500/10 text-violet-400"
                      }
                    >
                      {cert.origin === "discovered" ? "Discovered" : "Manual"}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <Button variant="ghost" size="sm" asChild>
                      <Link href={`/certificates/${cert.id}`}>View</Link>
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
          {data ? `Showing ${data.items.length} of ${data.total} certificates` : " "}
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
