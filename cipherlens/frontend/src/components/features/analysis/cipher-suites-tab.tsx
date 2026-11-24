"use client";

import { useMemo, useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { cn } from "@/lib/utils";
import type { ScanResult } from "@/types/scan";

type Filter = "all" | "secure" | "warning" | "critical";

const STATUS_CLASS: Record<string, string> = {
  secure: "border-emerald-500/40 bg-emerald-500/10 text-emerald-400",
  warning: "border-amber-500/40 bg-amber-500/10 text-amber-400",
  critical: "border-red-500/40 bg-red-500/10 text-red-400",
};

export function CipherSuitesTab({ scan }: { scan: ScanResult }) {
  const [filter, setFilter] = useState<Filter>("all");

  const filtered = useMemo(
    () => (filter === "all" ? scan.cipherSuites : scan.cipherSuites.filter((c) => c.status === filter)),
    [scan.cipherSuites, filter],
  );

  const counts = useMemo(
    () => ({
      secure: scan.cipherSuites.filter((c) => c.status === "secure").length,
      warning: scan.cipherSuites.filter((c) => c.status === "warning").length,
      critical: scan.cipherSuites.filter((c) => c.status === "critical").length,
    }),
    [scan.cipherSuites],
  );

  const filters: { key: Filter; label: string; count: number }[] = [
    { key: "all", label: "All", count: scan.cipherSuites.length },
    { key: "secure", label: "Secure", count: counts.secure },
    { key: "warning", label: "Warning", count: counts.warning },
    { key: "critical", label: "Critical", count: counts.critical },
  ];

  return (
    <Card>
      <CardHeader className="flex-row items-center justify-between gap-4">
        <CardTitle className="text-base">Cipher Suites</CardTitle>
        <div className="flex flex-wrap gap-1.5">
          {filters.map((f) => (
            <Button
              key={f.key}
              size="sm"
              variant={filter === f.key ? "default" : "outline"}
              className="h-7 px-2.5 text-xs"
              onClick={() => setFilter(f.key)}
            >
              {f.label} ({f.count})
            </Button>
          ))}
        </div>
      </CardHeader>
      <CardContent className="p-0">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Cipher Suite</TableHead>
              <TableHead>TLS</TableHead>
              <TableHead>Key Exchange</TableHead>
              <TableHead>Encryption</TableHead>
              <TableHead className="text-right">Status</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {filtered.map((suite) => (
              <TableRow key={`${suite.protocol}-${suite.name}`} className={cn(suite.selected && "bg-accent/50")}>
                <TableCell className="font-mono text-sm">
                  {suite.name}
                  {suite.selected && (
                    <Badge variant="outline" className="ml-2 border-primary/40 bg-primary/10 text-[10px] text-primary">
                      negotiated
                    </Badge>
                  )}
                </TableCell>
                <TableCell className="font-mono text-sm text-muted-foreground">{suite.protocol}</TableCell>
                <TableCell className="font-mono text-sm text-muted-foreground">{suite.keyExchange}</TableCell>
                <TableCell className="font-mono text-sm text-muted-foreground">
                  {suite.encryption}
                  {suite.bits ? ` (${suite.bits})` : ""}
                </TableCell>
                <TableCell className="text-right">
                  <Badge variant="outline" className={cn("font-mono text-xs", STATUS_CLASS[suite.status])}>
                    {suite.status}
                  </Badge>
                </TableCell>
              </TableRow>
            ))}
            {filtered.length === 0 && (
              <TableRow>
                <TableCell colSpan={5} className="py-8 text-center text-sm text-muted-foreground">
                  No cipher suites in this category.
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  );
}
