"use client";

import { useMemo, useState } from "react";
import { ChevronDown, FileSearch, ShieldAlert, AlertTriangle, Bug } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { SeverityBadge } from "@/components/shared/severity-badge";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { EmptyState } from "@/components/shared/empty-state";
import type { ScanResult } from "@/types/scan";
import type { Severity } from "@/types/severity";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

function cvssColor(score?: number | null): string {
  if (score == null) return "text-muted-foreground";
  if (score >= 9.0) return "text-red-500";
  if (score >= 7.0) return "text-orange-500";
  if (score >= 4.0) return "text-yellow-500";
  return "text-muted-foreground";
}

export function FindingsTab({ scan }: { scan: ScanResult }) {
  const [filter, setFilter] = useState<Severity | "all">("all");

  const counts = useMemo(() => {
    const map: Record<string, number> = { all: scan.findings.length };
    for (const s of SEVERITIES) map[s] = scan.findings.filter((f) => f.severity === s).length;
    return map;
  }, [scan.findings]);

  const filtered = useMemo(
    () => (filter === "all" ? scan.findings : scan.findings.filter((f) => f.severity === filter)),
    [scan.findings, filter],
  );

  const liveCves = scan.liveCveMatches ?? [];
  const softwareCves = scan.softwareKnownCves;

  return (
    <div className="space-y-4">
    <Card>
      <CardHeader className="flex-row items-center justify-between gap-4">
        <CardTitle className="text-base">Security Findings</CardTitle>
        <div className="flex flex-wrap gap-1.5">
          {(["all", ...SEVERITIES] as const).map((s) => (
            <Button
              key={s}
              size="sm"
              variant={filter === s ? "default" : "outline"}
              className="h-7 px-2.5 text-xs"
              onClick={() => setFilter(s)}
            >
              {s === "all" ? "All" : s} ({counts[s]})
            </Button>
          ))}
        </div>
      </CardHeader>
      <CardContent className="p-5 pt-0">
        {filtered.length === 0 ? (
          <EmptyState
            icon={<FileSearch className="h-6 w-6" />}
            title="No findings"
            description="No security findings in this category."
          />
        ) : (
          <div className="space-y-2">
            {filtered.map((finding) => (
              <Collapsible key={finding.id}>
                <div className="rounded-lg border">
                  <div className="flex items-center gap-3 p-3">
                    <SeverityBadge severity={finding.severity} showDot={false} className="w-20 justify-center" />
                    <div className="min-w-0 flex-1">
                      <p className="truncate text-sm font-medium text-foreground">{finding.title}</p>
                      <p className="truncate text-xs text-muted-foreground">
                        <span className="font-mono">{finding.ruleId}</span>
                        <span className="mx-1.5">&bull;</span>
                        {finding.category}
                        <span className="mx-1.5">&bull;</span>
                        {finding.affectedHost}
                      </p>
                    </div>
                    {finding.relatedCves && finding.relatedCves.length > 0 && (
                      <span className="inline-flex items-center gap-1 rounded-md border border-red-500/30 bg-red-500/10 px-2 py-0.5 text-xs font-mono text-red-400 shrink-0">
                        <Bug className="h-3 w-3" />
                        {finding.relatedCves.length} CVE{finding.relatedCves.length > 1 ? "s" : ""}
                      </span>
                    )}
                    <CollapsibleTrigger className="rounded-md p-1.5 text-muted-foreground hover:bg-accent hover:text-foreground">
                      <ChevronDown className="h-4 w-4 transition-transform ui-open:rotate-180" />
                    </CollapsibleTrigger>
                  </div>
                  <CollapsibleContent>
                    <div className="space-y-3 border-t p-4">
                      <p className="text-sm text-muted-foreground">{finding.description}</p>
                      <div className="rounded-md border border-dashed bg-muted/40 p-3">
                        <p className="mb-1 text-xs font-medium text-foreground">Evidence</p>
                        <p className="font-mono text-xs text-muted-foreground">{finding.evidence}</p>
                      </div>
                      <div className="rounded-md border border-emerald-500/20 bg-emerald-500/5 p-3">
                        <p className="mb-1 text-xs font-medium text-emerald-400">Recommendation</p>
                        <p className="text-xs text-muted-foreground">{finding.recommendation}</p>
                      </div>
                      {finding.reference && (
                        <Badge variant="outline" className="text-xs">
                          {finding.reference}
                        </Badge>
                      )}
                      {finding.relatedCves && finding.relatedCves.length > 0 && (
                        <div className="rounded-md border border-red-500/20 bg-red-500/5 p-3">
                          <p className="mb-1.5 text-xs font-medium text-red-400">Related CVEs</p>
                          <div className="flex flex-wrap gap-1.5">
                            {finding.relatedCves.map((cve) => (
                              <a
                                key={cve.cveId}
                                href={cve.referenceUrl ?? `https://nvd.nist.gov/vuln/detail/${cve.cveId}`}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="inline-flex items-center gap-1 rounded-md border border-red-500/30 bg-red-500/10 px-2 py-0.5 text-xs font-mono text-red-400 hover:bg-red-500/20"
                              >
                                {cve.cveId}
                                {cve.name && <span className="font-sans text-muted-foreground">({cve.name})</span>}
                                {cve.cvssV3Score != null && (
                                  <span className={cvssColor(cve.cvssV3Score)}>{cve.cvssV3Score}</span>
                                )}
                              </a>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  </CollapsibleContent>
                </div>
              </Collapsible>
            ))}
          </div>
        )}
      </CardContent>
    </Card>

    {liveCves.length > 0 && (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <ShieldAlert className="h-4 w-4 text-orange-500" />
            Live CVE Matches (NVD)
            <Badge variant="outline" className="ml-1 text-xs">{liveCves.length}</Badge>
          </CardTitle>
          <p className="text-xs text-muted-foreground">
            Results from keyword search. May not be directly applicable to this server.
          </p>
        </CardHeader>
        <CardContent className="p-5 pt-0">
          <div className="space-y-2">
            {liveCves.map((cve) => (
              <div key={cve.cveId} className="flex items-center gap-3 rounded-lg border p-3">
                <a
                  href={`https://nvd.nist.gov/vuln/detail/${cve.cveId}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="font-mono text-sm font-medium text-orange-400 hover:underline"
                >
                  {cve.cveId}
                </a>
                {cve.cvssV3Score != null && (
                  <span className={`text-xs font-mono ${cvssColor(cve.cvssV3Score)}`}>
                    CVSS {cve.cvssV3Score}
                  </span>
                )}
                <Badge variant="outline" className="text-xs">{cve.matchType}</Badge>
                {cve.keyword && (
                  <Badge variant="outline" className="text-xs font-mono">
                    keyword: {cve.keyword}
                  </Badge>
                )}
                {cve.unverified && (
                  <Badge variant="secondary" className="flex items-center gap-1 text-xs">
                    <AlertTriangle className="h-3 w-3" />
                    unverified
                  </Badge>
                )}
                {cve.stale && <Badge variant="secondary" className="text-xs">stale</Badge>}
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    )}

    {softwareCves && softwareCves.queried && (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <ShieldAlert className="h-4 w-4 text-blue-500" />
            Software Known CVEs
            {softwareCves.cpeName && (
              <Badge variant="outline" className="ml-1 text-xs font-mono">{softwareCves.cpeName}</Badge>
            )}
          </CardTitle>
        </CardHeader>
        <CardContent className="p-5 pt-0">
          {softwareCves.matches.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              No known CVEs found for this software version in NVD.
            </p>
          ) : (
            <div className="space-y-2">
              {softwareCves.matches.map((cve) => (
                <div key={cve.cveId} className="flex items-center gap-3 rounded-lg border p-3">
                  <a
                    href={`https://nvd.nist.gov/vuln/detail/${cve.cveId}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="font-mono text-sm font-medium text-blue-400 hover:underline"
                  >
                    {cve.cveId}
                  </a>
                  {cve.cvssV3Score != null && (
                    <span className={`text-xs font-mono ${cvssColor(cve.cvssV3Score)}`}>
                      CVSS {cve.cvssV3Score}
                    </span>
                  )}
                <Badge variant="outline" className="text-xs">{cve.matchType}</Badge>
                  {cve.stale && <Badge variant="secondary" className="text-xs">stale</Badge>}
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    )}
    </div>
  );
}
