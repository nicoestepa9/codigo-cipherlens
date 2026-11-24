"use client";

import Link from "next/link";
import { ArrowLeft, Download, Plus, RotateCcw } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { StatusBadge } from "@/components/shared/status-badge";
import { formatDateTime, formatDuration } from "@/lib/format";
import type { ScanResult } from "@/types/scan";

function scoreBadgeClass(score: number) {
  return score >= 85
    ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-400"
    : score >= 65
      ? "border-amber-500/40 bg-amber-500/10 text-amber-400"
      : "border-red-500/40 bg-red-500/10 text-red-400";
}

export function ResultHeader({ scan }: { scan: ScanResult }) {
  function downloadJson() {
    const blob = new Blob([JSON.stringify(scan, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${scan.host}_${scan.port}_${new Date(scan.scanStartedAt).toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="mb-6 space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <Button variant="ghost" size="sm" asChild className="gap-1.5 px-2">
          <Link href="/scanner">
            <ArrowLeft className="h-4 w-4" /> Back
          </Link>
        </Button>
        <h1 className="min-w-0 flex-1 truncate font-mono text-2xl font-semibold tracking-tight">
          TLS Analysis — {scan.host}
        </h1>
        {scan.status === "failed" || scan.connectionError ? (
          <Badge variant="destructive">Scan failed</Badge>
        ) : (
          <>
            <StatusBadge status={scan.status} />
            <Badge variant="outline" className={scoreBadgeClass(scan.score)}>
              Score {scan.score}/100
            </Badge>
          </>
        )}
      </div>

      <div className="grid grid-cols-2 gap-3 text-sm sm:grid-cols-3 lg:grid-cols-6">
        <div>
          <p className="text-xs text-muted-foreground">Target</p>
          <p className="font-mono">{scan.target}</p>
        </div>
        <div>
          <p className="text-xs text-muted-foreground">IP Address</p>
          <p className="font-mono">{scan.ipAddress}</p>
        </div>
        <div>
          <p className="text-xs text-muted-foreground">Port used</p>
          <p className="font-mono">
            {scan.port}
            {scan.portIsAlternate && (
              <Badge variant="outline" className="ml-1.5 border-sky-500/40 bg-sky-500/10 px-1.5 py-0 text-[10px] text-sky-400">
                alternate
              </Badge>
            )}
          </p>
        </div>
        <div>
          <p className="text-xs text-muted-foreground">Scan date</p>
          <p>{formatDateTime(scan.scanStartedAt)}</p>
        </div>
        <div>
          <p className="text-xs text-muted-foreground">Duration</p>
          <p>{formatDuration(scan.scanDurationMs)}</p>
        </div>
        <div>
          <p className="text-xs text-muted-foreground">Profile</p>
          <p className="font-mono">{scan.profile}</p>
        </div>
      </div>

      <div className="flex flex-wrap gap-2">
        <Button size="sm" asChild className="gap-1.5">
          <Link href="/scanner">
            <Plus className="h-4 w-4" /> New Scan
          </Link>
        </Button>
        <Button size="sm" variant="outline" asChild className="gap-1.5">
          <Link href="/scanner">
            <RotateCcw className="h-4 w-4" /> Re-scan
          </Link>
        </Button>
        <Button size="sm" variant="outline" className="gap-1.5" onClick={downloadJson}>
          <Download className="h-4 w-4" /> Export JSON
        </Button>
      </div>
    </div>
  );
}
