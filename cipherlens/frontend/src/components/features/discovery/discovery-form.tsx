"use client";

import { useRef, useState } from "react";
import { ChevronDown, Loader2, Radar, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { ScanProgressTerminal } from "@/components/features/scanner/scan-terminal";
import { ExecutorSelect } from "@/components/features/executor/executor-select";
import { cancelDiscovery, DiscoveryCancelledError, runDiscovery } from "@/services/discoveryService";
import {
  CloudAuthorizationCancelledError,
  cloudAuthorizationFields,
  type CloudAuthorizationFields,
} from "@/services/cloudAuthorization";
import { isPrivateHost, isPrivateRange } from "@/lib/target";
import { cn } from "@/lib/utils";
import type { DiscoveryProgressStep, DiscoveryResult } from "@/types/discovery";
import type { ExecutorSelection } from "@/types/agent";

const DISCOVERY_STEPS = [
  { label: "Resolving IP range / domains", detail: "Expanding CIDR and resolving DNS names" },
  { label: "Scanning hosts", detail: "Sending TCP connection probes" },
  { label: "Detecting services", detail: "Identifying open ports and protocols" },
  { label: "Performing TLS handshakes", detail: "Probing TLS on secure ports" },
  { label: "Fingerprinting OS / service", detail: "Matching banners and handshake signatures" },
  { label: "Matching declared inventory", detail: "Flagging inventoried vs shadow IT" },
  { label: "Generating discovery report", detail: "Compiling assets and flags" },
];

/** Deriva el estado de cada paso a partir del porcentaje real que reporta el backend. */
function stepsFromProgress(percent: number): DiscoveryProgressStep[] {
  const total = DISCOVERY_STEPS.length;
  return DISCOVERY_STEPS.map((step, i) => {
    const upper = ((i + 1) / total) * 100;
    const lower = (i / total) * 100;
    const state = percent >= upper ? "done" : percent > lower ? "running" : "pending";
    return { ...step, state };
  });
}

function isAbortError(err: unknown): boolean {
  return err instanceof Error && err.name === "AbortError";
}

export function DiscoveryForm({ onComplete }: { onComplete: (results: DiscoveryResult[]) => void }) {
  const [ipRange, setIpRange] = useState("");
  const [ports, setPorts] = useState("443, 8080, 8000, 4443");
  const [domains, setDomains] = useState("");
  const [scanInternal, setScanInternal] = useState(false);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [phase, setPhase] = useState<"idle" | "running" | "done" | "error">("idle");
  const [steps, setSteps] = useState<DiscoveryProgressStep[]>([]);
  const [progress, setProgress] = useState(0);
  const [status, setStatus] = useState("");
  const [error, setError] = useState<string | null>(null);
  const abortRef = useRef<AbortController | null>(null);
  const jobIdRef = useRef<string | null>(null);
  const [executor, setExecutor] = useState<ExecutorSelection>({ type: "cloud" });
  const targetIsPrivate =
    isPrivateRange(ipRange) ||
    domains
      .split(/[\n,;]/)
      .map((domain) => domain.trim())
      .filter(Boolean)
      .some(isPrivateHost);
  const privateBlocked = targetIsPrivate && (executor.type !== "agent" || !executor.agentId);

  function resetProgress() {
    setProgress(0);
    setStatus("");
    setSteps(DISCOVERY_STEPS.map((s) => ({ ...s, state: "pending" })));
  }

  async function handleStart() {
    if (phase === "running") return;
    if (!ipRange.trim() && !domains.trim()) {
      setError("Enter an IP range/CIDR or a domain list to scan.");
      return;
    }
    if (privateBlocked) {
      setError("Private ranges must run from an enrolled on-prem agent. Select one or enroll an agent first.");
      return;
    }

    const portList = ports
      .split(",")
      .map((p) => parseInt(p.trim(), 10))
      .filter((p) => !Number.isNaN(p) && p > 0 && p < 65536);

    const domainList = domains
      .split(/[\n,;]/)
      .map((d) => d.trim())
      .filter(Boolean);

    setError(null);

    let authorization: CloudAuthorizationFields | undefined;
    if (executor.type === "cloud") {
      try {
        authorization = await cloudAuthorizationFields({ alwaysPrompt: true });
      } catch (err) {
        if (err instanceof CloudAuthorizationCancelledError) {
          setError("Discovery not started: accept the authorization statement to continue.");
        } else {
          setError(err instanceof Error ? err.message : "Cloud discovery authorization failed.");
        }
        return;
      }
    }

    const controller = new AbortController();
    abortRef.current = controller;

    setPhase("running");
    setProgress(0);
    setStatus("queued");
    setSteps(DISCOVERY_STEPS.map((s) => ({ ...s, state: "pending" })));

    try {
      const results = await runDiscovery(
        { ipRange: ipRange.trim(), ports: portList, domains: domainList, scanInternal, executor },
        {
          signal: controller.signal,
          onJobCreated: (id) => {
            jobIdRef.current = id;
          },
          onProgress: (p) => {
            setProgress(p.progress);
            setStatus(`${p.status} · ${p.totalFound} found`);
            setSteps(stepsFromProgress(p.progress));
          },
        },
        authorization,
      );
      setProgress(100);
      setStatus(`completed · ${results.length} found`);
      setSteps(DISCOVERY_STEPS.map((s) => ({ ...s, state: "done" })));
      setPhase("done");
      onComplete(results);
    } catch (err) {
      if (err instanceof CloudAuthorizationCancelledError) {
        setPhase("idle");
        setError("Discovery not started: accept the authorization statement to continue.");
        resetProgress();
        return;
      }
      if (isAbortError(err) || err instanceof DiscoveryCancelledError) {
        setPhase("idle");
        setError(null);
        resetProgress();
        return;
      }
      setPhase("error");
      setSteps((prev) => prev.map((s) => ({ ...s, state: "error" })));
      setError(err instanceof Error ? err.message : "Discovery failed.");
    } finally {
      abortRef.current = null;
      jobIdRef.current = null;
    }
  }

  function handleCancel() {
    // Primero se le avisa al backend que frene el scan; despues se corta el polling.
    // Al reves, el worker seguiria gastando CPU en los hosts restantes.
    const jobId = jobIdRef.current;
    if (jobId) void cancelDiscovery(jobId);
    abortRef.current?.abort();
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <Radar className="h-4 w-4 text-primary" />
          Network Discovery
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid gap-4 sm:grid-cols-2">
          <div className="space-y-1.5">
            <Label htmlFor="ip-range">IP Range / CIDR</Label>
            <Input
              id="ip-range"
              value={ipRange}
              onChange={(e) => setIpRange(e.target.value)}
              placeholder="8.8.8.0/24 (public targets only)"
              className="font-mono"
              disabled={phase === "running"}
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="ports">Port list</Label>
            <Input
              id="ports"
              value={ports}
              onChange={(e) => setPorts(e.target.value)}
              placeholder="443, 8080, 8000, 4443"
              className="font-mono"
              disabled={phase === "running"}
            />
          </div>
        </div>

        <ExecutorSelect
          value={executor}
          onChange={setExecutor}
          targetIsPrivate={targetIsPrivate}
          disabled={phase === "running"}
        />

        <div className="space-y-1.5">
          <Label htmlFor="domains">Domain list (optional)</Label>
          <Textarea
            id="domains"
            value={domains}
            onChange={(e) => setDomains(e.target.value)}
            placeholder={"example.com\napi.example.com\nlegacy.internal.company.com"}
            rows={3}
            className="font-mono"
            disabled={phase === "running"}
          />
          <p className="text-xs text-muted-foreground">
            Alternatively load a file with domains — one per line.
          </p>
        </div>

        <Collapsible open={showAdvanced} onOpenChange={setShowAdvanced}>
          <CollapsibleTrigger className="flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground">
            <ChevronDown className={cn("h-4 w-4 transition-transform", showAdvanced && "rotate-180")} />
            Advanced Options
          </CollapsibleTrigger>
          <CollapsibleContent className="mt-3 flex items-center gap-3">
            <Label className="text-sm">Scan internal range</Label>
            <Switch
              checked={scanInternal}
              onCheckedChange={setScanInternal}
              disabled={executor.type !== "agent"}
            />
            <span className="text-xs text-muted-foreground">
              Internal scans require an enrolled on-prem agent; the cloud scanner only reaches public ranges.
            </span>
          </CollapsibleContent>
        </Collapsible>

        <div className="flex items-center gap-2">
          <Button onClick={handleStart} disabled={phase === "running" || privateBlocked} className="gap-2">
            {phase === "running" ? <Loader2 className="h-4 w-4 animate-spin" /> : <Radar className="h-4 w-4" />}
            {phase === "running" ? "Discovering..." : "Start Discovery"}
          </Button>
          {phase === "running" && (
            <Button onClick={handleCancel} variant="outline" className="gap-2">
              <X className="h-4 w-4" />
              Cancel
            </Button>
          )}
        </div>

        {error && (
          <Alert variant="destructive">
            <AlertTitle>Error</AlertTitle>
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        {phase === "running" && (
          <ScanProgressTerminal steps={steps} progress={progress} status={status} />
        )}
      </CardContent>
    </Card>
  );
}
