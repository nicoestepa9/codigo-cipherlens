"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { ChevronDown, Loader2, Play } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { ScanProgressTerminal } from "./scan-terminal";
import { ExecutorSelect } from "@/components/features/executor/executor-select";
import { runScan } from "@/services/scansService";
import {
  CloudAuthorizationCancelledError,
  cloudAuthorizationFields,
  type CloudAuthorizationFields,
} from "@/services/cloudAuthorization";
import { isPrivateTarget, isValidTarget } from "@/lib/target";
import { useSettings } from "@/context/settings-context";
import { cn } from "@/lib/utils";
import type { ScanProgressStep } from "@/types/scan";
import type { ExecutorSelection } from "@/types/agent";

const SCAN_STEPS = [
  { label: "Connecting to target", detail: "Resolving DNS and opening TCP connection" },
  { label: "Performing TLS handshake", detail: "Negotiating protocol and cipher suites" },
  { label: "Extracting certificate", detail: "Parsing X.509 certificate chain" },
  { label: "Analyzing cipher suites", detail: "Testing supported protocols and ciphers" },
  { label: "Checking TLS configuration", detail: "Evaluating against NIST SP 800-52 Rev.2" },
  { label: "Generating security report", detail: "Compiling findings and recommendations" },
];

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export function ScannerForm() {
  const router = useRouter();
  const { settings } = useSettings();
  const defaults = settings.scanDefaults;

  const [target, setTarget] = useState("");
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [timeout, setTimeoutSec] = useState(defaults.timeout);
  const [sni, setSni] = useState(defaults.sni);
  const [profile, setProfile] = useState<"citizen-facing" | "government-only">(defaults.profile);
  const [cloudAlternatePorts, setCloudAlternatePorts] = useState(defaults.alternatePorts.join(", "));
  const [agentAlternatePorts, setAgentAlternatePorts] = useState("");
  const [phase, setPhase] = useState<"idle" | "running" | "done" | "error">("idle");
  const [steps, setSteps] = useState<ScanProgressStep[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [executor, setExecutor] = useState<ExecutorSelection>({ type: "cloud" });
  const alternatePorts = executor.type === "agent" ? agentAlternatePorts : cloudAlternatePorts;
  const setAlternatePorts = executor.type === "agent" ? setAgentAlternatePorts : setCloudAlternatePorts;
  const targetIsPrivate = isValidTarget(target) && isPrivateTarget(target);
  const privateBlocked = targetIsPrivate && (executor.type !== "agent" || !executor.agentId);

  async function playScanSteps(shouldStop: () => boolean) {
    for (let i = 0; i < SCAN_STEPS.length; i++) {
      if (shouldStop()) return;
      setSteps((prev) => prev.map((s, idx) => (idx === i ? { ...s, state: "running" } : s)));
      await sleep(i === 0 ? 900 : 650);
      if (shouldStop()) return;
      setSteps((prev) => prev.map((s, idx) => (idx === i ? { ...s, state: "done" } : s)));
      await sleep(150);
    }
  }

  async function handleStart() {
    if (phase === "running") return;
    if (!target.trim()) {
      setError("Enter a target host, IP or host:port.");
      return;
    }
    if (privateBlocked) {
      setError("Private targets must run from an enrolled on-prem agent. Select one or enroll an agent first.");
      return;
    }
    if (!isValidTarget(target)) {
      setError("Invalid target format. Use host, host:port or https://host.");
      return;
    }

    const ports = alternatePorts
      .split(",")
      .map((p) => parseInt(p.trim(), 10))
      .filter((p) => !Number.isNaN(p) && p > 0 && p < 65536);

    setError(null);

    let authorization: CloudAuthorizationFields | undefined;
    if (executor.type === "cloud") {
      try {
        authorization = await cloudAuthorizationFields({ alwaysPrompt: true });
      } catch (err) {
        if (err instanceof CloudAuthorizationCancelledError) {
          setError("Scan not started: accept the authorization statement to continue.");
        } else {
          setError(err instanceof Error ? err.message : "Cloud scan authorization failed.");
        }
        return;
      }
    }

    setPhase("running");
    setSteps(SCAN_STEPS.map((s) => ({ ...s, state: "pending" })));

    let failed = false;
    const scanPromise = runScan(target.trim(), {
      timeout,
      sni,
      profile,
      alternatePorts: ports,
    }, executor, authorization).then(
      (result) => ({ ok: true as const, result }),
      (scanError: unknown) => {
        failed = true;
        return { ok: false as const, error: scanError };
      },
    );

    try {
      const [outcome] = await Promise.all([
        scanPromise,
        playScanSteps(() => failed),
      ]);

      if (!outcome.ok) throw outcome.error;

      setPhase("done");
      await sleep(500);
      router.push(`/scanner/${outcome.result.id}`);
    } catch (err) {
      if (err instanceof CloudAuthorizationCancelledError) {
        setPhase("idle");
        setSteps([]);
        setError("Scan not started: accept the authorization statement to continue.");
        return;
      }
      setPhase("error");
      setError(
        err instanceof Error && err.message
          ? `The analysis failed. ${err.message}`
          : "The analysis failed. Try again or check the scan executor logs.",
      );
      setSteps((prev) => prev.map((s) => ({ ...s, state: "error" })));
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <Play className="h-4 w-4 text-primary" />
          New TLS Analysis
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid gap-3 sm:grid-cols-[1fr_auto]">
          <div className="space-y-1.5">
            <Label htmlFor="target">Target</Label>
            <Input
              id="target"
              placeholder="example.com or 192.168.1.50:443"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleStart()}
              disabled={phase === "running"}
              className="font-mono"
            />
            <p className="text-xs text-muted-foreground">
              Supports hostname, IP:port or https:// URL. Default port 443.
            </p>
          </div>
          <div className="flex items-end">
            <Button onClick={handleStart} disabled={phase === "running" || privateBlocked} className="gap-2">
              {phase === "running" ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
              {phase === "running" ? "Analyzing..." : "Start TLS Analysis"}
            </Button>
          </div>
        </div>

        <ExecutorSelect
          value={executor}
          onChange={setExecutor}
          targetIsPrivate={targetIsPrivate}
          disabled={phase === "running"}
        />

        <Collapsible open={showAdvanced} onOpenChange={setShowAdvanced}>
          <CollapsibleTrigger className="flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground">
            <ChevronDown className={cn("h-4 w-4 transition-transform", showAdvanced && "rotate-180")} />
            Advanced Options
          </CollapsibleTrigger>
          <CollapsibleContent className="mt-3 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <div className="space-y-1.5">
              <Label htmlFor="timeout">Timeout (s)</Label>
              <Input
                id="timeout"
                type="number"
                min={1}
                max={120}
                value={timeout}
                onChange={(e) => setTimeoutSec(parseInt(e.target.value || "15", 10))}
                disabled={phase === "running"}
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="profile">Profile</Label>
              <Select
                value={profile}
                onValueChange={(v) => setProfile(v as "citizen-facing" | "government-only")}
                disabled={phase === "running"}
              >
                <SelectTrigger id="profile">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="citizen-facing">citizen-facing</SelectItem>
                  <SelectItem value="government-only">government-only</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="flex items-end gap-2 pb-1">
              <Label className="text-sm">SNI</Label>
              <Switch checked={sni} onCheckedChange={setSni} disabled={phase === "running"} />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="alt-ports">Alternate ports</Label>
              <Input
                id="alt-ports"
                placeholder="8080, 8000, 4443"
                value={alternatePorts}
                onChange={(e) => setAlternatePorts(e.target.value)}
                disabled={phase === "running"}
                className="font-mono"
              />
              <p className="text-xs text-muted-foreground">
                Tried if the main port does not respond.
              </p>
            </div>
          </CollapsibleContent>
        </Collapsible>

        {error && (
          <Alert variant="destructive">
            <AlertTitle>Error</AlertTitle>
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        {phase === "running" && <ScanProgressTerminal steps={steps} />}
        {phase === "done" && (
          <Alert>
            <AlertTitle>Analysis complete</AlertTitle>
            <AlertDescription>Opening the security report...</AlertDescription>
          </Alert>
        )}
      </CardContent>
    </Card>
  );
}
