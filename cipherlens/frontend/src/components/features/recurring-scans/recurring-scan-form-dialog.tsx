"use client";

import { useEffect, useState } from "react";
import { Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { ExecutorSelect } from "@/components/features/executor/executor-select";
import { isPrivateTarget } from "@/lib/target";
import type { RecurringScan, RecurringScanInput } from "@/types/recurringScan";

const PROFILES = [
  { value: "citizen-facing", label: "Citizen-facing" },
  { value: "internal", label: "Internal" },
  { value: "critical", label: "Critical" },
];

const FREQUENCIES = [
  { hours: 1, label: "Hourly" },
  { hours: 24, label: "Daily" },
  { hours: 168, label: "Weekly" },
];

interface Props {
  open: boolean;
  scan: RecurringScan | null;
  saving: boolean;
  error: string | null;
  onClose: () => void;
  onSubmit: (input: RecurringScanInput) => void;
}

export function RecurringScanFormDialog({ open, scan, saving, error, onClose, onSubmit }: Props) {
  const [host, setHost] = useState("");
  const [port, setPort] = useState("443");
  const [alternatePorts, setAlternatePorts] = useState("");
  const [profile, setProfile] = useState("citizen-facing");
  const [intervalHours, setIntervalHours] = useState("24");
  const [enabled, setEnabled] = useState(true);
  const [agentId, setAgentId] = useState<string | null>(null);
  const targetIsPrivate = isPrivateTarget(host);
  const privateBlocked = targetIsPrivate && !agentId;
  const interval = Number(intervalHours);
  const validInterval = Number.isFinite(interval) && interval > 0;

  function reset(initial: RecurringScan | null) {
    setHost(initial?.host ?? "");
    setPort(initial ? String(initial.port) : "443");
    setAlternatePorts(initial?.alternatePorts.join(", ") ?? "");
    setProfile(initial?.profile ?? "citizen-facing");
    setIntervalHours(initial ? String(initial.intervalHours) : "24");
    setEnabled(initial?.enabled ?? true);
    setAgentId(initial?.agentId ?? null);
  }

  useEffect(() => {
    if (open) reset(scan);
  }, [open, scan]);

  function handleSubmit() {
    if (!host.trim() || privateBlocked || !validInterval) return;
    const portNum = parseInt(port, 10);
    onSubmit({
      host: host.trim(),
      port: Number.isNaN(portNum) || portNum <= 0 ? 443 : portNum,
      alternatePorts: alternatePorts
        .split(",")
        .map((p) => parseInt(p.trim(), 10))
        .filter((p) => !Number.isNaN(p) && p > 0 && p < 65536),
      profile,
      intervalHours: interval,
      enabled,
      agentId,
    });
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(o) => {
        if (!o && !saving) {
          reset(null);
          onClose();
        }
      }}
    >
      <DialogContent className="max-h-[calc(100dvh-2rem)] overflow-y-auto sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{scan ? "Edit recurring scan" : "New recurring scan"}</DialogTitle>
          <DialogDescription>
            {scan
              ? `Update the schedule for ${scan.host}.`
              : "Schedule automated TLS scans that run periodically against a target."}
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          <div className="space-y-1.5">
            <Label htmlFor="rs-host">Host / target</Label>
            <Input
              id="rs-host"
              value={host}
              onChange={(e) => setHost(e.target.value)}
              placeholder="api.internal.company.com"
              className="font-mono"
              disabled={saving}
            />
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="rs-interval">Scan frequency</Label>
            <div className="flex flex-wrap gap-2" role="group" aria-label="Frequency presets">
              {FREQUENCIES.map(({ hours, label }) => (
                <Button
                  key={hours}
                  type="button"
                  size="sm"
                  variant={interval === hours ? "default" : "outline"}
                  aria-pressed={interval === hours}
                  onClick={() => setIntervalHours(String(hours))}
                  disabled={saving}
                >
                  {label}
                </Button>
              ))}
            </div>
            <div className="flex items-center gap-2">
              <span className="text-sm text-muted-foreground">Every</span>
              <Input
                id="rs-interval"
                type="number"
                step="any"
                value={intervalHours}
                onChange={(e) => setIntervalHours(e.target.value)}
                className="w-24 font-mono"
                aria-describedby="rs-interval-hint"
                aria-invalid={!validInterval}
                disabled={saving}
              />
              <span className="text-sm text-muted-foreground">hours</span>
            </div>
            <p id="rs-interval-hint" className={validInterval ? "sr-only" : "text-xs text-destructive"}>
              Enter a frequency greater than zero hours.
            </p>
          </div>

          <ExecutorSelect
            value={agentId ? { type: "agent", agentId } : { type: "cloud" }}
            onChange={(executor) => setAgentId(executor.type === "agent" ? executor.agentId ?? null : null)}
            targetIsPrivate={targetIsPrivate}
            disabled={saving}
          />

          <div className="space-y-1.5">
            <Label htmlFor="rs-port">Port</Label>
            <Input
              id="rs-port"
              value={port}
              onChange={(e) => setPort(e.target.value)}
              placeholder="443"
              className="font-mono"
              disabled={saving}
            />
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="rs-alt">Alternate ports (comma separated)</Label>
            <Input
              id="rs-alt"
              value={alternatePorts}
              onChange={(e) => setAlternatePorts(e.target.value)}
              placeholder="8443, 4443"
              className="font-mono"
              disabled={saving}
            />
          </div>

          <div className="space-y-1.5">
            <Label>Profile</Label>
            <Select value={profile} onValueChange={setProfile} disabled={saving}>
              <SelectTrigger className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {PROFILES.map((p) => (
                  <SelectItem key={p.value} value={p.value}>
                    {p.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="flex items-center justify-between rounded-lg border px-3 py-2">
            <div>
              <Label className="text-sm">Enabled</Label>
              <p className="text-xs text-muted-foreground">Whether this schedule is active.</p>
            </div>
            <Switch checked={enabled} onCheckedChange={setEnabled} disabled={saving} />
          </div>

          {error && (
            <Alert variant="destructive">
              <AlertTitle>Error</AlertTitle>
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => { reset(null); onClose(); }} disabled={saving}>
            Cancel
          </Button>
          <Button onClick={handleSubmit} disabled={saving || !host.trim() || privateBlocked || !validInterval} className="gap-2">
            {saving && <Loader2 className="h-4 w-4 animate-spin" />}
            {scan ? "Save changes" : "Create schedule"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
