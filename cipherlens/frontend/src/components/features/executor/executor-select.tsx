"use client";

import { useEffect } from "react";
import { Building2, Cloud, Loader2, Server } from "lucide-react";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useRole } from "@/components/auth/AuthContext";
import { useAsync } from "@/hooks/use-async";
import { listAgents } from "@/services/agentsService";
import type { ExecutorSelection } from "@/types/agent";

interface ExecutorSelectProps {
  value: ExecutorSelection;
  onChange: (value: ExecutorSelection) => void;
  targetIsPrivate: boolean;
  disabled?: boolean;
}

export function ExecutorSelect({ value, onChange, targetIsPrivate, disabled }: ExecutorSelectProps) {
  const { canAssign } = useRole();
  const { data, loading } = useAsync(
    () => (canAssign ? listAgents() : Promise.resolve([])),
    [canAssign],
  );

  const agents = canAssign ? data ?? [] : [];
  const onlineAgents = agents.filter((agent) => agent.isOnline && agent.status === "active");

  useEffect(() => {
    if (!targetIsPrivate || value.type === "agent" || !onlineAgents[0]) return;
    onChange({ type: "agent", agentId: onlineAgents[0].id });
  }, [targetIsPrivate, value.type, onlineAgents, onChange]);

  const noAgentAvailable = targetIsPrivate && onlineAgents.length === 0;
  const cloudOnly = !loading && onlineAgents.length === 0;

  return (
    <div className="space-y-2">
      <Label htmlFor={cloudOnly ? undefined : "executor"}>Run from</Label>

      {cloudOnly ? (
        <div>
          <Badge variant="secondary" className="gap-1.5">
            <Cloud className="h-3.5 w-3.5" />
            Cloud scanner
          </Badge>
        </div>
      ) : (
        <Select
          value={value.type === "agent" ? value.agentId ?? "" : "cloud"}
          onValueChange={(next) => {
            if (next === "cloud") onChange({ type: "cloud" });
            else onChange({ type: "agent", agentId: next });
          }}
          disabled={disabled || loading || noAgentAvailable}
        >
          <SelectTrigger id="executor">
            <SelectValue>
              {value.type === "agent" ? (
                <span className="flex items-center gap-2">
                  <Server className="h-3.5 w-3.5" />
                  {agents.find((agent) => agent.id === value.agentId)?.name ?? "On-prem agent"}
                </span>
              ) : (
                <span className="flex items-center gap-2">
                  <Cloud className="h-3.5 w-3.5" />
                  Cloud scanner
                </span>
              )}
            </SelectValue>
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="cloud" disabled={targetIsPrivate}>
              <span className="flex items-center gap-2">
                <Cloud className="h-3.5 w-3.5" />
                Cloud scanner
              </span>
            </SelectItem>
            {onlineAgents.map((agent) => (
              <SelectItem key={agent.id} value={agent.id}>
                <span className="flex items-center gap-2">
                  <Building2 className="h-3.5 w-3.5" />
                  {agent.name} — {agent.siteLabel}
                </span>
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      )}

      {value.type === "cloud" && (
        <p className="text-xs text-muted-foreground">
          Cloud scans ask for authorization confirmation when you start.
        </p>
      )}

      {loading && (
        <p className="flex items-center gap-1.5 text-xs text-muted-foreground">
          <Loader2 className="h-3 w-3 animate-spin" /> Loading enrolled agents...
        </p>
      )}

      {targetIsPrivate && value.type === "cloud" && (
        <Alert>
          <AlertDescription>
            Private targets cannot be reached from the cloud. Enroll an on-prem agent to scan internal
            ranges.
          </AlertDescription>
        </Alert>
      )}
      {targetIsPrivate && onlineAgents.length > 0 && value.type === "agent" && (
        <p className="text-xs text-muted-foreground">
          Private target: the scan will run from the selected agent, within its allowed networks and ports.
        </p>
      )}
    </div>
  );
}
