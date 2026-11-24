"use client";

import { useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { EmptyState, ErrorState } from "@/components/shared/empty-state";
import { PageHeader } from "@/components/shared/page-header";
import { useRole } from "@/components/auth/AuthContext";
import { useAsync } from "@/hooks/use-async";
import { relativeTime } from "@/lib/format";
import { createAgent, listAgents, revokeAgent, rotateAgentKey } from "@/services/agentsService";
import { Copy, Cpu, Loader2, RefreshCw, ShieldOff, UserPlus } from "lucide-react";

function agentConfigExample(siteLabel: string): string {
  const configuredUrl = process.env.NEXT_PUBLIC_API_URL;
  const serverUrl = configuredUrl
    ? configuredUrl.replace(/\/api\/?$/, "")
    : typeof window !== "undefined"
      ? window.location.origin
      : "https://platform.example.com";
  const site = siteLabel.trim() || "Sede Central";

  return `server_url: ${serverUrl}
site_label: ${site}
upload_level: standard
pseudonymize: internal
max_concurrent: 3
allow_remote_tasks: false
allowed_networks: []
allowed_ports: []`;
}

export default function AgentsPage() {
  const router = useRouter();
  const { canAssign, isAdmin } = useRole();
  const { data, loading, error, refetch } = useAsync(listAgents, []);

  const [createOpen, setCreateOpen] = useState(false);
  const [name, setName] = useState("");
  const [siteLabel, setSiteLabel] = useState("");
  const [saving, setSaving] = useState(false);
  const [apiKey, setApiKey] = useState<string | null>(null);
  const [keySiteLabel, setKeySiteLabel] = useState("");
  const [siteFilter, setSiteFilter] = useState("all");
  const [formError, setFormError] = useState<string | null>(null);

  const agents = useMemo(() => data ?? [], [data]);
  const sites = useMemo(
    () => Array.from(new Set(agents.map((agent) => agent.siteLabel).filter(Boolean))).sort(),
    [agents],
  );
  const visibleAgents =
    siteFilter === "all" ? agents : agents.filter((agent) => agent.siteLabel === siteFilter);

  useEffect(() => {
    if (!canAssign) router.push("/dashboard");
  }, [canAssign, router]);

  if (!canAssign) return null;

  const agentYaml = agentConfigExample(keySiteLabel);

  async function handleCreate() {
    if (!name.trim() || !siteLabel.trim()) {
      setFormError("Name and site are required.");
      return;
    }
    setSaving(true);
    setFormError(null);
    try {
      const createdSite = siteLabel.trim();
      const created = await createAgent({ name: name.trim(), siteLabel: createdSite });
      setApiKey(created.apiKey);
      setKeySiteLabel(createdSite);
      setName("");
      setSiteLabel("");
      await refetch();
    } catch (err) {
      setFormError(err instanceof Error ? err.message : "Could not create the agent.");
    } finally {
      setSaving(false);
    }
  }

  async function handleRotate(id: string) {
    if (!confirm("Rotate this agent key? The current key stops working immediately.")) return;
    try {
      const rotated = await rotateAgentKey(id);
      setApiKey(rotated.apiKey);
      setKeySiteLabel(agents.find((agent) => agent.id === id)?.siteLabel ?? "");
      setCreateOpen(true);
      await refetch();
    } catch (err) {
      alert(err instanceof Error ? err.message : "Could not rotate the key.");
    }
  }

  async function handleRevoke(id: string) {
    if (!confirm("Revoke this agent? It will no longer be able to connect or run tasks.")) return;
    try {
      await revokeAgent(id);
      await refetch();
    } catch (err) {
      alert(err instanceof Error ? err.message : "Could not revoke the agent.");
    }
  }

  function closeDialog(open: boolean) {
    setCreateOpen(open);
    if (!open) {
      setApiKey(null);
      setKeySiteLabel("");
      setFormError(null);
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="On-prem Agents"
        subtitle="Collectors enrolled in this organization. They run private scans within their allowlisted networks and ports."
        actions={
          isAdmin && (
            <Button onClick={() => setCreateOpen(true)} className="gap-2">
              <UserPlus className="h-4 w-4" />
              Enroll agent
            </Button>
          )
        }
      />

      <Card>
        <CardHeader className="flex flex-row flex-wrap items-center justify-between gap-2">
          <CardTitle className="text-base">Enrolled agents</CardTitle>
          <div className="flex items-center gap-2">
            <Select value={siteFilter} onValueChange={setSiteFilter}>
              <SelectTrigger className="h-8 w-44">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All sites</SelectItem>
                {sites.map((site) => (
                  <SelectItem key={site} value={site}>
                    {site}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Button variant="ghost" size="sm" onClick={() => void refetch()} className="gap-2">
              <RefreshCw className="h-3.5 w-3.5" />
              Refresh
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="flex justify-center py-10">
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
            </div>
          ) : error ? (
            <ErrorState message={error.message} onRetry={() => void refetch()} />
          ) : visibleAgents.length === 0 ? (
            <EmptyState
              icon={<Cpu className="h-8 w-8" />}
              title={agents.length === 0 ? "No agents enrolled" : "No agents for this site"}
              description={
                agents.length === 0
                  ? "Enroll an on-prem agent to scan private networks and internal ranges from inside your infrastructure."
                  : "Choose another site or enroll a new agent for this location."
              }
            />
          ) : (
            <div className="overflow-x-auto rounded-lg border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Agent</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Version</TableHead>
                  <TableHead>Last seen</TableHead>
                  <TableHead>Remote tasks</TableHead>
                  <TableHead>Services</TableHead>
                  {isAdmin && <TableHead className="text-right">Actions</TableHead>}
                </TableRow>
              </TableHeader>
              <TableBody>
                {visibleAgents.map((agent) => (
                  <TableRow key={agent.id}>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <span className="font-medium">{agent.name}</span>
                        <Badge variant="outline" className="text-[10px]">
                          {agent.siteLabel}
                        </Badge>
                      </div>
                      <div className="font-mono text-[11px] text-muted-foreground">{agent.id}</div>
                    </TableCell>
                    <TableCell>
                      <Badge variant={agent.status === "revoked" ? "outline" : agent.isOnline ? "default" : "secondary"}>
                        {agent.status === "revoked" ? "Revoked" : agent.isOnline ? "Online" : "Offline"}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-sm">{agent.version ?? "—"}</TableCell>
                    <TableCell className="text-sm">{relativeTime(agent.lastSeenAt)}</TableCell>
                    <TableCell className="text-sm">
                      {agent.reportedCapabilities?.allowRemoteTasks ? (
                        <div className="space-y-1">
                          <span>
                            {agent.reportedCapabilities.networkCount ?? 0} nets /{" "}
                            {agent.reportedCapabilities.portCount ?? 0} ports
                          </span>
                          <div className="flex max-w-[260px] flex-wrap gap-1">
                            {(agent.reportedCapabilities.allowedNetworks ?? []).map((network) => (
                              <Badge key={network} variant="secondary" className="font-mono text-[10px]">
                                {network}
                              </Badge>
                            ))}
                            {(agent.reportedCapabilities.allowedPorts ?? []).map((port) => (
                              <Badge key={port} variant="outline" className="font-mono text-[10px]">
                                {port}
                              </Badge>
                            ))}
                          </div>
                        </div>
                      ) : (
                        <span className="text-muted-foreground">Disabled</span>
                      )}
                    </TableCell>
                    <TableCell className="text-sm">{agent.serviceCount}</TableCell>
                    {isAdmin && (
                      <TableCell className="space-x-1 text-right">
                        <Button size="sm" variant="ghost" onClick={() => void handleRotate(agent.id)}>
                          <RefreshCw className="h-4 w-4" />
                        </Button>
                        <Button size="sm" variant="ghost" onClick={() => void handleRevoke(agent.id)}>
                          <ShieldOff className="h-4 w-4 text-destructive" />
                        </Button>
                      </TableCell>
                    )}
                  </TableRow>
                ))}
              </TableBody>
            </Table>
            </div>
          )}
        </CardContent>
      </Card>

      <Dialog open={createOpen} onOpenChange={closeDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{apiKey ? "Agent API key" : "Enroll agent"}</DialogTitle>
            <DialogDescription>
              {apiKey
                ? "Copy this key now. It will not be shown again."
                : "The key is shown once after enrollment. Configure the agent immediately."}
            </DialogDescription>
          </DialogHeader>

          {apiKey ? (
            <div className="space-y-4">
              <Alert>
                <AlertTitle>Store this key securely</AlertTitle>
                <AlertDescription>
                  <code className="mt-2 block break-all rounded bg-muted p-2 font-mono text-xs">{apiKey}</code>
                </AlertDescription>
              </Alert>
              <Button
                className="w-full gap-2"
                onClick={() => void navigator.clipboard.writeText(apiKey)}
              >
                <Copy className="h-4 w-4" />
                Copy key
              </Button>
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <Label htmlFor="agent-yaml">agent.yaml</Label>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="gap-1"
                    onClick={() => void navigator.clipboard.writeText(agentYaml)}
                  >
                    <Copy className="h-3.5 w-3.5" />
                    Copy config
                  </Button>
                </div>
                <Textarea id="agent-yaml" readOnly value={agentYaml} className="min-h-[190px] font-mono text-xs" />
                <p className="text-xs text-muted-foreground">
                  Set <code>CRYPTOGUARD_AGENT_KEY</code> from the key above. The key is never stored in the YAML.
                </p>
              </div>
              <Button variant="outline" className="w-full" onClick={() => closeDialog(false)}>
                Done
              </Button>
            </div>
          ) : (
            <div className="space-y-4">
              <div className="space-y-1.5">
                <Label htmlFor="agent-name">Name</Label>
                <Input
                  id="agent-name"
                  value={name}
                  onChange={(event) => setName(event.target.value)}
                  placeholder="HQ Collector"
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="agent-site">Site</Label>
                <Input
                  id="agent-site"
                  value={siteLabel}
                  onChange={(event) => setSiteLabel(event.target.value)}
                  placeholder="Sede Central"
                />
              </div>
              {formError && <p className="text-sm text-destructive">{formError}</p>}
              <Button className="w-full" onClick={() => void handleCreate()} disabled={saving}>
                {saving && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                Create agent key
              </Button>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
