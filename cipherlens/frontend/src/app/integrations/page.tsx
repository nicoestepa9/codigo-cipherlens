"use client";

import { useMemo, useState } from "react";
import { useAsync } from "@/hooks/use-async";
import {
  Copy,
  Gauge,
  KeyRound,
  Link2,
  Plus,
  RefreshCw,
  ShieldAlert,
  Trash2,
  Unplug,
} from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { TableSkeleton } from "@/components/shared/skeletons";
import { EmptyState } from "@/components/shared/empty-state";
import { formatDate, relativeTime } from "@/lib/format";
import { cn } from "@/lib/utils";
import {
  createGrafanaViewerKey,
  generateApiKey,
  getApiEndpoints,
  getApiKeys,
  getIntegrations,
  revokeApiKey,
} from "@/services/integrationsService";
import type { IntegrationStatus } from "@/types/integration";

const INTEGRATION_STATUS: Record<IntegrationStatus, { label: string; cls: string; dot: string }> = {
  connected: { label: "Connected", cls: "border-emerald-500/40 bg-emerald-500/10 text-emerald-400", dot: "bg-emerald-500" },
  pending: { label: "Pending", cls: "border-amber-500/40 bg-amber-500/10 text-amber-400", dot: "bg-amber-500" },
  disconnected: { label: "Disconnected", cls: "border-muted text-muted-foreground", dot: "bg-muted-foreground" },
};

const METHOD_CLS: Record<string, string> = {
  GET: "border-emerald-500/40 bg-emerald-500/10 text-emerald-400",
  POST: "border-sky-500/40 bg-sky-500/10 text-sky-400",
  PUT: "border-amber-500/40 bg-amber-500/10 text-amber-400",
  DELETE: "border-red-500/40 bg-red-500/10 text-red-400",
};

export default function IntegrationsPage() {
  const [createOpen, setCreateOpen] = useState(false);
  const [newKeyName, setNewKeyName] = useState("");
  const [generatedKey, setGeneratedKey] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const [grafanaOpen, setGrafanaOpen] = useState(false);
  const [grafanaKey, setGrafanaKey] = useState<string | null>(null);
  const [grafanaCopied, setGrafanaCopied] = useState(false);
  const [grafanaLoading, setGrafanaLoading] = useState(false);
  const [grafanaError, setGrafanaError] = useState<string | null>(null);

  const {
    data: integrations,
    loading: integrationsLoading,
    error: integrationsError,
    refetch: refetchIntegrations,
  } = useAsync(getIntegrations, []);

  const {
    data: apiKeys,
    loading: keysLoading,
    error: keysError,
    refetch: refetchKeys,
  } = useAsync(getApiKeys, []);

  const {
    data: endpoints,
    loading: endpointsLoading,
    error: endpointsError,
  } = useAsync(getApiEndpoints, []);

  const liveKeys = useMemo(() => (apiKeys ?? []).filter((k) => !k.revoked), [apiKeys]);

  async function handleCreate() {
    const name = newKeyName.trim();
    if (!name) return;
    const key = await generateApiKey(name);
    setGeneratedKey(key.prefix.replace(/^cg_live_/, "cg_live_"));
    setNewKeyName("");
    setCopied(false);
    refetchKeys();
  }

  function handleRevoke(id: string) {
    revokeApiKey(id).then(refetchKeys);
  }

  async function copyKey(value: string) {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      // clipboard unavailable
    }
  }

  async function handleCreateGrafanaKey() {
    setGrafanaLoading(true);
    setGrafanaError(null);
    try {
      const created = await createGrafanaViewerKey();
      setGrafanaKey(created.key);
      setGrafanaCopied(false);
      refetchKeys();
    } catch (err) {
      setGrafanaError(
        err instanceof Error ? err.message : "No se pudo generar la key de Grafana.",
      );
    } finally {
      setGrafanaLoading(false);
    }
  }

  async function copyGrafanaKey(value: string) {
    try {
      await navigator.clipboard.writeText(value);
      setGrafanaCopied(true);
      setTimeout(() => setGrafanaCopied(false), 1500);
    } catch {
      // clipboard unavailable
    }
  }

  function openGrafanaDialog() {
    setGrafanaKey(null);
    setGrafanaError(null);
    setGrafanaCopied(false);
    setGrafanaOpen(true);
  }

  const showTableSkeleton = integrationsLoading || keysLoading || endpointsLoading;
  const showError = integrationsError || keysError || endpointsError;

  return (
    <div>
      <PageHeader
        title="Integrations & API"
        subtitle="Connect your tooling and access CipherLens programmatically via REST API."
      />

      {showTableSkeleton ? (
        <TableSkeleton columns={4} rows={6} />
      ) : showError ? (
        <EmptyState title="Could not load integrations." />
      ) : (
        <>
          <Card className="mb-4">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-base">
                <Link2 className="h-4 w-4 text-muted-foreground" />
                External Integrations
              </CardTitle>
              <CardDescription>Sync certificate lifecycle, asset inventory, and security events.</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
                {(integrations ?? []).map((it) => {
                  const st = INTEGRATION_STATUS[it.status];
                  return (
                    <div key={it.id} className="flex flex-col gap-2 rounded-lg border p-4">
                      <div className="flex items-start justify-between gap-2">
                        <p className="text-sm font-medium text-foreground">{it.name}</p>
                        <Badge variant="outline" className={st.cls}>
                          <span className={cn("mr-1.5 inline-block h-1.5 w-1.5 rounded-full", st.dot)} />
                          {st.label}
                        </Badge>
                      </div>
                      <p className="flex-1 text-xs text-muted-foreground">{it.description}</p>
                      <div className="flex items-center justify-between gap-2">
                        <p className="text-[11px] text-muted-foreground">
                          {it.lastSyncAt ? `Last sync ${relativeTime(it.lastSyncAt)}` : "Never synced"}
                        </p>
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-7 text-xs"
                          disabled={it.status === "pending"}
                          onClick={() => {
                            const next = it.status === "connected" ? "disconnected" : "connected";
                            // local toggle only in mock mode
                            it.status = next;
                            refetchIntegrations();
                          }}
                        >
                          {it.status === "connected" ? (
                            <><Unplug className="mr-1 h-3.5 w-3.5" /> Disconnect</>
                          ) : (
                            <><Link2 className="mr-1 h-3.5 w-3.5" /> Connect</>
                          )}
                        </Button>
                      </div>
                    </div>
                  );
                })}
              </div>
            </CardContent>
          </Card>

          <Card className="mb-4">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-base">
                <Gauge className="h-4 w-4 text-muted-foreground" />
                Grafana
              </CardTitle>
              <CardDescription>
                Connect Grafana (via the Infinity datasource) to the read-only
                <code className="mx-1 font-mono text-xs">/api/reports/*</code>
                endpoints. The guide and the exported dashboard ship in the repo.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                <div className="min-w-0 space-y-1">
                  <p className="text-[11px] text-muted-foreground">Guía de integración:</p>
                  <code className="block break-all font-mono text-xs text-foreground">
                    analisis/docs/grafana_investigacion.md
                  </code>
                  <p className="pt-1 text-[11px] text-muted-foreground">Dashboard exportado:</p>
                  <code className="block break-all font-mono text-xs text-foreground">
                    grafana/dashboards/cryptoguard-overview.json
                  </code>
                </div>
                <Button size="sm" className="shrink-0" onClick={openGrafanaDialog}>
                  <KeyRound className="mr-2 h-4 w-4" />
                  Generate viewer key
                </Button>
              </div>
            </CardContent>
          </Card>

          <Card className="mb-4">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-base">
                <KeyRound className="h-4 w-4 text-muted-foreground" />
                API Keys
              </CardTitle>
              <CardDescription>Authenticate API calls with Bearer tokens.</CardDescription>
              <div className="flex justify-end pt-2">
                <Button size="sm" onClick={() => { setGeneratedKey(null); setCreateOpen(true); }}>
                  <Plus className="mr-2 h-4 w-4" />
                  Generate Key
                </Button>
              </div>
            </CardHeader>
            <CardContent className="p-0">
              {liveKeys.length === 0 ? (
                <p className="px-4 pb-4 text-xs text-muted-foreground">No active API keys.</p>
              ) : (
                <div className="overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Name</TableHead>
                      <TableHead>Key</TableHead>
                      <TableHead>Created</TableHead>
                      <TableHead>Last Used</TableHead>
                      <TableHead className="w-8" />
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {liveKeys.map((k) => (
                      <TableRow key={k.id}>
                        <TableCell className="text-sm font-medium">{k.name}</TableCell>
                        <TableCell className="font-mono text-xs text-muted-foreground">{k.prefix}…</TableCell>
                        <TableCell className="text-xs text-muted-foreground">{formatDate(k.createdAt)}</TableCell>
                        <TableCell className="text-xs text-muted-foreground">
                          {k.lastUsedAt ? relativeTime(k.lastUsedAt) : "Never"}
                        </TableCell>
                        <TableCell>
                          <Button
                            variant="ghost"
                            size="icon"
                            className="h-8 w-8 text-muted-foreground hover:text-red-400"
                            onClick={() => handleRevoke(k.id)}
                            title="Revoke key"
                          >
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
                </div>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-base">
                <ShieldAlert className="h-4 w-4 text-muted-foreground" />
                API Reference
              </CardTitle>
              <CardDescription>REST endpoints available over HTTPS with Bearer authentication.</CardDescription>
            </CardHeader>
            <CardContent className="p-0">
              <div className="divide-y divide-border/60">
                {(endpoints ?? []).map((ep) => (
                  <div key={`${ep.method}-${ep.path}`} className="flex flex-col gap-1 px-4 py-3 sm:flex-row sm:items-start sm:justify-between">
                    <div className="min-w-0">
                      <div className="flex flex-wrap items-center gap-2">
                        <Badge variant="outline" className={cn("font-mono text-[10px]", METHOD_CLS[ep.method])}>
                          {ep.method}
                        </Badge>
                        <code className="font-mono text-xs text-foreground">{ep.path}</code>
                      </div>
                      <p className="mt-1 text-xs text-muted-foreground">{ep.description}</p>
                    </div>
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-7 shrink-0 text-xs text-muted-foreground"
                      onClick={() => copyKey(ep.example)}
                    >
                      {copied ? <RefreshCw className="mr-1 h-3.5 w-3.5" /> : <Copy className="mr-1 h-3.5 w-3.5" />}
                      Copy curl
                    </Button>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </>
      )}

      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Generate API Key</DialogTitle>
            <DialogDescription>
              {generatedKey
                ? "Copy this key now — it won't be shown again."
                : "Give the key a descriptive name so you can identify its consumer."}
            </DialogDescription>
          </DialogHeader>
          {generatedKey ? (
            <div className="flex items-center gap-2 rounded-lg border bg-background p-3">
              <code className="min-w-0 flex-1 break-all font-mono text-xs">{generatedKey}</code>
              <Button size="sm" variant="outline" onClick={() => copyKey(generatedKey)}>
                {copied ? "Copied" : <><Copy className="mr-1 h-4 w-4" /> Copy</>}
              </Button>
            </div>
          ) : (
            <Input
              value={newKeyName}
              onChange={(e) => setNewKeyName(e.target.value)}
              placeholder="e.g. ci-pipeline-prod"
              onKeyDown={(e) => e.key === "Enter" && handleCreate()}
            />
          )}
          <DialogFooter>
            {generatedKey ? (
              <Button onClick={() => setCreateOpen(false)}>Done</Button>
            ) : (
              <>
                <Button variant="outline" onClick={() => setCreateOpen(false)}>Cancel</Button>
                <Button onClick={handleCreate} disabled={!newKeyName.trim()}>Generate</Button>
              </>
            )}
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={grafanaOpen} onOpenChange={setGrafanaOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Generate Grafana viewer key</DialogTitle>
            <DialogDescription>
              {grafanaKey
                ? "Copy this key now — it won't be shown again. Set it as CRYPTOGUARD_API_KEY in grafana/.env."
                : "Creates an API key with the read-only 'viewer' role, labelled 'grafana'."}
            </DialogDescription>
          </DialogHeader>
          {grafanaKey ? (
            <div className="flex items-center gap-2 rounded-lg border bg-background p-3">
              <code className="min-w-0 flex-1 break-all font-mono text-xs">{grafanaKey}</code>
              <Button size="sm" variant="outline" onClick={() => copyGrafanaKey(grafanaKey)}>
                {grafanaCopied ? "Copied" : <><Copy className="mr-1 h-4 w-4" /> Copy</>}
              </Button>
            </div>
          ) : grafanaError ? (
            <p className="text-sm text-red-400">{grafanaError}</p>
          ) : (
            <p className="text-sm text-muted-foreground">
              The key can only read reports. It cannot modify data.
            </p>
          )}
          <DialogFooter>
            {grafanaKey ? (
              <Button onClick={() => setGrafanaOpen(false)}>Done</Button>
            ) : (
              <>
                <Button variant="outline" onClick={() => setGrafanaOpen(false)}>Cancel</Button>
                <Button onClick={handleCreateGrafanaKey} disabled={grafanaLoading}>
                  {grafanaLoading ? "Generating…" : "Generate"}
                </Button>
              </>
            )}
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
