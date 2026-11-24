"use client";

import { useEffect, useMemo, useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";

interface DiscoveryResult {
  id: string;
  ipAddress: string;
  hostname: string | null;
  port: number;
  service: string;
  tlsVersion: string | null;
  shadowIt: boolean;
  inventoried: boolean;
  scope: string;
  hasTls: boolean;
}

interface Asset {
  id: string;
  ip_address: string;
  hostname: string | null;
  port: number;
  service: string;
  tls_version: string | null;
  scope: string;
  inventory_status: string;
}

type ScopeFilter = "all" | "internal" | "external";
type FlagFilter = "all" | "inventoried" | "shadow";

function authHeaders(): Record<string, string> {
  const token = typeof window !== "undefined" ? localStorage.getItem("authToken") : null;
  return token ? { Authorization: `Bearer ${token}` } : {};
}

function normalizeHost(value: string | null | undefined): string {
  return (value ?? "").trim().toLowerCase();
}

/** Identidad de asset: ip + hostname + puerto (sin fallback por hostname). */
function findAsset(assets: Asset[], result: DiscoveryResult): Asset | undefined {
  return assets.find(
    (asset) =>
      asset.ip_address === result.ipAddress &&
      Number(asset.port) === result.port &&
      normalizeHost(asset.hostname) === normalizeHost(result.hostname),
  );
}

export function DiscoveryResults({ results }: { results: DiscoveryResult[] }) {
  const [search, setSearch] = useState("");
  const [scope, setScope] = useState<ScopeFilter>("all");
  const [flag, setFlag] = useState<FlagFilter>("all");
  const [assets, setAssets] = useState<Asset[]>([]);
  const [busyId, setBusyId] = useState<string | null>(null);

  useEffect(() => {
    fetch("/api/assets", { credentials: "include", headers: authHeaders() })
      .then((res) => {
        if (!res.ok) throw new Error("Failed to fetch assets");
        return res.json();
      })
      .then((data: Asset[]) => setAssets(data))
      .catch((e) => console.error("Error fetching assets:", e));
  }, []);

  const isInventoried = (r: DiscoveryResult) => Boolean(findAsset(assets, r));

  const filtered = useMemo(() => {
    return results.filter((r) => {
      const inventoried = Boolean(findAsset(assets, r));
      if (scope !== "all" && r.scope !== scope) return false;
      if (flag === "inventoried" && !inventoried) return false;
      if (flag === "shadow" && inventoried) return false;
      if (search) {
        const q = search.toLowerCase();
        const haystack = `${r.ipAddress} ${r.hostname ?? ""} ${r.service}`.toLowerCase();
        if (!haystack.includes(q)) return false;
      }
      return true;
    });
  }, [results, assets, scope, flag, search]);

  const handleAddAsset = (result: DiscoveryResult) => {
    if (busyId) return;
    setBusyId(result.id);
    fetch("/api/assets", {
      method: "POST",
      credentials: "include",
      headers: {
        "Content-Type": "application/json",
        ...authHeaders(),
      },
      body: JSON.stringify({
        ip_address: result.ipAddress,
        hostname: result.hostname ?? null,
        port: result.port,
        service: result.service,
        tls_version: result.hasTls ? result.tlsVersion ?? null : null,
        scope: result.scope,
        inventory_status: "inventoried",
      }),
    })
      .then(async (res) => {
        if (res.status === 409) {
          alert("El asset ya existe en la base de datos");
          const fresh = await fetch("/api/assets", { credentials: "include", headers: authHeaders() });
          if (fresh.ok) setAssets(await fresh.json());
          return null;
        }
        if (!res.ok) throw new Error("Failed to create asset");
        return (await res.json()) as Asset;
      })
      .then((created) => {
        if (created) setAssets((prev) => [...prev, created]);
      })
      .catch((e) => {
        console.error("Error adding asset:", e);
        alert("Error al agregar el asset: " + e.message);
      })
      .finally(() => setBusyId(null));
  };

  const handleRemoveAsset = (result: DiscoveryResult) => {
    if (busyId) return;
    const asset = findAsset(assets, result);
    if (!asset) return;
    if (!confirm(`¿Eliminar ${result.hostname ?? result.ipAddress}:${result.port} de Assets?`)) return;
    setBusyId(result.id);
    fetch(`/api/assets/${asset.id}`, {
      method: "DELETE",
      credentials: "include",
      headers: authHeaders(),
    })
      .then((res) => {
        if (!res.ok) throw new Error("Failed to delete asset");
        setAssets((prev) => prev.filter((a) => a.id !== asset.id));
      })
      .catch((e) => {
        console.error("Error deleting asset:", e);
        alert("Error al eliminar el asset: " + e.message);
      })
      .finally(() => setBusyId(null));
  };

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
        <Badge className="h-6 w-6">
          <svg
            xmlns="http://www.w3.org/2000/svg"
            className="h-4 w-4 text-primary"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V5a2 2 0 00-2-2H5a2 2 0 00-2 2v14a2 2 0 002 2h2a2 2 0 002-2zm10 7V5a2 2 0 00-2-2h-2a2 2 0 00-2 2v14a2 2 0 002 2h2a2 2 0 002-2z"
            />
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              d="M15 10l3 3m0 0l-3-3m3 3H9"
            />
          </svg>
        </Badge>
        <span className="text-xs font-medium ml-2">Assets Found</span>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <Input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search IP, hostname, service..."
          className="h-8 w-64"
        />
        {["all", "internal", "external"].map((s) => (
          <Button
            key={s}
            size="sm"
            variant={scope === s ? "default" : "outline"}
            className="h-8 text-xs capitalize"
            onClick={() => setScope((prev) => (prev === s ? "all" : s as ScopeFilter))}
          >
            {s}
          </Button>
        ))}
        <span className="mx-1 h-4 w-px bg-border" />
        {["all", "inventoried", "shadow"].map((f) => (
          <Button
            key={f}
            size="sm"
            variant={flag === f ? "default" : "outline"}
            className="h-8 text-xs capitalize"
            onClick={() => setFlag((prev) => (prev === f ? "all" : f as FlagFilter))}
          >
            {f}
          </Button>
        ))}
      </div>

      <div className="overflow-x-auto rounded-lg border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>IP Address</TableHead>
              <TableHead>Hostname</TableHead>
              <TableHead>Port</TableHead>
              <TableHead>Service</TableHead>
              <TableHead>TLS</TableHead>
              <TableHead>Scope</TableHead>
              <TableHead>Inventory</TableHead>
              <TableHead>Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {filtered.map((r) => {
              const inventoried = isInventoried(r);
              const busy = busyId === r.id;
              return (
                <TableRow key={r.id}>
                  <TableCell className="font-mono text-sm">{r.ipAddress}</TableCell>
                  <TableCell className="max-w-[220px] truncate font-mono text-sm text-muted-foreground">
                    {r.hostname ?? "—"}
                  </TableCell>
                  <TableCell className="font-mono text-sm text-muted-foreground">{r.port}</TableCell>
                  <TableCell className="text-sm">{r.service}</TableCell>
                  <TableCell>
                    {r.hasTls ? (
                      <Badge variant="outline" className="border-emerald-500/40 bg-emerald-500/10 text-emerald-400">
                        {r.tlsVersion}
                      </Badge>
                    ) : (
                      <span className="text-xs text-muted-foreground">—</span>
                    )}
                  </TableCell>
                  <TableCell className="font-mono text-sm">{r.scope}</TableCell>
                  <TableCell>
                    {inventoried ? (
                      <Badge variant="default">Inventoried</Badge>
                    ) : (
                      <Badge variant="outline" className="border-amber-500/40 bg-amber-500/10 text-amber-400">
                        Shadow IT
                      </Badge>
                    )}
                  </TableCell>
                  <TableCell>
                    {inventoried ? (
                      <Button
                        size="sm"
                        variant="destructive"
                        disabled={busy}
                        onClick={() => handleRemoveAsset(r)}
                      >
                        Eliminar
                      </Button>
                    ) : (
                      <Button
                        size="sm"
                        variant="default"
                        disabled={busy}
                        onClick={() => handleAddAsset(r)}
                      >
                        Agregar a Assets
                      </Button>
                    )}
                  </TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}
