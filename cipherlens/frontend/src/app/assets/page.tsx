"use client";

import { useEffect, useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";

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

function authHeaders(): Record<string, string> {
  const token = typeof window !== "undefined" ? localStorage.getItem("authToken") : null;
  return token ? { Authorization: `Bearer ${token}` } : {};
}

export default function AssetsPage() {
  const [assets, setAssets] = useState<Asset[]>([]);

  useEffect(() => {
    fetch("/api/assets", {
      credentials: "include",
      headers: authHeaders(),
    })
      .then((res) => {
        if (!res.ok) throw new Error("Failed to fetch");
        return res.json();
      })
      .then((data: Asset[]) => setAssets(data))
      .catch((e) => console.error("Error fetching assets:", e));
  }, []);

  const handleDelete = (id: string) => {
    fetch(`/api/assets/${id}`, {
      method: "DELETE",
      credentials: "include",
      headers: authHeaders(),
    })
      .then((res) => {
        if (!res.ok) throw new Error("Failed to delete");
      })
      .then(() => {
        setAssets((prev) => prev.filter((a) => a.id !== id));
      })
      .catch((e) => console.error("Error deleting asset:", e));
  };

  return (
    <div className="p-6">
      <h1 className="text-2xl font-bold mb-6">Assets</h1>

      <div className="overflow-x-auto rounded-lg border mt-4">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>IP Address</TableHead>
              <TableHead>Hostname</TableHead>
              <TableHead>Port</TableHead>
              <TableHead>Service</TableHead>
              <TableHead>TLS Version</TableHead>
              <TableHead>Scope</TableHead>
              <TableHead>Inventory Status</TableHead>
              <TableHead>Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {assets.map((asset) => (
              <TableRow key={asset.id}>
                <TableCell className="font-mono text-sm">{asset.ip_address}</TableCell>
                <TableCell className="max-w-[220px] truncate font-mono text-sm text-muted-foreground">
                  {asset.hostname ?? "—"}
                </TableCell>
                <TableCell className="font-mono text-sm">{asset.port}</TableCell>
                <TableCell className="text-sm">{asset.service}</TableCell>
                <TableCell>
                  {asset.tls_version ? (
                    <Badge variant="outline" className="border-emerald-500/40 bg-emerald-500/10 text-emerald-400">
                      {asset.tls_version}
                    </Badge>
                  ) : (
                    <span className="text-xs text-muted-foreground">—</span>
                  )}
                </TableCell>
                <TableCell className="font-mono text-sm">{asset.scope}</TableCell>
                <TableCell className="font-mono text-sm">{asset.inventory_status}</TableCell>
                <TableCell className="text-sm">
                  <Button
                    size="sm"
                    variant="destructive"
                    onClick={() => handleDelete(asset.id)}
                  >
                    Eliminar
                  </Button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}
