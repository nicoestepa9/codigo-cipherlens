"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/components/auth/AuthContext";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import {
  createOrganization,
  disableOrganization,
  enableOrganization,
  listOrganizations,
  purgeOrganization,
  type Organization,
} from "@/services/organizationsService";
import { Loader2, Plus, ShieldAlert } from "lucide-react";

export default function OperatorPage() {
  const { user, isOperator, loading } = useAuth();
  const router = useRouter();
  const [orgs, setOrgs] = useState<Organization[]>([]);
  const [fetching, setFetching] = useState(true);
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");
  const [adminEmail, setAdminEmail] = useState("");
  const [adminName, setAdminName] = useState("");
  const [adminPassword, setAdminPassword] = useState("");

  useEffect(() => {
    if (!loading && !isOperator) {
      router.replace("/dashboard");
    }
  }, [loading, isOperator, router]);

  async function load() {
    try {
      setFetching(true);
      const data = await listOrganizations();
      setOrgs(data);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Error al cargar organizaciones");
    } finally {
      setFetching(false);
    }
  }

  useEffect(() => {
    if (isOperator) load();
  }, [isOperator]);

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    if (!adminName.trim() || !adminEmail.trim() || !adminPassword.trim()) {
      setError("Completa nombre, email y password del admin.");
      return;
    }
    setCreating(true);
    setError(null);
    try {
      await createOrganization({
        name,
        slug,
        admin_email: adminEmail.trim(),
        admin_name: adminName.trim(),
        admin_password: adminPassword,
      });
      setName("");
      setSlug("");
      setAdminEmail("");
      setAdminName("");
      setAdminPassword("");
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Error al crear organización");
    } finally {
      setCreating(false);
    }
  }

  async function handleDisable(id: number) {
    if (!confirm("¿Deshabilitar esta organización?")) return;
    try {
      await disableOrganization(id);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Error al deshabilitar");
    }
  }

  async function handleEnable(id: number) {
    try {
      await enableOrganization(id);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Error al habilitar");
    }
  }

  async function handlePurge(id: number) {
    if (!confirm("¿ELIMINAR COMPLETAMENTE esta organización y TODOS sus datos? Esta acción NO se puede deshacer.")) return;
    try {
      await purgeOrganization(id);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Error al purgar");
    }
  }

  if (loading || !isOperator) {
    return (
      <div className="flex h-screen items-center justify-center">
        <Loader2 className="h-6 w-6 animate-spin" />
      </div>
    );
  }

  return (
    <div className="container mx-auto max-w-6xl space-y-6 p-6">
      <div className="flex items-center gap-3">
        <div className="flex h-10 w-10 items-center justify-center rounded-md bg-primary text-primary-foreground">
          <ShieldAlert className="h-5 w-5" />
        </div>
        <div>
          <h1 className="text-2xl font-semibold">Panel de Operador</h1>
          <p className="text-sm text-muted-foreground">Gestión de organizaciones (solo plataforma)</p>
        </div>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Plus className="h-4 w-4" />
            Crear organización
          </CardTitle>
          <CardDescription>Crear org + admin inicial</CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleCreate} className="grid gap-4 md:grid-cols-2">
            <div className="space-y-1.5">
              <Label htmlFor="name">Nombre</Label>
              <Input id="name" value={name} onChange={(e) => setName(e.target.value)} required />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="slug">Slug</Label>
              <Input id="slug" value={slug} onChange={(e) => setSlug(e.target.value.toLowerCase())} placeholder="mi-org" required />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="adminName">Nombre Admin</Label>
              <Input id="adminName" value={adminName} onChange={(e) => setAdminName(e.target.value)} required />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="adminEmail">Email Admin</Label>
              <Input id="adminEmail" type="email" value={adminEmail} onChange={(e) => setAdminEmail(e.target.value)} required />
            </div>
            <div className="space-y-1.5 md:col-span-2">
              <Label htmlFor="adminPassword">Password Admin</Label>
              <Input id="adminPassword" type="password" value={adminPassword} onChange={(e) => setAdminPassword(e.target.value)} required />
            </div>
            <div className="md:col-span-2">
              <Button type="submit" disabled={creating}>
                {creating && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                Crear organización
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>

      {error && (
        <p className="rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-sm text-destructive">{error}</p>
      )}

      <Card>
        <CardHeader>
          <CardTitle>Organizaciones</CardTitle>
          <CardDescription>Listado de todas las organizaciones</CardDescription>
        </CardHeader>
        <CardContent>
          {fetching ? (
            <div className="flex items-center justify-center py-8">
              <Loader2 className="h-6 w-6 animate-spin" />
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>ID</TableHead>
                  <TableHead>Nombre</TableHead>
                  <TableHead>Slug</TableHead>
                  <TableHead>Estado</TableHead>
                  <TableHead className="text-right">Acciones</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {orgs.map((org) => (
                  <TableRow key={org.id}>
                    <TableCell>{org.id}</TableCell>
                    <TableCell>{org.name}</TableCell>
                    <TableCell>{org.slug}</TableCell>
                    <TableCell>
                      <Badge variant={org.status === "active" ? "default" : "secondary"}>{org.status}</Badge>
                    </TableCell>
                    <TableCell className="flex justify-end gap-2">
                      {org.status === "active" ? (
                        <Button size="sm" variant="outline" onClick={() => handleDisable(org.id)}>
                          Deshabilitar
                        </Button>
                      ) : (
                        <Button size="sm" variant="outline" onClick={() => handleEnable(org.id)}>
                          Habilitar
                        </Button>
                      )}
                      <Button size="sm" variant="destructive" onClick={() => handlePurge(org.id)}>
                        Purgar
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
