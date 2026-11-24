"use client";

import { useState, useEffect, useCallback } from "react";
import { useRouter } from "next/navigation";
import { useAuth, useRole } from "@/components/auth/AuthContext";
import {
  listTeams,
  createTeam,
  updateTeam,
  deleteTeam,
  addTeamMember,
  removeTeamMember,
  listTeamMembers,
} from "@/services/teamsService";
import type { Team, TeamMember } from "@/types/team";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Crown, Loader2, Pencil, Trash2, UserPlus, UsersRound, X } from "lucide-react";

export default function TeamsPage() {
  const { user } = useAuth();
  const { isAdmin, canAssign } = useRole();
  const router = useRouter();
  const [teams, setTeams] = useState<Team[]>([]);
  const [directory, setDirectory] = useState<TeamMember[]>([]);
  const [loading, setLoading] = useState(true);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [editingTeam, setEditingTeam] = useState<Team | null>(null);
  const [form, setForm] = useState({ name: "", description: "" });
  const [saving, setSaving] = useState(false);
  const [addingTo, setAddingTo] = useState<string | null>(null);

  useEffect(() => {
    if (!canAssign) {
      router.push("/dashboard");
    }
  }, [canAssign, router]);

  const load = useCallback(async () => {
    try {
      const [teamList, users] = await Promise.all([listTeams(), listTeamMembers()]);
      setTeams(teamList);
      const orgId = user?.organization_id;
      const filteredDirectory = orgId != null
        ? users.filter((u) => u.organization_id === orgId)
        : users;
      setDirectory(filteredDirectory);
    } catch {
      // ignore
    } finally {
      setLoading(false);
    }
  }, [user]);

  useEffect(() => {
    if (canAssign) {
      void load();
    }
  }, [canAssign, load]);

  const memberName = (id: string) => directory.find((d) => d.id === id)?.name ?? id;

  const isMemberLead = (team: Team, userId: string) =>
    (team.leadIds ?? []).includes(userId);

  const canManageMembers = (team: Team) =>
    isAdmin || (team.leadIds ?? []).includes(user?.id ?? "");

  const openCreate = () => {
    setEditingTeam(null);
    setForm({ name: "", description: "" });
    setDialogOpen(true);
  };

  const openEdit = (t: Team) => {
    setEditingTeam(t);
    setForm({ name: t.name, description: t.description ?? "" });
    setDialogOpen(true);
  };

  const handleSave = async () => {
    setSaving(true);
    try {
      if (editingTeam) {
        await updateTeam(editingTeam.id, { name: form.name, description: form.description });
      } else {
        await createTeam({ name: form.name, description: form.description, memberIds: [] });
      }
      setDialogOpen(false);
      await load();
    } catch (err) {
      alert(err instanceof Error ? err.message : "Error al guardar equipo");
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async (t: Team) => {
    if (!confirm(`¿Eliminar equipo ${t.name}?`)) return;
    try {
      await deleteTeam(t.id);
      await load();
    } catch (err) {
      alert(err instanceof Error ? err.message : "Error al eliminar equipo");
    }
  };

  const handleAddMember = async (teamId: string, userId: string, isLead = false) => {
    try {
      await addTeamMember(teamId, userId, isLead);
      setAddingTo(null);
      await load();
    } catch (err) {
      alert(err instanceof Error ? err.message : "Error al agregar miembro");
    }
  };

  const handlePromote = async (teamId: string, userId: string) => {
    try {
      await addTeamMember(teamId, userId, true);
      await load();
    } catch (err) {
      alert(err instanceof Error ? err.message : "Error al designar líder");
    }
  };

  const handleRemoveMember = async (teamId: string, userId: string) => {
    try {
      await removeTeamMember(teamId, userId);
      await load();
    } catch (err) {
      alert(err instanceof Error ? err.message : "Error al quitar miembro");
    }
  };

  if (!canAssign) return null;

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <CardTitle className="flex items-center gap-2">
            Equipos
            {!isAdmin && (
              <Badge variant="secondary" className="gap-1 font-normal">
                <Crown className="h-3.5 w-3.5" />
                Líder de equipo
              </Badge>
            )}
          </CardTitle>
          {isAdmin && (
            <Button onClick={openCreate}>
              <UsersRound className="mr-1.5 h-4 w-4" />
              Nuevo equipo
            </Button>
          )}
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="flex justify-center py-8">
              <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
            </div>
          ) : teams.length === 0 ? (
            <p className="py-8 text-center text-muted-foreground">
              {isAdmin
                ? "No hay equipos. Creá uno para comenzar."
                : "No liderás ningún equipo todavía."}
            </p>
          ) : (
            <div className="space-y-3">
              {teams.map((team) => {
                const memberIds = team.memberIds ?? [];
                const manageable = canManageMembers(team);
                const available = directory.filter((d) => !memberIds.includes(d.id));
                return (
                  <div key={team.id} className="rounded-lg border p-4">
                    <div className="flex items-start justify-between gap-4">
                      <div className="space-y-1">
                        <div className="flex items-center gap-2">
                          <span className="font-medium">{team.name}</span>
                          <Badge variant="secondary">
                            {team.memberCount} miembro{team.memberCount !== 1 ? "s" : ""}
                          </Badge>
                        </div>
                        {team.description && (
                          <p className="text-sm text-muted-foreground">{team.description}</p>
                        )}
                      </div>
                      {isAdmin && (
                        <div className="flex gap-1">
                          <Button size="sm" variant="ghost" onClick={() => openEdit(team)}>
                            <Pencil className="h-4 w-4" />
                          </Button>
                          <Button size="sm" variant="ghost" onClick={() => void handleDelete(team)}>
                            <Trash2 className="h-4 w-4 text-destructive" />
                          </Button>
                        </div>
                      )}
                    </div>

                    <div className="mt-3 flex flex-wrap items-center gap-2">
                      {memberIds.map((uid) => (
                        <Badge
                          key={uid}
                          variant={isMemberLead(team, uid) ? "default" : "outline"}
                          className="gap-1 py-1 pr-1"
                        >
                          {isMemberLead(team, uid) && <Crown className="h-3 w-3" />}
                          {memberName(uid)}
                          {manageable && isAdmin && !isMemberLead(team, uid) && (
                            <button
                              type="button"
                              className="ml-1 rounded-full p-0.5 hover:bg-muted"
                              onClick={() => void handlePromote(team.id, uid)}
                              aria-label={`Designar líder a ${memberName(uid)}`}
                            >
                              <Crown className="h-3 w-3" />
                            </button>
                          )}
                          {manageable && (
                            <button
                              type="button"
                              className="ml-1 rounded-full p-0.5 hover:bg-muted"
                              onClick={() => void handleRemoveMember(team.id, uid)}
                              aria-label={`Quitar ${memberName(uid)}`}
                            >
                              <X className="h-3 w-3" />
                            </button>
                          )}
                        </Badge>
                      ))}

                      {manageable &&
                        (addingTo === team.id ? (
                          <Select value="" onValueChange={(v) => void handleAddMember(team.id, v, false)}>
                            <SelectTrigger className="h-8 w-56">
                              <SelectValue placeholder="Seleccionar usuario" />
                            </SelectTrigger>
                            <SelectContent>
                              {available.length === 0 ? (
                                <SelectItem value="__none" disabled>
                                  No hay usuarios disponibles
                                </SelectItem>
                              ) : (
                                available.map((u) => (
                                  <SelectItem key={u.id} value={u.id}>
                                    {u.name} ({u.email})
                                  </SelectItem>
                                ))
                              )}
                            </SelectContent>
                          </Select>
                        ) : (
                          <Button
                            size="sm"
                            variant="outline"
                            className="h-8"
                            disabled={available.length === 0}
                            onClick={() => setAddingTo(team.id)}
                          >
                            <UserPlus className="mr-1 h-3.5 w-3.5" />
                            Agregar miembro
                          </Button>
                        ))}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </CardContent>
      </Card>

      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{editingTeam ? "Editar equipo" : "Nuevo equipo"}</DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <Input
              placeholder="Nombre del equipo"
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
            />
            <Input
              placeholder="Descripción"
              value={form.description}
              onChange={(e) => setForm({ ...form, description: e.target.value })}
            />
            <Button onClick={() => void handleSave()} disabled={saving} className="w-full">
              {saving && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Guardar
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}
