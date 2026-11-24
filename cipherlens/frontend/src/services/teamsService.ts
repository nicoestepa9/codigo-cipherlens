import { isMock } from "./config";
import { api } from "./apiClient";
import type { Team, TeamMember } from "@/types/team";
import { mocked } from "./mock/utils";
import { mockTeamMembers, mockTeams } from "./mock/store";

export async function listTeams(): Promise<Team[]> {
  if (isMock()) return mocked([...mockTeams]);
  return api.get<Team[]>("/teams");
}

export async function getTeam(id: string): Promise<Team | null> {
  if (isMock()) {
    const team = mockTeams.find((t) => t.id === id) ?? null;
    return mocked(team ? { ...team } : null);
  }
  return api.get<Team>(`/teams/${id}`);
}

export async function createTeam(input: { name: string; description?: string; memberIds?: string[] }): Promise<Team> {
  if (isMock()) {
    const team: Team = {
      id: `team_${Math.random().toString(36).slice(2, 8)}`,
      name: input.name,
      description: input.description ?? null,
      createdAt: new Date().toISOString(),
      memberIds: input.memberIds ?? [],
      memberCount: input.memberIds?.length ?? 0,
      leadIds: [],
    };
    mockTeams.push(team);
    return mocked({ ...team });
  }
  return api.post<Team>("/teams", { body: { name: input.name, description: input.description, memberIds: input.memberIds } });
}

export async function updateTeam(id: string, input: { name?: string; description?: string }): Promise<Team> {
  if (isMock()) {
    const team = mockTeams.find((t) => t.id === id);
    if (!team) throw new Error("Equipo no encontrado");
    if (input.name !== undefined) team.name = input.name;
    if (input.description !== undefined) team.description = input.description;
    return mocked({ ...team });
  }
  return api.patch<Team>(`/teams/${id}`, { body: { name: input.name, description: input.description } });
}

export async function addTeamMember(teamId: string, userId: string, isLead = false): Promise<Team> {
  if (isMock()) {
    const team = mockTeams.find((t) => t.id === teamId);
    if (!team) throw new Error("Equipo no encontrado");
    if (!team.memberIds?.includes(userId)) {
      team.memberIds = [...(team.memberIds ?? []), userId];
      team.memberCount = team.memberIds.length;
    }
    if (isLead && !(team.leadIds ?? []).includes(userId)) {
      team.leadIds = [...(team.leadIds ?? []), userId];
    }
    return mocked({ ...team });
  }
  return api.post<Team>(`/teams/${teamId}/members`, { body: { userId, isLead } });
}

export async function removeTeamMember(teamId: string, userId: string): Promise<Team> {
  if (isMock()) {
    const team = mockTeams.find((t) => t.id === teamId);
    if (!team) throw new Error("Equipo no encontrado");
    team.memberIds = (team.memberIds ?? []).filter((id) => id !== userId);
    team.memberCount = team.memberIds.length;
    team.leadIds = (team.leadIds ?? []).filter((id) => id !== userId);
    return mocked({ ...team });
  }
  return api.delete<Team>(`/teams/${teamId}/members/${userId}`);
}

export async function deleteTeam(id: string): Promise<void> {
  if (isMock()) {
    const idx = mockTeams.findIndex((t) => t.id === id);
    if (idx >= 0) mockTeams.splice(idx, 1);
    return mocked(undefined);
  }
  await api.delete(`/teams/${id}`);
}

export async function listTeamMembers(orgId?: string): Promise<TeamMember[]> {
  if (isMock()) return mocked([...mockTeamMembers]);
  const users = await api.get<{ id: string; name: string; email: string; role: string; organization_id: string | number | null }[]>("/users/directory", { organization_id: orgId });
  return users.map((u) => ({ id: u.id, name: u.name, email: u.email, role: u.role, organization_id: u.organization_id ?? null }));
}
