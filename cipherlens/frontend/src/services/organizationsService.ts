import { api } from "./apiClient";

export interface Organization {
  id: number;
  name: string;
  slug: string;
  status: string;
  ai_mode?: string | null;
  max_agents?: number | null;
  max_cloud_scans_per_hour?: number | null;
  max_recurring_scans?: number | null;
}

export interface CreateOrganizationPayload {
  name: string;
  slug: string;
  status?: string;
  admin_email: string;
  admin_name: string;
  admin_password: string;
}

export async function listOrganizations(): Promise<Organization[]> {
  return api.get<Organization[]>("/organizations");
}

export async function createOrganization(payload: CreateOrganizationPayload): Promise<Organization> {
  return api.post<Organization>("/organizations", { body: payload });
}

export async function disableOrganization(id: number): Promise<void> {
  await api.post<void>(`/organizations/${id}/disable`);
}

export async function enableOrganization(id: number): Promise<void> {
  await api.post<void>(`/organizations/${id}/enable`);
}

export async function purgeOrganization(id: number): Promise<void> {
  await api.delete<void>(`/organizations/${id}`);
}
