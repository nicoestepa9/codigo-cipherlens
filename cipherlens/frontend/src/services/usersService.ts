import { isMock } from "./config";
import { api } from "./apiClient";
import type { AuthUser, Role } from "@/types/auth";
import type { Paged } from "@/types/settings"; // Paged may be used elsewhere; keep if needed
import { mocked } from "./mock/utils";
import { mockUsers, toAuthUser, type MockUser } from "./mock/store";

export interface UserDirectoryEntry {
  id: string;
  name: string;
  email: string;
  role: Role | string;
}

export async function listUsers(): Promise<AuthUser[]> {
  if (isMock()) return mocked(mockUsers.filter((u) => u.isActive).map(toAuthUser));
  return api.get<AuthUser[]>("/users");
}

export async function listUserDirectory(): Promise<UserDirectoryEntry[]> {
  if (isMock()) {
    return mocked(
      mockUsers.filter((u) => u.isActive).map((u) => ({ id: u.id, name: u.name, email: u.email, role: u.role as Role })),
    );
  }
  return api.get<UserDirectoryEntry[]>("/users/directory");
}

export async function createUser(input: { email: string; name: string; password: string; role: Role | string }): Promise<AuthUser> {
  if (isMock()) {
    const user: MockUser = {
      id: `user_${Math.random().toString(36).slice(2, 8)}`,
      email: input.email,
      name: input.name,
      role: input.role as MockUser["role"],
      isActive: true,
      createdAt: new Date().toISOString(),
      lastLoginAt: null,
      organization_id: null,
    };
    mockUsers.push(user);
    return mocked(toAuthUser(user));
  }
  return api.post<AuthUser>("/users", { body: { email: input.email, name: input.name, password: input.password, role: input.role } });
}

export async function getUser(id: string): Promise<AuthUser | null> {
  if (isMock()) {
    const user = mockUsers.find((u) => u.id === id) ?? null;
    return mocked(user ? toAuthUser(user) : null);
  }
  return api.get<AuthUser>(`/users/${id}`);
}

export async function updateUser(
  id: string,
  input: { name?: string; role?: Role | string; isActive?: boolean },
): Promise<AuthUser> {
  if (isMock()) {
    const user = mockUsers.find((u) => u.id === id);
    if (!user) throw new Error("Usuario no encontrado");
    if (input.name !== undefined) user.name = input.name;
    if (input.role !== undefined) user.role = input.role as MockUser["role"];
    if (input.isActive !== undefined) user.isActive = input.isActive;
    return mocked(toAuthUser(user));
  }
  return api.patch<AuthUser>(`/users/${id}`, { body: { name: input.name, role: input.role, isActive: input.isActive } });
}

export async function deleteUser(id: string): Promise<void> {
  if (isMock()) {
    const idx = mockUsers.findIndex((u) => u.id === id);
    if (idx >= 0) mockUsers.splice(idx, 1);
    return mocked(undefined);
  }
  await api.delete(`/users/${id}`);
}
