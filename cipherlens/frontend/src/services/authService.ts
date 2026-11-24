import { API_BASE_URL, isMock } from "./config";
import { api, ApiError } from "./apiClient";
import type { AuthUser, LoginResponse } from "@/types/auth";
import { mocked } from "./mock/utils";
import { mockUsers, toAuthUser } from "./mock/store";

const BASE = API_BASE_URL;

let mockEmail = "admin@cipherlens.local";

export function getMockCurrentUser(name?: string): AuthUser {
  return mockCurrentUser(name);
}

function mockCurrentUser(name?: string): AuthUser {
  const match = mockUsers.find((u) => u.email.toLowerCase() === mockEmail.toLowerCase());
  if (match) {
    return toAuthUser(name !== undefined ? { ...match, name } : match);
  }
  return {
    id: "user_1",
    email: "admin@cipherlens.local",
    name: name ?? "Administrador",
    role: "admin",
    isActive: true,
    createdAt: new Date().toISOString(),
    lastLoginAt: new Date().toISOString(),
    organization_id: "org_1",
  };
}

export async function login(email: string, password: string): Promise<LoginResponse> {
  if (isMock()) {
    mockEmail = email || "admin@cipherlens.local";
    return mocked<LoginResponse>({
      accessToken: "mock-access-token",
      refreshToken: "mock-refresh-token",
      tokenType: "bearer",
    });
  }
  const response = await fetch(`${BASE}/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "same-origin",
    body: JSON.stringify({ email, password }),
  });
  if (!response.ok) {
    let message = "Credenciales inválidas";
    try {
      const payload = (await response.json()) as { detail?: string };
      message = payload.detail ?? message;
    } catch {
      // ignore
    }
    throw new ApiError(response.status, message);
  }
  return (await response.json()) as LoginResponse;
}

export async function logoutRequest(): Promise<void> {
  if (isMock()) return;
  try {
    await fetch(`${BASE}/auth/logout`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      body: "{}",
    });
  } catch {
    // ignore
  }
}

export async function fetchMe(): Promise<AuthUser> {
  if (isMock()) {
    return mocked<AuthUser>(mockCurrentUser());
  }
  return api.get<AuthUser>("/users/me");
}

export async function updateMyProfile(name: string): Promise<AuthUser> {
  if (isMock()) {
    return mocked<AuthUser>(mockCurrentUser(name));
  }
  return api.patch<AuthUser>("/users/me", { body: { name } });
}

export async function changeMyPassword(currentPassword: string, newPassword: string): Promise<void> {
  if (isMock()) return;
  await api.post("/users/me/password", { body: { currentPassword, newPassword } });
}

export async function deleteMyAccount(): Promise<void> {
  if (isMock()) return;
  await api.delete("/users/me");
}
