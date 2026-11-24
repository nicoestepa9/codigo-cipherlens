export type Role = "admin" | "lead" | "user" | "viewer" | "operator";

export interface AuthUser {
  id: string;
  email: string;
  name: string;
  role: Role;
  isActive: boolean;
  createdAt: string | null;
  lastLoginAt: string | null;
  mustChangePassword?: boolean;
  organization_id: string | null;
}

export interface LoginResponse {
  accessToken: string;
  refreshToken: string;
  tokenType: string;
}

export interface TokenResponse {
  accessToken: string;
  refreshToken: string;
}
