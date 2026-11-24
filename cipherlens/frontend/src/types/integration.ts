export type IntegrationStatus = "connected" | "disconnected" | "pending";

export interface Integration {
  id: string;
  name: string;
  type: string;
  description: string;
  status: IntegrationStatus;
  lastSyncAt: string | null;
}

export interface ApiKey {
  id: string;
  name: string;
  prefix: string;
  createdAt: string;
  lastUsedAt: string | null;
  revoked: boolean;
}

/** Respuesta de POST /api-keys: incluye el secreto completo (solo una vez). */
export interface ApiKeyCreated extends ApiKey {
  key: string;
  role?: string;
  expiresAt?: string | null;
}

export type HttpMethod = "GET" | "POST" | "PUT" | "DELETE";

export interface ApiEndpoint {
  method: HttpMethod;
  path: string;
  description: string;
  example: string;
}
