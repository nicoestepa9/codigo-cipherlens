import { isMock } from "./config";
import { api } from "./apiClient";
import type { ApiEndpoint, ApiKey, ApiKeyCreated, Integration } from "@/types/integration";
import {
  API_ENDPOINTS,
  createMockApiKey,
  createMockGrafanaViewerKey,
  getMockApiKeys,
  getMockIntegrations,
  revokeMockApiKey,
} from "./mock/integrations";
import { mocked } from "./mock/utils";

export async function getIntegrations(): Promise<Integration[]> {
  if (isMock()) return mocked(getMockIntegrations());
  return api.get<Integration[]>("/integrations");
}

export async function getApiKeys(): Promise<ApiKey[]> {
  if (isMock()) return mocked(getMockApiKeys());
  return api.get<ApiKey[]>("/api-keys");
}

export async function generateApiKey(name: string): Promise<ApiKey> {
  if (isMock()) {
    const key = createMockApiKey(name);
    return mocked(key);
  }
  return api.post<ApiKey>("/api-keys", { body: { name } });
}

/** Crea una ApiKey de rol "viewer" para consumir /api/reports/* desde Grafana. */
export async function createGrafanaViewerKey(): Promise<ApiKeyCreated> {
  if (isMock()) return mocked(createMockGrafanaViewerKey(), 80, 200);
  return api.post<ApiKeyCreated>("/api-keys", {
    body: { name: "grafana", role: "viewer" },
  });
}

export async function revokeApiKey(id: string): Promise<void> {
  if (isMock()) {
    revokeMockApiKey(id);
    return mocked(undefined, 80, 200);
  }
  await api.delete(`/api-keys/${id}`);
}

export async function getApiEndpoints(): Promise<ApiEndpoint[]> {
  if (isMock()) return mocked(API_ENDPOINTS, 50, 150);
  return api.get<ApiEndpoint[]>("/docs");
}
