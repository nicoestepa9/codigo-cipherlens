import type { ApiEndpoint, ApiKey, ApiKeyCreated, Integration } from "@/types/integration";
import { daysAgo } from "@/lib/format";

export const API_ENDPOINTS: ApiEndpoint[] = [
  {
    method: "GET",
    path: "/api/certificates?status=expiring&days=15",
    description: "List certificates expiring within a window. Filters: status, days, issuer, domain.",
    example: "curl -H \"Authorization: Bearer $API_KEY\" \"https://cipherlens.internal/api/certificates?status=expiring&days=15\"",
  },
  {
    method: "GET",
    path: "/api/certificates/{id}",
    description: "Get full certificate details including chain and related services.",
    example: "curl -H \"Authorization: Bearer $API_KEY\" https://cipherlens.internal/api/certificates/cert_42",
  },
  {
    method: "GET",
    path: "/api/assets/{id}/certificates",
    description: "List certificates bound to a specific asset/service.",
    example: "curl -H \"Authorization: Bearer $API_KEY\" https://cipherlens.internal/api/assets/asset_10/certificates",
  },
  {
    method: "POST",
    path: "/api/certificates",
    description: "Manually load a certificate into the inventory (origin=manual).",
    example: "curl -X POST -H \"Authorization: Bearer $API_KEY\" -H \"Content-Type: application/json\" -d '{\"pem\":\"...\",\"domain\":\"example.com\"}' https://cipherlens.internal/api/certificates",
  },
  {
    method: "GET",
    path: "/api/discovery/results",
    description: "Get the latest network discovery results with inventoried / shadow IT flags.",
    example: "curl -H \"Authorization: Bearer $API_KEY\" https://cipherlens.internal/api/discovery/results",
  },
  {
    method: "POST",
    path: "/api/discovery",
    description: "Trigger a new discovery scan over an IP range or domain list.",
    example: "curl -X POST -H \"Authorization: Bearer $API_KEY\" -H \"Content-Type: application/json\" -d '{\"ip_range\":\"10.0.0.0/24\",\"ports\":[443,8080,8000,4443]}' https://cipherlens.internal/api/discovery",
  },
  {
    method: "GET",
    path: "/api/services",
    description: "List services with their TLS configuration and linked certificate.",
    example: "curl -H \"Authorization: Bearer $API_KEY\" \"https://cipherlens.internal/api/services?scope=internal\"",
  },
  {
    method: "GET",
    path: "/api/vulnerabilities",
    description: "Aggregated vulnerabilities with severity filters.",
    example: "curl -H \"Authorization: Bearer $API_KEY\" \"https://cipherlens.internal/api/vulnerabilities?severity=critical\"",
  },
  {
    method: "GET",
    path: "/api/alerts",
    description: "List security alerts (expiration, compliance, discovery, system).",
    example: "curl -H \"Authorization: Bearer $API_KEY\" \"https://cipherlens.internal/api/alerts?status=unread\"",
  },
  {
    method: "POST",
    path: "/api/alerts/{id}/resolve",
    description: "Resolve a security alert.",
    example: "curl -X POST -H \"Authorization: Bearer $API_KEY\" https://cipherlens.internal/api/alerts/alert_7/resolve",
  },
  {
    method: "GET",
    path: "/api/history",
    description: "List previous TLS analyses and discovery runs.",
    example: "curl -H \"Authorization: Bearer $API_KEY\" https://cipherlens.internal/api/history",
  },
];

const INTEGRATIONS: Integration[] = [
  {
    id: "int_1",
    name: "Internal Cert Manager",
    type: "certificate",
    description: "Corporate certificate lifecycle manager. Syncs issuance and renewal events.",
    status: "connected",
    lastSyncAt: new Date().toISOString(),
  },
  {
    id: "int_2",
    name: "ServiceNow CMDB",
    type: "asset",
    description: "Configuration management database used for declared asset inventory.",
    status: "connected",
    lastSyncAt: new Date(Date.now() - 2 * 86_400_000).toISOString(),
  },
  {
    id: "int_3",
    name: "Splunk SIEM",
    type: "soc",
    description: "Security event pipeline. Sends alerts and discovery events.",
    status: "pending",
    lastSyncAt: null,
  },
  {
    id: "int_4",
    name: "PagerDuty",
    type: "incident",
    description: "Incident escalation for critical certificate and vulnerability alerts.",
    status: "disconnected",
    lastSyncAt: daysAgo(21),
  },
  {
    id: "int_5",
    name: "GitHub Actions Webhook",
    type: "ci",
    description: "Enforces certificate checks in deployment pipelines.",
    status: "connected",
    lastSyncAt: new Date(Date.now() - 1 * 86_400_000).toISOString(),
  },
];

let API_KEYS: ApiKey[] = [
  {
    id: "key_1",
    name: "cert-manager-sync",
    prefix: "cg_live_8f3a",
    createdAt: daysAgo(180),
    lastUsedAt: daysAgo(1),
    revoked: false,
  },
  {
    id: "key_2",
    name: "ci-pipeline",
    prefix: "cg_live_2b91",
    createdAt: daysAgo(120),
    lastUsedAt: daysAgo(2),
    revoked: false,
  },
  {
    id: "key_3",
    name: "legacy-integration",
    prefix: "cg_live_77cc",
    createdAt: daysAgo(400),
    lastUsedAt: daysAgo(120),
    revoked: true,
  },
  {
    id: "key_4",
    name: "soc-analyst-read",
    prefix: "cg_live_aa12",
    createdAt: daysAgo(60),
    lastUsedAt: daysAgo(4),
    revoked: false,
  },
];

export function getMockIntegrations(): Integration[] {
  return INTEGRATIONS;
}

export function getMockApiKeys(): ApiKey[] {
  return API_KEYS;
}

export function createMockApiKey(name: string): ApiKey {
  const chars = "abcdef0123456789";
  const token = Array.from({ length: 40 }, () => chars[Math.floor(Math.random() * chars.length)]).join("");
  const key: ApiKey = {
    id: `key_${Date.now().toString(36)}`,
    name,
    prefix: `cg_live_${token.slice(0, 4)}`,
    createdAt: new Date().toISOString(),
    lastUsedAt: null,
    revoked: false,
  };
  API_KEYS = [key, ...API_KEYS];
  return { ...key, prefix: `cg_live_${token}` };
}

export function revokeMockApiKey(id: string): void {
  const key = API_KEYS.find((k) => k.id === id);
  if (key) key.revoked = true;
}

export function createMockGrafanaViewerKey(): ApiKeyCreated {
  const chars = "abcdef0123456789";
  const token = Array.from({ length: 40 }, () => chars[Math.floor(Math.random() * chars.length)]).join("");
  const key: ApiKey = {
    id: `key_${Date.now().toString(36)}`,
    name: "grafana",
    prefix: `cg_live_${token.slice(0, 4)}`,
    createdAt: new Date().toISOString(),
    lastUsedAt: null,
    revoked: false,
  };
  API_KEYS = [key, ...API_KEYS];
  return { ...key, key: `cg_live_${token}`, prefix: `cg_live_${token}`, role: "viewer" };
}
