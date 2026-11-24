import { isMock } from "./config";
import { api } from "./apiClient";
import type { Agent, AgentCreated, AgentDetail } from "@/types/agent";
import { mocked, uuid } from "./mock/utils";

const mockAgents: Agent[] = [
  {
    id: "agent_demo_1",
    name: "HQ Collector",
    siteLabel: "Sede Central",
    status: "active",
    version: "1.4.0",
    lastSeenAt: new Date(Date.now() - 60_000).toISOString(),
    lastIp: "10.0.0.12",
    createdAt: new Date(Date.now() - 86_400_000 * 30).toISOString(),
    revokedAt: null,
    schemaVersion: 1,
    rulesVersion: "2026.10",
    serviceCount: 42,
    keyPrefix: "cg_demo1...",
    isOnline: true,
    reportedCapabilities: {
      allowRemoteTasks: true,
      networkCount: 2,
      portCount: 3,
      allowedNetworks: ["10.0.0.0/24", "192.168.10.0/24"],
      allowedPorts: [443, 8443, 4443],
    },
  },
  {
    id: "agent_demo_2",
    name: "Branch Collector",
    siteLabel: "Sucursal Norte",
    status: "active",
    version: "1.3.2",
    lastSeenAt: new Date(Date.now() - 3_600_000).toISOString(),
    lastIp: "192.168.10.20",
    createdAt: new Date(Date.now() - 86_400_000 * 12).toISOString(),
    revokedAt: null,
    schemaVersion: 1,
    rulesVersion: "2026.09",
    serviceCount: 11,
    keyPrefix: "cg_demo2...",
    isOnline: false,
    reportedCapabilities: {
      allowRemoteTasks: false,
      networkCount: 0,
      portCount: 0,
      allowedNetworks: [],
      allowedPorts: [],
    },
  },
];

export async function listAgents(): Promise<Agent[]> {
  if (isMock()) return mocked(mockAgents);
  return api.get<Agent[]>("/agents");
}

export async function getAgent(id: string): Promise<AgentDetail> {
  if (isMock()) {
    const agent = mockAgents.find((item) => item.id === id);
    if (!agent) throw new Error("Agent not found");
    return mocked({ agent, recentScans: [] });
  }
  return api.get<AgentDetail>(`/agents/${id}`);
}

export async function createAgent(input: {
  name: string;
  siteLabel: string;
}): Promise<AgentCreated> {
  if (isMock()) {
    const agent: AgentCreated = {
      id: uuid("agent"),
      name: input.name,
      siteLabel: input.siteLabel,
      status: "active",
      version: null,
      lastSeenAt: null,
      lastIp: null,
      createdAt: new Date().toISOString(),
      revokedAt: null,
      schemaVersion: null,
      rulesVersion: null,
      serviceCount: 0,
      keyPrefix: "cg_mock...",
      isOnline: false,
      reportedCapabilities: null,
      apiKey: "cg_mock_agent_key_only_shown_once",
    };
    mockAgents.push(agent);
    return mocked(agent);
  }
  return api.post<AgentCreated>("/agents", {
    body: { name: input.name, siteLabel: input.siteLabel },
  });
}

export async function updateAgent(
  id: string,
  input: { name?: string; siteLabel?: string },
): Promise<Agent> {
  if (isMock()) {
    const agent = mockAgents.find((item) => item.id === id);
    if (!agent) throw new Error("Agent not found");
    if (input.name !== undefined) agent.name = input.name;
    if (input.siteLabel !== undefined) agent.siteLabel = input.siteLabel;
    return mocked(agent);
  }
  return api.patch<Agent>(`/agents/${id}`, { body: input });
}

export async function rotateAgentKey(id: string): Promise<AgentCreated> {
  if (isMock()) {
    const agent = mockAgents.find((item) => item.id === id);
    if (!agent) throw new Error("Agent not found");
    return mocked({ ...agent, apiKey: "cg_mock_rotated_key_only_shown_once" });
  }
  return api.post<AgentCreated>(`/agents/${id}/rotate-key`);
}

export async function revokeAgent(id: string): Promise<void> {
  if (isMock()) {
    const index = mockAgents.findIndex((item) => item.id === id);
    if (index >= 0) mockAgents.splice(index, 1);
    return mocked(undefined);
  }
  await api.delete<void>(`/agents/${id}`);
}
