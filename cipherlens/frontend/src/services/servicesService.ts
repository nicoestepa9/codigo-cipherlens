import { isMock } from "./config";
import { api } from "./apiClient";
import type { Service } from "@/types/service";
import type { Paged } from "@/types/settings";
import { getMockServices } from "./mock/services";
import { mocked } from "./mock/utils";

export interface ServiceFilter {
  search?: string;
  status?: "secure" | "warning" | "critical" | "all";
  scope?: "internal" | "external" | "all";
  tlsVersion?: string;
  page?: number;
  pageSize?: number;
}

function listMock(filter: ServiceFilter = {}): Paged<Service> {
  let items = getMockServices();
  if (filter.search) {
    const q = filter.search.toLowerCase();
    items = items.filter(
      (s) => s.host.toLowerCase().includes(q) || s.name.toLowerCase().includes(q) || s.ipAddress.includes(q),
    );
  }
  if (filter.status && filter.status !== "all") {
    items = items.filter((s) => s.securityStatus === filter.status);
  }
  if (filter.scope && filter.scope !== "all") {
    items = items.filter((s) => s.scope === filter.scope);
  }
  if (filter.tlsVersion) {
    items = items.filter((s) => s.tlsVersion === filter.tlsVersion);
  }
  const total = items.length;
  const page = filter.page ?? 1;
  const pageSize = filter.pageSize ?? 12;
  return { items: items.slice((page - 1) * pageSize, page * pageSize), total, page, pageSize };
}

export async function getServices(filter: ServiceFilter = {}): Promise<Paged<Service>> {
  if (isMock()) return mocked(listMock(filter));
  return api.get<Paged<Service>>("/services", { query: { ...filter } });
}

export async function getService(id: string): Promise<Service | null> {
  if (isMock()) {
    const svc = getMockServices().find((s) => s.id === id) ?? null;
    return mocked(svc);
  }
  return api.get<Service>(`/services/${id}`);
}
