import { isMock } from "./config";
import { api } from "./apiClient";
import type { CertificateChainCert, CertificateDetail, CertificateInfo } from "@/types/certificate";
import type { Paged } from "@/types/settings";
import {
  getExpirationStats,
  getIssuerOptions,
  getMockCertificates,
  listCertificates,
  type CertFilter,
} from "./mock/certificates";
import { getMockServices } from "./mock/services";
import { getGlobalFindings } from "./mock/findings";
import { mocked } from "./mock/utils";

function buildChain(leaf: CertificateInfo): CertificateChainCert[] {
  const rootName = leaf.issuerName.startsWith("Let's")
    ? "ISRG Root X1"
    : leaf.issuerName.replace("G2", "Root").replace("WE1", "Root G2");
  return [
    {
      id: `${leaf.id}_root`,
      commonName: rootName,
      issuerName: rootName,
      isRoot: true,
      isLeaf: false,
      selfSigned: true,
      notBefore: "2019-01-01T00:00:00Z",
      notAfter: "2039-01-01T00:00:00Z",
    },
    {
      id: `${leaf.id}_intermediate`,
      commonName: leaf.issuerName,
      issuerName: rootName,
      isRoot: false,
      isLeaf: false,
      selfSigned: false,
      notBefore: "2020-01-01T00:00:00Z",
      notAfter: "2030-01-01T00:00:00Z",
    },
    {
      id: leaf.id,
      commonName: leaf.commonName,
      issuerName: leaf.issuerName,
      isRoot: false,
      isLeaf: true,
      selfSigned: false,
      notBefore: leaf.notBefore,
      notAfter: leaf.notAfter,
    },
  ];
}

function buildDetail(id: string): CertificateDetail | null {
  const cert = getMockCertificates().find((c) => c.id === id);
  if (!cert) return null;

  const relatedServices = getMockServices()
    .filter((s) => s.certificateId === id)
    .map((s) => ({
      id: s.id,
      name: s.name,
      host: s.host,
      port: s.port,
      tlsVersion: s.tlsVersion,
      securityStatus: s.securityStatus,
    }));

  const relatedFindings = getGlobalFindings().filter((f) => f.affectedHost === cert.domain).length;

  return {
    certificate: cert,
    chain: buildChain(cert),
    relatedServices,
    relatedFindings,
  };
}

export async function getCertificates(filter: CertFilter = {}): Promise<Paged<CertificateInfo>> {
  if (isMock()) return mocked(listCertificates(filter));
  return api.get<Paged<CertificateInfo>>("/certificates", { query: { ...filter } });
}

export async function getCertificateDetail(id: string): Promise<CertificateDetail | null> {
  if (isMock()) return mocked(buildDetail(id));
  return api.get<CertificateDetail>(`/certificates/${id}`);
}

export interface ExpirationStats {
  expired: number;
  critical: number;
  warning: number;
  healthy: number;
  total: number;
  criticalDays: number;
  warningDays: number;
  byWindow: { label: string; min: number; max: number; count: number }[];
}

export async function getExpirationStatsService(criticalDays?: number, warningDays?: number): Promise<ExpirationStats> {
  if (isMock()) return mocked(getExpirationStats(criticalDays ?? 7, warningDays ?? 30));
  const query: Record<string, number> = {};
  if (criticalDays !== undefined) query.criticalDays = criticalDays;
  if (warningDays !== undefined) query.warningDays = warningDays;
  return api.get<ExpirationStats>("/certificates/expiration-stats", { query });
}

export async function getIssuerOptionsService(): Promise<string[]> {
  if (isMock()) return mocked(getIssuerOptions(), 50, 150);
  return api.get<string[]>("/certificates/issuers");
}
