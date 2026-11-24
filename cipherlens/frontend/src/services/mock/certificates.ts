import type { CertificateInfo } from "@/types/certificate";
import type { CertificateStatus } from "@/types/severity";
import { EXTERNAL_DOMAINS, INTERNAL_DOMAINS, ISSUERS, KEY_TYPES } from "./catalog";
import { fingerprint, mulberry32, randomSerialNumber } from "./utils";

const DAY = 86_400_000;
const rnd = mulberry32(20260101);
const NOW = Date.now();

const CERT_POOL: CertificateInfo[] = [];
let seeded = false;

export function certStatus(days: number, criticalDays = 7, warningDays = 30): CertificateStatus {
  if (days < 0) return "expired";
  if (days < criticalDays) return "expiring_soon";
  if (days < warningDays) return "expiring_soon";
  return "valid";
}

interface Bucket {
  label: CertificateStatus;
  min: number;
  max: number;
  notAfter: (r: () => number) => Date;
}

function addDays(date: Date, days: number): Date {
  return new Date(date.getTime() + days * DAY);
}

function buildCert(index: number, domain: string, notAfter: Date, validityDays: number): CertificateInfo {
  const issuer = ISSUERS[Math.floor(rnd() * ISSUERS.length)];
  const key = KEY_TYPES[Math.floor(rnd() * KEY_TYPES.length)];
  const notBefore = addDays(notAfter, -validityDays);
  const daysUntilExpiry = Math.ceil((notAfter.getTime() - NOW) / DAY);
  const sanCount = 1 + Math.floor(rnd() * 3);
  const sans = [domain];
  for (let i = 0; i < sanCount; i++) {
    sans.push(`*.${domain.split(".").slice(-2).join(".")}`);
  }
  const serial = randomSerialNumber(rnd);
  return {
    id: `cert_${index}`,
    domain,
    commonName: domain,
    subject: { CN: domain, O: "Company Corp", C: "AR" },
    issuerName: issuer.cn,
    issuer: { CN: issuer.cn, O: issuer.o, C: issuer.c },
    serialNumber: serial,
    notBefore: notBefore.toISOString(),
    notAfter: notAfter.toISOString(),
    daysUntilExpiry,
    isExpired: daysUntilExpiry < 0,
    san: Array.from(new Set(sans)),
    keyType: key.keyType,
    keySize: key.keySize,
    signatureAlgorithm: key.alg,
    fingerprintSha256: fingerprint("6a7041850081b32dbe52400df0a2842c32d55e80ffa40e339f7c1508a913d3f4"),
    fingerprintSha1: fingerprint("868b692c5ded0ea40cb860de746eea19d0be2e7c"),
    isSelfSigned: false,
    basicConstraints: "CA=False, pathLen=None",
    keyUsage: ["digitalSignature"],
    extendedKeyUsage: ["serverAuth"],
    caIssuers: [`http://${issuer.o.toLowerCase().replace(/\s+/g, "")}/crt/${issuer.cn.toLowerCase().replace(/\s+/g, "")}.crt`],
    crlDistributionPoints: [`http://crl.${issuer.o.toLowerCase().replace(/\s+/g, "")}/${serial.slice(0, 8)}.crl`],
    ocspMustStaple: false,
    status: certStatus(daysUntilExpiry),
    origin: rnd() < 0.15 ? "manual" : "discovered",
    serviceId: null,
    serviceName: null,
  };
}

export function generateCertificates(): CertificateInfo[] {
  if (seeded) return CERT_POOL;
  seeded = true;

  const domains = [...INTERNAL_DOMAINS, ...EXTERNAL_DOMAINS];

  const buckets: Bucket[] = [
    { label: "expired", min: -120, max: -1, notAfter: (r) => addDays(new Date(), -Math.floor(r() * 120) - 1) },
    { label: "expiring_soon", min: 0, max: 6, notAfter: (r) => addDays(new Date(), Math.floor(r() * 7)) },
    { label: "expiring_soon", min: 7, max: 29, notAfter: (r) => addDays(new Date(), 7 + Math.floor(r() * 23)) },
    { label: "valid", min: 31, max: 90, notAfter: (r) => addDays(new Date(), 31 + Math.floor(r() * 60)) },
    { label: "valid", min: 91, max: 365, notAfter: (r) => addDays(new Date(), 91 + Math.floor(r() * 275)) },
    { label: "valid", min: 366, max: 825, notAfter: (r) => addDays(new Date(), 366 + Math.floor(r() * 460)) },
  ];

  const counts = [8, 5, 18, 40, 150, 121];
  let index = 1;

  counts.forEach((count, bucketIndex) => {
    for (let i = 0; i < count; i++) {
      const domain = domains[Math.floor(rnd() * domains.length)];
      const notAfter = buckets[bucketIndex].notAfter(rnd);
      const validity = 180 + Math.floor(rnd() * 520);
      CERT_POOL.push(buildCert(index++, domain, notAfter, validity));
    }
  });

  return CERT_POOL;
}

export function getMockCertificates(): CertificateInfo[] {
  return generateCertificates();
}

export interface CertFilter {
  search?: string;
  status?: CertificateStatus | "all";
  issuer?: string;
  origin?: "discovered" | "manual" | "all";
  scope?: "internal" | "external" | "all";
  sortBy?: "domain" | "daysUntilExpiry" | "notAfter" | "issuerName";
  sortDir?: "asc" | "desc";
  page?: number;
  pageSize?: number;
}

export interface PagedCerts {
  items: CertificateInfo[];
  total: number;
  page: number;
  pageSize: number;
}

export function isInternalDomain(domain: string): boolean {
  return domain.includes("internal") || domain.includes("10.") || domain.startsWith("192.168.");
}

export function listCertificates(filter: CertFilter = {}): PagedCerts {
  let items = getMockCertificates();

  if (filter.search) {
    const q = filter.search.toLowerCase();
    items = items.filter(
      (c) =>
        c.domain.toLowerCase().includes(q) ||
        c.issuerName.toLowerCase().includes(q) ||
        c.serialNumber.toLowerCase().includes(q),
    );
  }
  if (filter.status && filter.status !== "all") {
    items = items.filter((c) => c.status === filter.status);
  }
  if (filter.issuer) {
    items = items.filter((c) => c.issuerName === filter.issuer);
  }
  if (filter.origin && filter.origin !== "all") {
    items = items.filter((c) => c.origin === filter.origin);
  }
  if (filter.scope && filter.scope !== "all") {
    items = items.filter((c) => isInternalDomain(c.domain) === (filter.scope === "internal"));
  }

  const sortBy = filter.sortBy ?? "daysUntilExpiry";
  const sortDir = filter.sortDir ?? "asc";
  items = [...items].sort((a, b) => {
    let cmp = 0;
    if (sortBy === "domain") cmp = a.domain.localeCompare(b.domain);
    else if (sortBy === "daysUntilExpiry") cmp = a.daysUntilExpiry - b.daysUntilExpiry;
    else if (sortBy === "notAfter") cmp = a.notAfter.localeCompare(b.notAfter);
    else cmp = a.issuerName.localeCompare(b.issuerName);
    return sortDir === "asc" ? cmp : -cmp;
  });

  const total = items.length;
  const page = filter.page ?? 1;
  const pageSize = filter.pageSize ?? 12;
  return { items: items.slice((page - 1) * pageSize, page * pageSize), total, page, pageSize };
}

export function getIssuerOptions(): string[] {
  return Array.from(new Set(getMockCertificates().map((c) => c.issuerName))).sort();
}

export function getExpirationStats(criticalDays = 7, warningDays = 30) {
  const certs = getMockCertificates();
  const expired = certs.filter((c) => c.daysUntilExpiry < 0).length;
  const critical = certs.filter((c) => c.daysUntilExpiry >= 0 && c.daysUntilExpiry <= criticalDays).length;
  const warning = certs.filter((c) => c.daysUntilExpiry > criticalDays && c.daysUntilExpiry <= warningDays).length;
  const healthy = certs.filter((c) => c.daysUntilExpiry > warningDays).length;

  const byWindow = [
    { label: "Expired", min: -9999, max: 0, count: expired },
    { label: `0-${criticalDays} days`, min: 0, max: criticalDays, count: critical },
    { label: `${criticalDays + 1}-${warningDays} days`, min: criticalDays + 1, max: warningDays, count: warning },
    { label: `>${warningDays} days`, min: warningDays + 1, max: Number.POSITIVE_INFINITY, count: healthy },
  ];

  return { expired, critical, warning, healthy, criticalDays, warningDays, byWindow, total: certs.length };
}
