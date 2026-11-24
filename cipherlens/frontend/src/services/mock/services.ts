import type { Service } from "@/types/service";
import type { SecurityStatus } from "@/types/severity";
import { getMockCertificates } from "./certificates";
import { DEPARTMENTS, EXTERNAL_DOMAINS, INTERNAL_DOMAINS, OS_FINGERPRINTS, OWNERS, SERVICES, TLS_CONFIGS } from "./catalog";
import { mulberry32, randomIp } from "./utils";

const rnd = mulberry32(20260202);

const SERVICE_PORTS: Record<string, number[]> = {
  "HTTPS Web Server": [443, 8443, 4443],
  "API Gateway": [443, 8443, 8080],
  Database: [5432, 3306, 1433],
  "Message Broker": [9092, 9093, 5671],
  "Kubernetes API": [6443, 10250],
  "Load Balancer": [443, 8443],
  "Mail Server": [993, 587, 465],
  "Identity Provider": [443, 8443],
  "CI/CD": [443, 8080, 8443],
  "Container Registry": [443, 5000],
  Monitoring: [443, 9090, 9091],
  Storage: [443, 9000],
  ERP: [443, 8000],
  CRM: [443],
  "Payment Gateway": [443, 8443],
  "VPN Gateway": [443, 4443],
  "Reverse Proxy": [443, 8080],
  "Search Engine": [443, 9200],
  "Authentication Service": [443, 8443],
  "Object Storage": [443, 9000],
};

function pickStatus(r: () => number): SecurityStatus {
  const v = r();
  if (v < 0.7) return "secure";
  if (v < 0.9) return "warning";
  return "critical";
}

function tlsConfigFor(status: SecurityStatus) {
  return TLS_CONFIGS.find((t) => t.status === status) ?? TLS_CONFIGS[0];
}

function severityForStatus(status: SecurityStatus): string | null {
  if (status === "critical") return "critical";
  if (status === "warning") return "medium";
  return null;
}

function countForStatus(status: SecurityStatus): number {
  if (status === "critical") return 6 + Math.floor(rnd() * 5);
  if (status === "warning") return 2 + Math.floor(rnd() * 4);
  return Math.floor(rnd() * 2);
}

const POOL: Service[] = [];
let seeded = false;

export function generateServices(): Service[] {
  if (seeded) return POOL;
  seeded = true;

  const certs = getMockCertificates();
  const byDomain = new Map<string, typeof certs>();
  for (const cert of certs) {
    const list = byDomain.get(cert.domain) ?? [];
    list.push(cert);
    byDomain.set(cert.domain, list);
  }

  const internalHosts = [...INTERNAL_DOMAINS];
  const externalHosts = [...EXTERNAL_DOMAINS];
  const count = 52;

  for (let i = 0; i < count; i++) {
    const internal = i < 38;
    const host = internal ? internalHosts[i % internalHosts.length] : externalHosts[i % externalHosts.length];
    const serviceName = SERVICES[Math.floor(rnd() * SERVICES.length)];
    const ports = SERVICE_PORTS[serviceName] ?? [443];
    const port = ports[Math.floor(rnd() * ports.length)];

    const domainCerts = byDomain.get(host) ?? [];
    const current = domainCerts.reduce((best, c) => (c.daysUntilExpiry > best.daysUntilExpiry ? c : best), domainCerts[0]);

    const status = pickStatus(rnd);
    const tls = tlsConfigFor(status);
    const service: Service = {
      id: `svc_${i + 1}`,
      name: serviceName,
      host,
      ipAddress: randomIp(rnd, internal),
      port,
      protocol: "tcp",
      service: serviceName.toLowerCase().replace(/[^a-z0-9]+/g, ""),
      tlsVersion: tls.protocol,
      cipherSuite: tls.cipher,
      securityStatus: status,
      certificateId: current?.id ?? null,
      certificateDomain: current?.domain ?? host,
      certificateStatus: current?.status ?? "unknown",
      certificateDaysLeft: current?.daysUntilExpiry ?? 0,
      asset: {
        id: `asset_${i + 1}`,
        name: host.split(".")[0],
        type: serviceName,
        owner: OWNERS[Math.floor(rnd() * OWNERS.length)],
        department: DEPARTMENTS[Math.floor(rnd() * DEPARTMENTS.length)],
        declared: true,
      },
      scope: internal ? "internal" : "external",
      lastSeen: new Date(Date.now() - Math.floor(rnd() * 1000 * 60 * 60 * 24 * 3)).toISOString(),
      osFingerprint: rnd() < 0.8 ? OS_FINGERPRINTS[Math.floor(rnd() * OS_FINGERPRINTS.length)] : null,
      vulnerabilityCount: countForStatus(status),
      findingsSeverity: severityForStatus(status),
    };

    if (current) {
      current.serviceId = service.id;
      current.serviceName = serviceName;
    }

    POOL.push(service);
  }

  return POOL;
}

export function getMockServices(): Service[] {
  return generateServices();
}
