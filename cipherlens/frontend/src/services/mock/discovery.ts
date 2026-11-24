import type { DiscoveryResult, DiscoverySummary } from "@/types/discovery";
import { EXTERNAL_DOMAINS, INTERNAL_DOMAINS } from "./catalog";
import { mulberry32, pick } from "./utils";

const rnd = mulberry32(20260404);

const SHADOW_INTERNAL = [
  "ubuntu-test-01.internal.company.com",
  "temp-web.internal.company.com",
  "lab-gateway-01.internal.company.com",
  "legacy-db.internal.company.com",
  "raspberry-labs.internal.company.com",
  "staging-old.internal.company.com",
  "dev-box-42.internal.company.com",
  "print-server.internal.company.com",
  "nas-backup.internal.company.com",
  "iot-controller.internal.company.com",
  "shadow-vpn.internal.company.com",
];

const SHADOW_EXTERNAL = [
  "legacy-web.company.com",
  "test-api.company.com",
  "beta.company.com",
  "old-portal.company.com",
  "internal-mirror.company.com",
];

const PORTS: Record<string, number[]> = {
  HTTPS: [443, 8443],
  HTTP: [80, 8080],
  SSH: [22],
  "Mail Server": [25, 587, 993],
  "Message Broker": [9092],
  Database: [5432, 3306],
  "Container Registry": [5000],
};

let RESULTS: DiscoveryResult[] | null = null;

function buildResult(
  ipAddress: string,
  hostname: string | null,
  port: number,
  service: string,
  hasTls: boolean,
  inventoried: boolean,
  scope: "internal" | "external",
  index: number,
): DiscoveryResult {
  const tlsVersions = ["TLS 1.3", "TLS 1.2", "TLS 1.1", null];
  const osFingerprints = [
    "Linux (Ubuntu 22.04)",
    "Linux (Debian 12)",
    "Linux (Amazon Linux 2)",
    "Windows Server 2022",
    "Linux (CentOS 7)",
    null,
  ];
  return {
    id: `disc_${index}`,
    ipAddress,
    hostname,
    port,
    service,
    serviceName: service.toLowerCase().replace(/[^a-z0-9]+/g, ""),
    hasTls,
    tlsVersion: hasTls ? pick(tlsVersions.filter((t): t is string => t !== null), rnd) : null,
    osFingerprint: pick(osFingerprints, rnd),
    inventoried,
    shadowIt: !inventoried,
    scope,
    firstSeen: new Date(Date.now() - rnd() * 30 * 86_400_000).toISOString(),
    lastSeen: new Date(Date.now() - rnd() * 3 * 86_400_000).toISOString(),
  };
}

export function getDiscoveryResults(): DiscoveryResult[] {
  if (RESULTS) return RESULTS;
  const out: DiscoveryResult[] = [];
  let index = 1;

  // Internal range 10.0.0.0/24
  INTERNAL_DOMAINS.forEach((hostname, i) => {
    const ip = `10.0.0.${(i % 250) + 1}`;
    const hasTls = i % 5 !== 3;
    const service = hasTls ? (i % 7 === 0 ? "HTTPS" : pick(["HTTPS", "Database", "Message Broker", "Container Registry"], rnd)) : "HTTP";
    const port = pick(PORTS[service] ?? [443], rnd);
    out.push(buildResult(ip, hostname, port, service, hasTls, true, "internal", index++));
  });

  // Shadow IT internal
  SHADOW_INTERNAL.forEach((hostname, i) => {
    const ip = `10.0.0.${(i % 250) + 40}`;
    const service = i % 4 === 0 ? "SSH" : i % 3 === 0 ? "HTTP" : "HTTPS";
    const port = pick(PORTS[service] ?? [443], rnd);
    out.push(buildResult(ip, hostname, port, service, service !== "SSH", false, "internal", index++));
  });

  // External range
  EXTERNAL_DOMAINS.forEach((hostname, i) => {
    const ip = `${104 + Math.floor(i / 200)}.${(i * 17) % 255}.${(i * 7) % 255}.${(i % 200) + 1}`;
    const hasTls = i % 6 !== 2;
    const service = hasTls ? "HTTPS" : "HTTP";
    const port = pick(PORTS[service] ?? [443], rnd);
    out.push(buildResult(ip, hostname, port, service, hasTls, true, "external", index++));
  });

  // Shadow IT external
  SHADOW_EXTERNAL.forEach((hostname, i) => {
    const ip = `198.51.100.${i + 10}`;
    out.push(buildResult(ip, hostname, 443, "HTTPS", true, false, "external", index++));
  });

  RESULTS = out;
  return RESULTS;
}

export function runDiscoveryMock(): DiscoveryResult[] {
  return getDiscoveryResults();
}

export function getDiscoverySummary(): DiscoverySummary {
  const results = getDiscoveryResults();
  return {
    total: results.length,
    inventoried: results.filter((r) => r.inventoried).length,
    shadowIt: results.filter((r) => r.shadowIt).length,
    withTls: results.filter((r) => r.hasTls).length,
    internal: results.filter((r) => r.scope === "internal").length,
    external: results.filter((r) => r.scope === "external").length,
  };
}
