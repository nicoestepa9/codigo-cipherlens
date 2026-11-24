import type { CertificateInfo } from "@/types/certificate";
import type { CipherSuite, HandshakeStep, OsFingerprint, ScanOptions, ScanResult } from "@/types/scan";
import type { HistoryEntry } from "@/types/history";
import { getMockCertificates } from "./certificates";
import { findingsForTarget } from "./findings";
import { KEY_TYPES, OS_FINGERPRINTS, TLS_CONFIGS } from "./catalog";
import { daysAgo, daysFromNow } from "@/lib/format";
import { mulberry32, randomIp, randomSerialNumber, fingerprint, pick, randInt } from "./utils";

function hashString(input: string): number {
  let h = 0;
  for (let i = 0; i < input.length; i++) {
    h = (h << 5) - h + input.charCodeAt(i);
    h |= 0;
  }
  return Math.abs(h);
}

function isInternalTarget(host: string): boolean {
  return (
    host.includes("internal") ||
    host.startsWith("10.") ||
    host.startsWith("192.168.") ||
    host.startsWith("172.16.") ||
    host.includes("kafka") ||
    host.includes("elasticsearch")
  );
}

function syntheticLeaf(host: string, port: number, notAfterOffsetDays: number): CertificateInfo {
  const key = KEY_TYPES[Math.floor(Math.random() * KEY_TYPES.length)];
  const rnd = mulberry32(hashString(host + port));
  const issuerName = pick(["DigiCert Global CA G2", "Let's Encrypt Authority X3", "Google Trust Services WE1"], rnd);
  const notAfter = new Date(Date.now() + notAfterOffsetDays * 86_400_000).toISOString();
  return {
    id: `cert_synth_${host.replace(/[^a-z0-9]/gi, "_")}_${port}`,
    domain: host,
    commonName: host,
    subject: { CN: host, O: "Company Corp", C: "AR" },
    issuerName,
    issuer: { CN: issuerName, O: "CA", C: "US" },
    serialNumber: randomSerialNumber(rnd),
    notBefore: new Date(Date.now() - 400 * 86_400_000).toISOString(),
    notAfter,
    daysUntilExpiry: Math.ceil((new Date(notAfter).getTime() - Date.now()) / 86_400_000),
    isExpired: notAfterOffsetDays < 0,
    san: [host, `*.${host.split(".").slice(-2).join(".")}`],
    keyType: key.keyType,
    keySize: key.keySize,
    signatureAlgorithm: key.alg,
    fingerprintSha256: fingerprint(randomSerialNumber(rnd).replace(/:/g, "")),
    fingerprintSha1: fingerprint(randomSerialNumber(rnd).replace(/:/g, "")),
    isSelfSigned: false,
    basicConstraints: "CA=False, pathLen=None",
    keyUsage: ["digitalSignature"],
    extendedKeyUsage: ["serverAuth"],
    caIssuers: [`http://ca.corp/crt/${issuerName.toLowerCase().replace(/\s+/g, "")}.crt`],
    crlDistributionPoints: [`http://crl.corp/${issuerName.toLowerCase().replace(/\s+/g, "")}.crl`],
    ocspMustStaple: false,
    status: notAfterOffsetDays < 0 ? "expired" : notAfterOffsetDays < 30 ? "expiring_soon" : "valid",
    origin: "discovered",
    serviceId: null,
    serviceName: null,
  };
}

function buildChain(leaf: CertificateInfo): CertificateInfo[] {
  const root: CertificateInfo = {
    ...leaf,
    id: `${leaf.id}_root`,
    commonName: leaf.issuerName.startsWith("Let's") ? "ISRG Root X1" : leaf.issuerName.replace("G2", "Root").replace("WE1", "Root G2"),
    issuerName: leaf.issuerName.startsWith("Let's") ? "ISRG Root X1" : leaf.issuerName.replace("G2", "Root").replace("WE1", "Root G2"),
    isSelfSigned: true,
    basicConstraints: "CA=True, pathLen=None",
    subject: { CN: leaf.issuerName.startsWith("Let's") ? "ISRG Root X1" : leaf.issuerName, O: leaf.issuer.o ?? "CA", C: "US" },
    keyType: "RSA",
    keySize: 4096,
    signatureAlgorithm: "sha256WithRSAEncryption",
    notBefore: daysAgo(1460),
    notAfter: daysFromNow(365),
    daysUntilExpiry: 365,
    status: "valid",
    san: [],
    extendedKeyUsage: [],
    caIssuers: [],
    crlDistributionPoints: [],
  };
  const intermediate: CertificateInfo = {
    ...leaf,
    id: `${leaf.id}_intermediate`,
    commonName: leaf.issuerName,
    issuerName: root.commonName,
    isSelfSigned: false,
    basicConstraints: "CA=True, pathLen=0",
    subject: { CN: leaf.issuerName, O: leaf.issuer.o ?? "CA", C: "US" },
    san: [],
    extendedKeyUsage: [],
    keyUsage: ["certificateSign", "crlSign"],
    caIssuers: [root.commonName],
  };
  return [root, intermediate, leaf];
}

function buildCipherSuites(status: string, protocol: string, selectedCipher: string): CipherSuite[] {
  const all: CipherSuite[] = [
    { name: "TLS_AES_256_GCM_SHA384", protocol: "TLS 1.3", keyExchange: "X25519", encryption: "AES-256-GCM", mac: "AEAD", bits: 256, status: "secure" },
    { name: "TLS_CHACHA20_POLY1305_SHA256", protocol: "TLS 1.3", keyExchange: "X25519", encryption: "ChaCha20-Poly1305", mac: "AEAD", bits: 256, status: "secure" },
    { name: "TLS_AES_128_GCM_SHA256", protocol: "TLS 1.3", keyExchange: "X25519", encryption: "AES-128-GCM", mac: "AEAD", bits: 128, status: "secure" },
    { name: "ECDHE-ECDSA-AES256-GCM-SHA384", protocol: "TLS 1.2", keyExchange: "ECDHE", encryption: "AES-256-GCM", mac: "AEAD", bits: 256, status: "secure" },
    { name: "ECDHE-RSA-AES256-GCM-SHA384", protocol: "TLS 1.2", keyExchange: "ECDHE", encryption: "AES-256-GCM", mac: "AEAD", bits: 256, status: "secure" },
    { name: "ECDHE-RSA-AES128-GCM-SHA256", protocol: "TLS 1.2", keyExchange: "ECDHE", encryption: "AES-128-GCM", mac: "AEAD", bits: 128, status: "secure" },
    { name: "ECDHE-RSA-AES256-SHA384", protocol: "TLS 1.2", keyExchange: "ECDHE", encryption: "AES-256-CBC", mac: "SHA384", bits: 256, status: "warning" },
    { name: "ECDHE-RSA-AES128-SHA256", protocol: "TLS 1.2", keyExchange: "ECDHE", encryption: "AES-128-CBC", mac: "SHA256", bits: 128, status: "warning" },
    { name: "ECDHE-RSA-AES256-CBC-SHA", protocol: "TLS 1.1", keyExchange: "ECDHE", encryption: "AES-256-CBC", mac: "SHA1", bits: 256, status: "warning" },
    { name: "TLS_RSA_WITH_AES_128_CBC_SHA", protocol: "TLS 1.0", keyExchange: "RSA", encryption: "AES-128-CBC", mac: "SHA1", bits: 128, status: "critical" },
    { name: "TLS_RSA_WITH_3DES_EDE_CBC_SHA", protocol: "TLS 1.2", keyExchange: "RSA", encryption: "3DES-EDE-CBC", mac: "SHA1", bits: 168, status: "critical" },
  ];

  const suiteList = status === "critical" ? all : status === "warning" ? all.filter((s) => s.status !== "critical") : all.filter((s) => s.status === "secure");
  return suiteList.map((s) => ({ ...s, selected: s.name === selectedCipher }));
}

function buildHandshakeSteps(protocol: string, cipher: string): HandshakeStep[] {
  const tls13 = protocol.includes("1.3");
  const steps: HandshakeStep[] = [
    {
      step: "ClientHello",
      actor: "client",
      description: `Client offers TLS version support and ${tls13 ? "key_share for X25519" : "cipher suites"}.`,
      details: tls13
        ? "supported_versions: 1.3, 1.2 | key_share: X25519 | signature_algorithms: rsa_pss_rsae_sha256, ecdsa_secp256r1_sha256"
        : "cipher_suites: ECDHE-RSA-AES256-GCM-SHA384, ECDHE-RSA-AES128-GCM-SHA256 | signature_algorithms: rsa_pss_rsae_sha256",
    },
    {
      step: "ServerHello",
      actor: "server",
      description: `Server selects ${protocol} with ${cipher}.`,
      details: `selected_version: ${protocol} | cipher_suite: ${cipher} | ${tls13 ? "key_share: X25519" : "renegotiation_info: present"}`,
    },
    {
      step: "Certificate",
      actor: "server",
      description: "Server sends its X.509 certificate chain (leaf, intermediate, root).",
      details: "certificates: 3 | compression_method: null | ocsp_stapling: false",
    },
  ];
  if (tls13) {
    steps.push(
      {
        step: "CertificateVerify",
        actor: "server",
        description: "Server signs the handshake transcript to prove possession of the private key.",
        details: "signature_algorithm: rsa_pss_rsae_sha256 | signature: 256 bytes",
      },
      {
        step: "Finished",
        actor: "client",
        description: "Client verifies the transcript and finishes the handshake.",
        details: "verify_data: 32 bytes | no session resumption",
      },
    );
  } else {
    steps.push({
      step: "ChangeCipherSpec",
      actor: "client",
      description: "Client switches to encrypted communication.",
      details: "record_type: handshake | message: change_cipher_spec",
    });
  }
  steps.push({
    step: "Secure Connection Established",
    actor: "server",
    description: `Handshake complete. Application data is now encrypted with ${cipher}.`,
    details: `protocol: ${protocol} | session_ticket: issued`,
  });
  return steps;
}

function buildOsFingerprint(host: string, internal: boolean): OsFingerprint {
  if (!internal && !host.includes("internal")) {
    const rnd = mulberry32(hashString(host));
    return {
      detected: true,
      os: pick(["Linux (Ubuntu)", "Linux (Debian)", "Linux (Amazon Linux 2)"], rnd),
      service: pick(["nginx/1.24", "CloudFront", "Apache/2.4.57", "OpenResty/1.21"], rnd),
      banner: pick(["nginx/1.24.0", "Apache/2.4.57 (Ubuntu)", "cloudfront", "openresty/1.21.4.2"], rnd),
      confidence: "high",
      note: "Fingerprint derived from TLS handshake timing and ServerHello banner.",
    };
  }
  const entry = OS_FINGERPRINTS[Math.floor(Math.random() * OS_FINGERPRINTS.length)];
  return {
    detected: true,
    os: entry.split(" — ")[0],
    service: entry.split(" — ")[1],
    banner: entry.split(" — ")[1],
    confidence: "medium",
    note: "Fingerprint derived from TLS handshake + banner grab.",
  };
}

function buildAiRecommendation(score: number, findings: ReturnType<typeof findingsForTarget>): string {
  if (score >= 85) {
    return `Target shows a strong TLS posture. ${findings.length} informational findings were detected (e.g. missing OCSP stapling). Recommended actions: enable OCSP stapling and review ALPN configuration to prepare for HTTP/2. No immediate remediation required.`;
  }
  if (score >= 65) {
    const critical = findings.filter((f) => f.severity === "critical" || f.severity === "high");
    return `Target has a moderate TLS posture with ${findings.length} findings (${critical.length} critical/high). Prioritize: ${critical.map((f) => f.title).join("; ") || "review cipher suite configuration"}. Recommend updating the server configuration to enforce TLS 1.2+, removing deprecated ciphers, and renewing the certificate if it expires within the alert threshold.`;
  }
  return `Target has a weak TLS posture (score ${score}/100). The following critical issues must be addressed: ${findings
    .filter((f) => f.severity === "critical" || f.severity === "high")
    .map((f) => f.title)
    .join("; ")}. Immediate actions: disable TLS 1.0/1.1, remove 3DES and RSA key transport suites, re-issue the certificate if signed with SHA-1, and re-scan after changes.`;
}

export function generateScanResult(host: string, port: number, options: ScanOptions = {}): ScanResult {
  const rnd = mulberry32(hashString(`${host}:${port}`));
  const internal = isInternalTarget(host);
  const statusRoll = rnd();
  const status: ScanResult["status"] = internal
    ? statusRoll < 0.4
      ? "critical"
      : statusRoll < 0.75
        ? "warning"
        : "secure"
    : statusRoll < 0.12
      ? "warning"
      : "secure";

  const config = TLS_CONFIGS.find((t) => t.status === status) ?? TLS_CONFIGS[0];
  const score = status === "critical" ? randInt(28, 55, rnd) : status === "warning" ? randInt(62, 82, rnd) : randInt(88, 100, rnd);

  const portIsAlternate = (options.alternatePorts?.length ?? 0) > 0 && options.alternatePorts!.includes(port);
  const certificatePool = getMockCertificates();
  const poolCert = certificatePool.find((c) => c.domain === host);
  const leaf =
    poolCert ??
    syntheticLeaf(host, port, status === "critical" ? randInt(-10, 20, rnd) : randInt(60, 300, rnd));

  const findings = findingsForTarget(host, "TLS Service", status, leaf.daysUntilExpiry);
  const duration = randInt(900, 4800, rnd);

  return {
    id: `scan_${Date.now().toString(36)}_${Math.floor(rnd() * 9999)}`,
    target: `${host}:${port}`,
    host,
    port,
    portIsAlternate,
    ipAddress: randomIp(rnd, internal),
    scanStartedAt: new Date().toISOString(),
    scanDurationMs: duration,
    profile: options.profile ?? "citizen-facing",
    score,
    status,
    negotiatedProtocol: config.protocol,
    negotiatedCipher: config.cipher,
    keyExchange: config.keyExchange,
    signatureAlgorithm: config.signature,
    supportedProtocols:
      status === "critical" ? ["TLS 1.0", "TLS 1.1", "TLS 1.2"] : status === "warning" ? ["TLS 1.2", "TLS 1.3"] : ["TLS 1.2", "TLS 1.3"],
    cipherSuites: buildCipherSuites(status, config.protocol, config.cipher),
    certificate: leaf,
    chain: buildChain(leaf),
    findings,
    osFingerprint: buildOsFingerprint(host, internal),
    handshakeSteps: buildHandshakeSteps(config.protocol, config.cipher),
    aiRecommendation: buildAiRecommendation(score, findings),
    connectionError: null,
  };
}

const HISTORY: HistoryEntry[] = [];
const SCAN_RESULTS = new Map<string, ScanResult>();
let historySeeded = false;

export function seedHistory(): HistoryEntry[] {
  if (historySeeded) return HISTORY;
  historySeeded = true;

  const targets = [
    { host: "example.com", port: 443 },
    { host: "cloudflare.com", port: 443 },
    { host: "github.com", port: 443 },
    { host: "google.com", port: 443 },
    { host: "www.youtube.com", port: 443 },
    { host: "api.internal.company.com", port: 443 },
    { host: "legacy.internal.company.com", port: 443 },
    { host: "payments.internal.company.com", port: 443 },
    { host: "api.internal.company.com", port: 8080 },
    { host: "vpn.company.com", port: 4443 },
    { host: "portal.company.com", port: 443 },
    { host: "db-primary.internal.company.com", port: 5432 },
    { host: "erp.internal.company.com", port: 443 },
  ];

  targets.forEach((t, index) => {
    const result = generateScanResult(t.host, t.port, {
      alternatePorts: t.port !== 443 ? [t.port] : [],
    });
    result.id = `scan_hist_${index + 1}`;
    result.scanStartedAt = daysAgo((targets.length - index) * 2 + 1);
    SCAN_RESULTS.set(result.id, result);
    HISTORY.push({
      id: result.id,
      target: result.target,
      host: t.host,
      port: t.port,
      kind: "tls_scan",
      date: result.scanStartedAt,
      score: result.score,
      durationMs: result.scanDurationMs,
      status: "completed",
      profile: result.profile,
    });
  });

  HISTORY.push({
    id: "hist_discovery_1",
    target: "10.0.0.0/24",
    host: "10.0.0.0/24",
    port: 0,
    kind: "discovery",
    date: daysAgo(3),
    score: null,
    durationMs: 42000,
    status: "completed",
    profile: "citizen-facing",
  });

  return HISTORY;
}

export function getHistoryEntries(): HistoryEntry[] {
  return seedHistory();
}

export function getStoredScanResult(id: string): ScanResult | null {
  return SCAN_RESULTS.get(id) ?? null;
}

export async function executeScan(host: string, port: number, options: ScanOptions): Promise<ScanResult> {
  let effectivePort = port;
  let usedAlternate = false;
  if (port === 443 && options.alternatePorts && options.alternatePorts.length > 0) {
    const probe = mulberry32(hashString(host) + 7);
    const failsOn443 = isInternalTarget(host) ? probe() < 0.45 : probe() < 0.1;
    if (failsOn443) {
      effectivePort = options.alternatePorts[0];
      usedAlternate = true;
    }
  }
  const result = generateScanResult(host, effectivePort, options);
  result.port = effectivePort;
  result.target = `${host}:${effectivePort}`;
  result.portIsAlternate = usedAlternate;
  SCAN_RESULTS.set(result.id, result);
  HISTORY.unshift({
    id: result.id,
    target: result.target,
    host,
    port,
    kind: "tls_scan",
    date: result.scanStartedAt,
    score: result.score,
    durationMs: result.scanDurationMs,
    status: "completed",
    profile: result.profile,
  });
  return result;
}

export function getScanForHistory(entry: HistoryEntry): ScanResult | null {
  return SCAN_RESULTS.get(entry.id) ?? null;
}
