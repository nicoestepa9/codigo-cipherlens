import type { Finding } from "@/types/finding";
import type { Severity } from "@/types/severity";
import { getMockServices } from "./services";
import { mulberry32, randInt } from "./utils";

interface FindingTemplate {
  ruleId: string;
  title: string;
  description: string;
  recommendation: string;
  reference?: string;
  severity: Severity;
  category: string;
  evidence: (host: string, service: string) => string;
}

export const FINDING_TEMPLATES: FindingTemplate[] = [
  {
    ruleId: "PROTO-01",
    title: "TLS 1.0 Enabled",
    description:
      "The server supports TLS 1.0, which is deprecated and vulnerable to known attacks (BEAST, POODLE). NIST SP 800-52 Rev.2 requires TLS 1.0 to be disabled.",
    recommendation: "Disable TLS 1.0 and TLS 1.1. Allow only TLS 1.2 and TLS 1.3.",
    reference: "NIST SP 800-52 Rev.2, Section 3.1",
    severity: "critical",
    category: "Protocol",
    evidence: (host) => `Handshake probe succeeded with TLS 1.0 on ${host}.`,
  },
  {
    ruleId: "PROTO-02",
    title: "TLS 1.1 Enabled",
    description:
      "The server supports TLS 1.1, which is deprecated. NIST SP 800-52 Rev.2 mandates disabling TLS 1.0 and 1.1.",
    recommendation: "Disable TLS 1.1 and enforce TLS 1.2+.",
    reference: "NIST SP 800-52 Rev.2, Section 3.1",
    severity: "high",
    category: "Protocol",
    evidence: (host) => `Negotiated TLS 1.1 during probe of ${host}.`,
  },
  {
    ruleId: "CIPH-01",
    title: "Weak Cipher Suite (3DES)",
    description:
      "The server accepts 3DES (CBC) cipher suites. 3DES is cryptographically weak and not approved for use after 2023.",
    recommendation: "Disable 3DES and use modern AEAD cipher suites (AES-GCM, ChaCha20-Poly1305).",
    reference: "NIST SP 800-52 Rev.2, Section 3.3.1",
    severity: "critical",
    category: "Cipher Suite",
    evidence: (host) => `Cipher suite TLS_RSA_WITH_3DES_EDE_CBC_SHA accepted by ${host}.`,
  },
  {
    ruleId: "CIPH-03",
    title: "RSA Key Transport Without Forward Secrecy",
    description:
      "The server supports RSA key exchange, which provides no forward secrecy. Compromise of the private key would expose all recorded traffic.",
    recommendation: "Remove RSA key exchange and enable ECDHE-based suites.",
    reference: "NIST SP 800-52 Rev.2, Section 3.3.1",
    severity: "high",
    category: "Cipher Suite",
    evidence: (host) => `Suite TLS_RSA_WITH_AES_128_CBC_SHA uses RSA key transport on ${host}.`,
  },
  {
    ruleId: "CIPH-02",
    title: "CBC Mode Cipher Without Encrypt-then-MAC",
    description:
      "The server negotiates CBC-mode ciphers without the Encrypt-then-MAC extension, exposing connections to padding-oracle attacks (Lucky13).",
    recommendation: "Remove CBC suites or enable Encrypt-then-MAC.",
    reference: "NIST SP 800-52 Rev.2, Section 3.3.1",
    severity: "medium",
    category: "Cipher Suite",
    evidence: (host) => `Negotiated ECDHE-RSA-AES256-CBC-SHA without Encrypt-then-MAC on ${host}.`,
  },
  {
    ruleId: "CERT-01",
    title: "Certificate Expiration",
    description:
      "The TLS certificate is near its expiration date or already expired. Expired certificates break client validation and services.",
    recommendation: "Renew the certificate before expiration.",
    reference: "NIST SP 800-52 Rev.2, Section 3.2",
    severity: "medium",
    category: "Certificate",
    evidence: (host) => `Certificate for ${host} expires within 21 days.`,
  },
  {
    ruleId: "CERT-02",
    title: "Certificate Signed with SHA-1",
    description:
      "The certificate chain uses a SHA-1 signature, which is deprecated and no longer considered secure.",
    recommendation: "Re-issue the certificate signed with SHA-256 or stronger.",
    reference: "NIST SP 800-52 Rev.2, Section 3.2 / Table 3-1",
    severity: "high",
    category: "Certificate",
    evidence: (host) => `Leaf certificate signature algorithm is SHA1-RSA on ${host}.`,
  },
  {
    ruleId: "CERT-03",
    title: "Certificate Validity Longer Than 3 Years",
    description:
      "The certificate is valid for more than 3 years, exceeding NIST SP 800-52 Rev.2 limits for TLS server certificates.",
    recommendation: "Issue certificates with a maximum validity of 3 years.",
    reference: "NIST SP 800-52 Rev.2, Table 3-1",
    severity: "medium",
    category: "Certificate",
    evidence: (host) => `Certificate for ${host} has a validity period exceeding 1095 days.`,
  },
  {
    ruleId: "CERT-04",
    title: "Self-Signed Certificate",
    description:
      "The server presents a self-signed certificate that is not trusted by clients.",
    recommendation: "Replace with a certificate signed by a trusted CA.",
    severity: "medium",
    category: "Certificate",
    evidence: (host) => `Certificate for ${host} is self-signed.`,
  },
  {
    ruleId: "EXT-01",
    title: "OCSP Stapling Not Enabled",
    description:
      "The server does not provide OCSP stapling, forcing clients to contact the CA for revocation status.",
    recommendation: "Enable OCSP stapling on the TLS server.",
    reference: "NIST SP 800-52 Rev.2, Section 3.4",
    severity: "info",
    category: "Extension",
    evidence: (host) => `No status_request extension observed in ServerHello from ${host}.`,
  },
  {
    ruleId: "EXT-02",
    title: "ALPN Not Supported",
    description:
      "Application-Layer Protocol Negotiation is not in use. HTTP/2 and other protocols cannot be negotiated.",
    recommendation: "Enable ALPN for HTTP/2 support.",
    severity: "info",
    category: "Configuration",
    evidence: (host) => `ALPN extension absent from ServerHello of ${host}.`,
  },
  {
    ruleId: "COMP-01",
    title: "TLS Compression Enabled",
    description:
      "TLS compression is enabled, which is a prerequisite for the CRIME attack.",
    recommendation: "Disable TLS compression.",
    reference: "NIST SP 800-52 Rev.2, Section 3.7",
    severity: "low",
    category: "Compression",
    evidence: (host) => `Compression method DEFLATE offered by ${host}.`,
  },
];

function buildFinding(
  template: FindingTemplate,
  host: string,
  service: string | undefined,
  index: number,
): Finding {
  return {
    id: `fnd_${host.replace(/[^a-z0-9]/gi, "")}_${index}`,
    ruleId: template.ruleId,
    title: template.title,
    description: template.description,
    evidence: template.evidence(host, service ?? ""),
    recommendation: template.recommendation,
    reference: template.reference,
    severity: template.severity,
    category: template.category,
    affectedHost: host,
    affectedService: service,
    detectionDate: new Date().toISOString(),
  };
}

export function findingsForTarget(host: string, service: string, status: string, daysToExpiry: number): Finding[] {
  const rnd = mulberry32(host.split("").reduce((a, c) => a + c.charCodeAt(0), 0));
  const out: Finding[] = [];
  const push = (template: FindingTemplate) =>
    out.push(buildFinding(template, host, service, out.length + 1));

  if (status === "critical") {
    const tls10 = FINDING_TEMPLATES.find((t) => t.ruleId === "PROTO-01")!;
    const tls11 = FINDING_TEMPLATES.find((t) => t.ruleId === "PROTO-02")!;
    const threeDes = FINDING_TEMPLATES.find((t) => t.ruleId === "CIPH-01")!;
    const rsa = FINDING_TEMPLATES.find((t) => t.ruleId === "CIPH-03")!;
    push(tls10);
    if (rnd() < 0.7) push(tls11);
    push(threeDes);
    if (rnd() < 0.8) push(rsa);
  } else if (status === "warning") {
    const tls11 = FINDING_TEMPLATES.find((t) => t.ruleId === "PROTO-02")!;
    const cbc = FINDING_TEMPLATES.find((t) => t.ruleId === "CIPH-02")!;
    const cert = FINDING_TEMPLATES.find((t) => t.ruleId === "CERT-01")!;
    push(tls11);
    if (rnd() < 0.9) push(cbc);
    if (daysToExpiry < 30) push(cert);
  } else {
    const ocsp = FINDING_TEMPLATES.find((t) => t.ruleId === "EXT-01")!;
    const alpn = FINDING_TEMPLATES.find((t) => t.ruleId === "EXT-02")!;
    if (rnd() < 0.7) push(ocsp);
    if (rnd() < 0.6) push(alpn);
  }

  return out;
}

let GLOBAL: Finding[] | null = null;

export function getGlobalFindings(): Finding[] {
  if (GLOBAL) return GLOBAL;
  const rnd = mulberry32(20260303);
  const findings: Finding[] = [];
  const services = getMockServices();
  const templates = FINDING_TEMPLATES;

  for (const svc of services) {
    if (svc.securityStatus === "critical") {
      for (const t of templates) {
        if (["critical", "high"].includes(t.severity) && rnd() < 0.8) {
          findings.push(buildFinding(t, svc.host, svc.name, findings.length + 1));
        }
      }
      if (svc.certificateStatus !== "valid") {
        const cert = templates.find((t) => t.ruleId === "CERT-01")!;
        findings.push(buildFinding(cert, svc.host, svc.name, findings.length + 1));
      }
    } else if (svc.securityStatus === "warning") {
      const pickCount = randInt(1, 2, rnd);
      const pool = templates.filter((t) => t.severity === "high" || t.severity === "medium");
      for (let i = 0; i < pickCount; i++) {
        findings.push(buildFinding(pool[Math.floor(rnd() * pool.length)], svc.host, svc.name, findings.length + 1));
      }
    } else if (rnd() < 0.5) {
      const pool = templates.filter((t) => t.severity === "info" || t.severity === "low");
      findings.push(buildFinding(pool[Math.floor(rnd() * pool.length)], svc.host, svc.name, findings.length + 1));
    }
  }

  // Additional expired certificates across the fleet
  const expiringCerts = services.filter((s) => s.certificateDaysLeft < 0);
  for (const svc of expiringCerts) {
    const cert = templates.find((t) => t.ruleId === "CERT-01")!;
    findings.push(buildFinding(cert, svc.host, svc.name, findings.length + 1));
  }

  GLOBAL = findings;
  return GLOBAL;
}
