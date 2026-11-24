import type { CertificateInfo } from "./certificate";
import type { Finding } from "./finding";
import type { SecurityStatus } from "./severity";

export interface CipherSuite {
  name: string;
  protocol: string;
  keyExchange: string;
  encryption: string;
  mac: string;
  bits: number;
  status: "secure" | "warning" | "critical";
  selected?: boolean;
}

export interface HandshakeStep {
  step: string;
  actor: "client" | "server";
  description: string;
  details: string;
}

export interface OsFingerprint {
  detected: boolean;
  os?: string;
  service?: string;
  banner?: string;
  confidence?: string;
  note: string;
  softwareVersion?: string;
  ja3Hash?: string;
  ja3sHash?: string;
  method?: string;
}

export interface CveLiveMatch {
  cveId: string;
  cvssV3Score?: number;
  matchType: "cpe" | "keyword";
  stale: boolean;
  unverified?: boolean;
  keyword?: string;
}

export interface SoftwareKnownCves {
  queried: boolean;
  cpeName?: string;
  matches: CveLiveMatch[];
}

export interface ScanOptions {
  timeout?: number;
  sni?: boolean;
  profile?: "citizen-facing" | "government-only";
  alternatePorts?: number[];
}

export interface ScanResult {
  id: string;
  target: string;
  host: string;
  port: number;
  portIsAlternate: boolean;
  ipAddress: string;
  scanStartedAt: string;
  scanDurationMs: number;
  profile: string;
  score: number;
  status: SecurityStatus | "failed";
  negotiatedProtocol: string;
  negotiatedCipher: string;
  keyExchange: string;
  signatureAlgorithm: string;
  supportedProtocols: string[];
  cipherSuites: CipherSuite[];
  certificate: CertificateInfo;
  chain: CertificateInfo[];
  findings: Finding[];
  osFingerprint: OsFingerprint;
  handshakeSteps: HandshakeStep[];
  aiRecommendation: string;
  connectionError: string | null;
  liveCveMatches?: CveLiveMatch[];
  softwareKnownCves?: SoftwareKnownCves;
  agentId?: string | null;
  siteLabel?: string | null;
}

export interface ScanProgressStep {
  label: string;
  detail: string;
  state: "pending" | "running" | "done" | "error";
}
