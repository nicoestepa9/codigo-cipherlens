import type { CertificateStatus, Origin } from "./severity";

export interface CertificateInfo {
  id: string;
  domain: string;
  commonName: string;
  subject: Record<string, string>;
  issuerName: string;
  issuer: Record<string, string>;
  serialNumber: string;
  notBefore: string;
  notAfter: string;
  daysUntilExpiry: number;
  isExpired: boolean;
  san: string[];
  keyType: string;
  keySize: number;
  signatureAlgorithm: string;
  fingerprintSha256: string;
  fingerprintSha1: string;
  isSelfSigned: boolean;
  basicConstraints: string;
  keyUsage: string[];
  extendedKeyUsage: string[];
  caIssuers: string[];
  crlDistributionPoints: string[];
  ocspMustStaple: boolean;
  status: CertificateStatus;
  origin: Origin;
  serviceId: string | null;
  serviceName: string | null;
  agentId?: string | null;
  siteLabel?: string | null;
}

export interface CertificateChainCert {
  id: string;
  commonName: string;
  issuerName: string;
  isRoot: boolean;
  isLeaf: boolean;
  selfSigned: boolean;
  notBefore: string;
  notAfter: string;
}

export interface CertificateDetail {
  certificate: CertificateInfo;
  chain: CertificateChainCert[];
  relatedServices: {
    id: string;
    name: string;
    host: string;
    port: number;
    tlsVersion: string;
    securityStatus: string;
  }[];
  relatedFindings: number;
}
