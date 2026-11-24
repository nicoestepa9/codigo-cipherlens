import type { Scope, SecurityStatus } from "./severity";

export interface Asset {
  id: string;
  name: string;
  type: string;
  owner: string;
  department: string;
  declared: boolean;
}

export interface Service {
  id: string;
  name: string;
  host: string;
  ipAddress: string;
  port: number;
  protocol: string;
  service: string;
  tlsVersion: string;
  cipherSuite: string;
  securityStatus: SecurityStatus;
  certificateId: string;
  certificateDomain: string;
  certificateStatus: string;
  certificateDaysLeft: number;
  asset: Asset;
  scope: Scope;
  lastSeen: string;
  osFingerprint: string | null;
  vulnerabilityCount: number;
  findingsSeverity: string | null;
  agentId?: string | null;
  siteLabel?: string | null;
}
