import type { AuthUser } from "@/types/auth";
import type { Issue, IssueHistoryEntry } from "@/types/issue";
import type { Team, TeamMember } from "@/types/team";

const now = () => new Date().toISOString();
const daysAgo = (d: number) => new Date(Date.now() - d * 86400000).toISOString();
const daysAhead = (d: number) => new Date(Date.now() + d * 86400000).toISOString();

export interface MockUser {
  id: string;
  email: string;
  name: string;
  role: "admin" | "lead" | "user" | "viewer" | "operator";
  isActive: boolean;
  createdAt: string | null;
  lastLoginAt: string | null;
  organization_id: string | null;
}

export const mockUsers: MockUser[] = [
  {
    id: "user_1",
    email: "admin@cipherlens.local",
    name: "Administrador",
    role: "admin",
    isActive: true,
    createdAt: daysAgo(90),
    lastLoginAt: now(),
    organization_id: "org_1",
  },
  {
    id: "user_2",
    email: "analista@cipherlens.local",
    name: "María Fernández",
    role: "lead",
    isActive: true,
    createdAt: daysAgo(90),
    lastLoginAt: now(),
    organization_id: "org_1",
  },
  {
    id: "user_3",
    email: "analista2@cipherlens.local",
    name: "Carlos Núñez",
    role: "user",
    isActive: true,
    createdAt: daysAgo(60),
    lastLoginAt: daysAgo(1),
    organization_id: "org_1",
  },
  {
    id: "user_4",
    email: "operador@cipherlens.local",
    name: "Lucía Gómez",
    role: "user",
    isActive: true,
    createdAt: daysAgo(45),
    lastLoginAt: daysAgo(4),
    organization_id: "org_1",
  },
];

export const mockTeams: Team[] = [
  {
    id: "team_1",
    name: "Seguridad Infraestructura",
    description: "Equipo responsable de la seguridad de servidores y servicios TLS.",
    createdAt: daysAgo(80),
    memberIds: ["user_1", "user_2"],
    memberCount: 2,
    leadIds: ["user_2"],
  },
  {
    id: "team_2",
    name: "Operaciones TI",
    description: "Mantenimiento y operación de servicios internos.",
    createdAt: daysAgo(70),
    memberIds: ["user_3"],
    memberCount: 1,
    leadIds: [],
  },
];

export const mockTeamMembers: TeamMember[] = mockUsers.map((u) => ({
  id: u.id,
  name: u.name,
  email: u.email,
  role: u.role,
  organization_id: u.organization_id,
}));

export const mockIssues: Issue[] = [
  {
    id: "issue_1",
    serviceId: "svc_1",
    sourceDocument: "NIST SP 800-52 Rev. 2",
    ruleId: "tls_protocol_deprecated",
    title: "TLS 1.0 habilitado en servidor web",
    severity: "high",
    status: "open",
    ownerUserId: null,
    ownerTeamId: null,
    effectiveOwnerUserId: null,
    effectiveOwnerTeamId: null,
    ownerName: null,
    firstSeenAt: daysAgo(10),
    lastSeenAt: daysAgo(1),
    dueAt: daysAhead(20),
    isOverdue: false,
    resolvedAt: null,
    resolvedBy: null,
    verifiedAt: null,
    cleanScansSinceResolved: 0,
    riskAcceptedBy: null,
    riskAcceptanceReason: null,
    riskAcceptedUntil: null,
    reopenedCount: 0,
    lastCertificateFingerprint: "aa:bb:cc:dd:ee:ff",
  },
  {
    id: "issue_2",
    serviceId: "svc_2",
    sourceDocument: "NIST SP 800-57",
    ruleId: "certificate_expiry_30d",
    title: "Certificado expira en menos de 30 días",
    severity: "medium",
    status: "assigned",
    ownerUserId: "user_2",
    ownerTeamId: null,
    effectiveOwnerUserId: "user_2",
    effectiveOwnerTeamId: null,
    ownerName: "María Fernández",
    firstSeenAt: daysAgo(15),
    lastSeenAt: daysAgo(2),
    dueAt: daysAgo(1),
    isOverdue: true,
    resolvedAt: null,
    resolvedBy: null,
    verifiedAt: null,
    cleanScansSinceResolved: 0,
    riskAcceptedBy: null,
    riskAcceptanceReason: null,
    riskAcceptedUntil: null,
    reopenedCount: 0,
    lastCertificateFingerprint: "11:22:33:44:55:66",
  },
  {
    id: "issue_3",
    serviceId: "svc_3",
    sourceDocument: "CWE-327",
    ruleId: "weak_cipher_suite",
    title: "Suite de cifrado débil (RC4) negociado",
    severity: "critical",
    status: "in_progress",
    ownerUserId: "user_1",
    ownerTeamId: "team_1",
    effectiveOwnerUserId: "user_1",
    effectiveOwnerTeamId: "team_1",
    ownerName: "Administrador",
    firstSeenAt: daysAgo(30),
    lastSeenAt: daysAgo(1),
    dueAt: daysAgo(5),
    isOverdue: true,
    resolvedAt: null,
    resolvedBy: null,
    verifiedAt: null,
    cleanScansSinceResolved: 0,
    riskAcceptedBy: null,
    riskAcceptanceReason: null,
    riskAcceptedUntil: null,
    reopenedCount: 1,
    lastCertificateFingerprint: "ff:ee:dd:cc:bb:aa",
  },
  {
    id: "issue_4",
    serviceId: "svc_4",
    sourceDocument: "NIST SP 800-28",
    ruleId: "tls_certificate_expired",
    title: "Certificado vencido en pasarela de pago",
    severity: "critical",
    status: "resolved",
    ownerUserId: "user_2",
    ownerTeamId: null,
    effectiveOwnerUserId: "user_2",
    effectiveOwnerTeamId: null,
    ownerName: "María Fernández",
    firstSeenAt: daysAgo(50),
    lastSeenAt: daysAgo(12),
    dueAt: daysAgo(35),
    isOverdue: false,
    resolvedAt: daysAgo(12),
    resolvedBy: "user_2",
    verifiedAt: null,
    cleanScansSinceResolved: 2,
    riskAcceptedBy: null,
    riskAcceptanceReason: null,
    riskAcceptedUntil: null,
    reopenedCount: 0,
    lastCertificateFingerprint: "aa:11:bb:22:cc:33",
  },
  {
    id: "issue_5",
    serviceId: "svc_5",
    sourceDocument: "NIST SP 800-131A",
    ruleId: "tls_1_3_downgrade",
    title: "Posibilidad de degradación a TLS 1.2",
    severity: "low",
    status: "verified",
    ownerUserId: "user_1",
    ownerTeamId: null,
    effectiveOwnerUserId: "user_1",
    effectiveOwnerTeamId: null,
    ownerName: "Administrador",
    firstSeenAt: daysAgo(60),
    lastSeenAt: daysAgo(20),
    dueAt: daysAgo(25),
    isOverdue: false,
    resolvedAt: daysAgo(22),
    resolvedBy: "user_1",
    verifiedAt: daysAgo(20),
    cleanScansSinceResolved: 4,
    riskAcceptedBy: null,
    riskAcceptanceReason: null,
    riskAcceptedUntil: null,
    reopenedCount: 0,
    lastCertificateFingerprint: null,
  },
  {
    id: "issue_6",
    serviceId: "svc_6",
    sourceDocument: "CWE-295",
    ruleId: "self_signed_certificate",
    title: "Certificado autofirmado en servicio interno",
    severity: "medium",
    status: "risk_accepted",
    ownerUserId: "user_1",
    ownerTeamId: "team_2",
    effectiveOwnerUserId: "user_1",
    effectiveOwnerTeamId: "team_2",
    ownerName: "Administrador",
    firstSeenAt: daysAgo(40),
    lastSeenAt: daysAgo(3),
    dueAt: daysAhead(10),
    isOverdue: false,
    resolvedAt: null,
    resolvedBy: null,
    verifiedAt: null,
    cleanScansSinceResolved: 0,
    riskAcceptedBy: "user_1",
    riskAcceptanceReason: "Servicio interno controlado, sin exposición externa.",
    riskAcceptedUntil: daysAhead(30),
    reopenedCount: 0,
    lastCertificateFingerprint: "de:ad:be:ef:00:01",
  },
  {
    id: "issue_7",
    serviceId: "svc_7",
    sourceDocument: "NIST SP 800-52 Rev. 2",
    ruleId: "tls_certificate_hostname_mismatch",
    title: "Hostname no coincide con el certificado",
    severity: "medium",
    status: "false_positive",
    ownerUserId: "user_2",
    ownerTeamId: null,
    effectiveOwnerUserId: "user_2",
    effectiveOwnerTeamId: null,
    ownerName: "María Fernández",
    firstSeenAt: daysAgo(25),
    lastSeenAt: daysAgo(18),
    dueAt: daysAgo(8),
    isOverdue: false,
    resolvedAt: daysAgo(18),
    resolvedBy: "user_2",
    verifiedAt: null,
    cleanScansSinceResolved: 0,
    riskAcceptedBy: null,
    riskAcceptanceReason: null,
    riskAcceptedUntil: null,
    reopenedCount: 0,
    lastCertificateFingerprint: null,
  },
];

export function mockHistoryFor(issue: Issue): IssueHistoryEntry[] {
  const entries: IssueHistoryEntry[] = [
    {
      id: `hist_${issue.id}_1`,
      ts: issue.firstSeenAt,
      actorUserId: null,
      actorType: "system",
      eventType: "created",
      fromValue: null,
      toValue: issue.status,
      comment: null,
      scanId: null,
    },
  ];
  if (issue.ownerUserId || issue.ownerTeamId) {
    entries.push({
      id: `hist_${issue.id}_2`,
      ts: issue.lastSeenAt,
      actorUserId: issue.ownerUserId,
      actorType: "user",
      eventType: "owner_changed",
      fromValue: null,
      toValue: issue.ownerUserId ?? issue.ownerTeamId,
      comment: null,
      scanId: null,
    });
  }
  if (issue.resolvedAt) {
    entries.push({
      id: `hist_${issue.id}_3`,
      ts: issue.resolvedAt,
      actorUserId: issue.resolvedBy,
      actorType: "user",
      eventType: "status_changed",
      fromValue: "in_progress",
      toValue: "resolved",
      comment: null,
      scanId: null,
    });
  }
  if (issue.verifiedAt) {
    entries.push({
      id: `hist_${issue.id}_4`,
      ts: issue.verifiedAt,
      actorUserId: "system",
      actorType: "system",
      eventType: "auto_verified",
      fromValue: "resolved",
      toValue: "verified",
      comment: null,
      scanId: null,
    });
  }
  if (issue.status === "risk_accepted" && issue.riskAcceptedUntil) {
    entries.push({
      id: `hist_${issue.id}_5`,
      ts: issue.lastSeenAt,
      actorUserId: issue.riskAcceptedBy,
      actorType: "user",
      eventType: "risk_accept",
      fromValue: "open",
      toValue: "risk_accepted",
      comment: issue.riskAcceptanceReason,
      scanId: null,
    });
  }
  if (issue.status === "false_positive") {
    entries.push({
      id: `hist_${issue.id}_6`,
      ts: issue.resolvedAt ?? issue.lastSeenAt,
      actorUserId: issue.resolvedBy,
      actorType: "user",
      eventType: "false_positive",
      fromValue: "open",
      toValue: "false_positive",
      comment: null,
      scanId: null,
    });
  }
  return entries.sort((a, b) => (a.ts ?? "").localeCompare(b.ts ?? ""));
}

export function toAuthUser(u: MockUser): AuthUser {
  return {
    id: u.id,
    email: u.email,
    name: u.name,
    role: u.role,
    isActive: u.isActive,
    createdAt: u.createdAt,
    lastLoginAt: u.lastLoginAt,
    organization_id: u.organization_id,
  };
}
