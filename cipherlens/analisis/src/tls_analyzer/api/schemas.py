"""Esquemas Pydantic de request/response (camelCase, contrato del frontend)."""

from __future__ import annotations

from datetime import datetime
from typing import Generic, Literal, TypeVar

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

T = TypeVar("T")


class Paged(BaseModel, Generic[T]):
    items: list[T]
    total: int
    page: int
    pageSize: int


# --------------------------------------------------------------------------
# Request bodies
# --------------------------------------------------------------------------

class ScanOptionsIn(BaseModel):
    model_config = ConfigDict(extra="ignore")

    profile: str | None = None
    timeout: float | None = None
    sni: bool | None = None
    alternatePorts: list[int] | None = None


class ScanRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    target: str
    port: int | None = None
    options: ScanOptionsIn | None = None
    authorizationAccepted: bool = False
    authorizationVersion: str | None = None
    executor: "ExecutorIn | None" = None


class AlertStatusUpdate(BaseModel):
    status: str = "read"


class DiscoveryRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    ipRange: str = ""
    ports: list[int] = Field(default_factory=lambda: [443, 8080, 8000, 4443])
    domains: list[str] = Field(default_factory=list)
    scanInternal: bool = False
    authorizationAccepted: bool = False
    authorizationVersion: str | None = None
    executor: "ExecutorIn | None" = None


class ExecutorIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["cloud", "agent"] = "cloud"
    agentId: str | None = None

    @model_validator(mode="after")
    def _agent_only_for_agent_executor(self):
        if self.type == "cloud" and self.agentId is not None:
            raise ValueError("agentId is only valid when executor.type is 'agent'")
        if self.type == "agent" and not self.agentId:
            raise ValueError("agentId is required when executor.type is 'agent'")
        return self


class ThresholdUpdate(BaseModel):
    daysBeforeExpiry: list[int] = Field(default_factory=lambda: [30, 15, 7])
    notifyOnCriticalFinding: bool = True
    notifyOnCompliance: bool = True
    criticalDays: int = 7
    warningDays: int = 30


class ApiKeyCreate(BaseModel):
    model_config = ConfigDict(extra="ignore")

    name: str = "default"
    role: str = "lead"
    expiresInDays: int | None = None


# --------------------------------------------------------------------------
# Response models
# --------------------------------------------------------------------------

class CipherSuiteOut(BaseModel):
    name: str = ""
    protocol: str = ""
    keyExchange: str = ""
    encryption: str = ""
    mac: str = ""
    bits: int = 0
    status: str = "secure"
    selected: bool = False


class OsFingerprintOut(BaseModel):
    detected: bool = False
    os: str | None = None
    service: str | None = None
    banner: str | None = None
    confidence: str | None = None
    note: str = ""
    softwareVersion: str | None = None
    ja3Hash: str | None = None
    ja3sHash: str | None = None
    method: str | None = None


class HandshakeStepOut(BaseModel):
    step: str
    actor: str
    description: str
    details: str


class CveReferenceOut(BaseModel):
    cveId: str
    name: str | None = None
    cvssV3Score: float | None = None
    matchType: str = "static_mapping"  # static_mapping|cpe|keyword
    referenceUrl: str = ""


class CveLiveMatchOut(BaseModel):
    cveId: str
    cvssV3Score: float | None = None
    matchType: str = "keyword"  # cpe|keyword
    stale: bool = False
    unverified: bool = False  # True para keyword search (puede no ser relevante al servidor)
    keyword: str | None = None  # keyword que produjo este match


class SoftwareKnownCvesOut(BaseModel):
    queried: bool = False
    cpeName: str | None = None
    matches: list[CveLiveMatchOut] = Field(default_factory=list)


class FindingOut(BaseModel):
    id: str = ""
    ruleId: str = ""
    title: str = ""
    description: str = ""
    evidence: str = ""
    recommendation: str = ""
    reference: str | None = None
    severity: str = "info"
    category: str = ""
    affectedHost: str = ""
    affectedService: str | None = None
    detectionDate: str = ""
    citation: str = ""
    observedValue: str = ""
    sectionReference: str = ""
    sourceDocument: str | None = None
    standards: list[str] = Field(default_factory=list)
    ruleIds: list[str] = Field(default_factory=list)
    evaluable: bool = True
    status: str | None = None
    relatedCves: list[CveReferenceOut] = Field(default_factory=list)


class CertificateInfoOut(BaseModel):
    id: str = ""
    domain: str = ""
    commonName: str = ""
    subject: dict = Field(default_factory=dict)
    issuerName: str = ""
    issuer: dict = Field(default_factory=dict)
    serialNumber: str = ""
    notBefore: str = ""
    notAfter: str = ""
    daysUntilExpiry: int = 0
    isExpired: bool = False
    san: list[str] = Field(default_factory=list)
    keyType: str = ""
    keySize: int = 0
    signatureAlgorithm: str = ""
    fingerprintSha256: str = ""
    fingerprintSha1: str = ""
    isSelfSigned: bool = False
    basicConstraints: str = ""
    keyUsage: list[str] = Field(default_factory=list)
    extendedKeyUsage: list[str] = Field(default_factory=list)
    caIssuers: list[str] = Field(default_factory=list)
    crlDistributionPoints: list[str] = Field(default_factory=list)
    ocspMustStaple: bool = False
    status: str = "unknown"
    origin: str = "discovered"
    serviceId: str | None = None
    serviceName: str | None = None
    agentId: str | None = None
    siteLabel: str | None = None


class ScanResultOut(BaseModel):
    id: str
    target: str
    host: str
    port: int
    portIsAlternate: bool = False
    ipAddress: str = ""
    scanStartedAt: str
    scanDurationMs: int = 0
    profile: str = "citizen-facing"
    score: int = 0
    status: str = "warning"
    negotiatedProtocol: str = ""
    negotiatedCipher: str = ""
    keyExchange: str = ""
    signatureAlgorithm: str = ""
    supportedProtocols: list[str] = Field(default_factory=list)
    cipherSuites: list[CipherSuiteOut] = Field(default_factory=list)
    certificate: CertificateInfoOut = Field(default_factory=CertificateInfoOut)
    chain: list[CertificateInfoOut] = Field(default_factory=list)
    findings: list[FindingOut] = Field(default_factory=list)
    osFingerprint: OsFingerprintOut = Field(default_factory=OsFingerprintOut)
    handshakeSteps: list[HandshakeStepOut] = Field(default_factory=list)
    aiRecommendation: str = ""
    connectionError: str | None = None
    liveCveMatches: list[CveLiveMatchOut] = Field(default_factory=list)
    softwareKnownCves: SoftwareKnownCvesOut = Field(default_factory=SoftwareKnownCvesOut)
    agentId: str | None = None
    siteLabel: str | None = None


class HistoryEntryOut(BaseModel):
    id: str
    target: str
    host: str
    port: int
    kind: str = "tls_scan"
    date: str = ""
    score: int | None = None
    durationMs: int = 0
    status: str = "completed"
    profile: str = "citizen-facing"
    origin: str | None = None
    agentId: str | None = None
    uploadLevel: str | None = None
    startedAt: str | None = None
    siteLabel: str | None = None


class AssetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str = ""
    ip_address: str = ""
    hostname: str | None = None
    port: int = 443
    service: str = ""
    tls_version: str | None = None
    scope: str = "external"
    inventory_status: str = "shadow_it"
    name: str = ""
    type: str = ""
    owner: str = ""
    department: str = ""
    declared: bool = True


class AssetCreateIn(BaseModel):
    model_config = ConfigDict(extra="ignore")

    ip_address: str = ""
    hostname: str = ""
    port: int | None = None
    service: str = ""
    tls_version: str | None = None
    scope: str = ""
    inventory_status: str = "shadow_it"

    @field_validator("hostname", mode="before")
    @classmethod
    def normalize_missing_hostname(cls, value: object) -> object:
        return "" if value is None else value


class ServiceOut(BaseModel):
    id: str
    name: str
    host: str
    ipAddress: str
    port: int
    protocol: str
    service: str
    tlsVersion: str
    cipherSuite: str
    securityStatus: str
    certificateId: str | None
    certificateDomain: str
    certificateStatus: str
    certificateDaysLeft: int
    asset: AssetOut = Field(default_factory=AssetOut)
    scope: str
    lastSeen: str
    osFingerprint: str | None = None
    vulnerabilityCount: int
    findingsSeverity: str | None = None
    agentId: str | None = None
    siteLabel: str | None = None


class DashboardSummaryOut(BaseModel):
    totalServices: int = 0
    totalCertificates: int = 0
    certificatesExpiringSoon: int = 0
    criticalVulnerabilities: int = 0
    highVulnerabilities: int = 0
    shadowItDetected: int = 0
    lastScanAt: str | None = None
    securityScore: int = 0
    secure: int = 0
    warning: int = 0
    critical: int = 0
    unreadAlerts: int = 0
    certificateCriticalDays: int = 7
    certificateWarningDays: int = 30


class VulnerabilityStatsOut(BaseModel):
    bySeverity: dict = Field(default_factory=lambda: {
        "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
    })
    overTime: list[dict] = Field(default_factory=list)
    mostCommon: list[dict] = Field(default_factory=list)
    byService: list[dict] = Field(default_factory=list)


class ExpirationStatsOut(BaseModel):
    expired: int = 0
    critical: int = 0
    warning: int = 0
    healthy: int = 0
    total: int = 0
    criticalDays: int = 7
    warningDays: int = 30
    byWindow: list[dict] = Field(default_factory=list)


class AlertOut(BaseModel):
    id: str
    severity: str
    type: str
    title: str
    description: str
    createdAt: str
    status: str
    relatedTarget: str | None = None
    relatedCertificateId: str | None = None
    relatedScanId: str | None = None
    actionLabel: str | None = None
    actionHref: str | None = None


class DiscoveryJobOut(BaseModel):
    id: str
    status: str
    progress: int = 0
    totalFound: int = 0
    shadowItCount: int = 0
    startedAt: str | None = None
    completedAt: str | None = None
    error: str | None = None


class DiscoveryResultOut(BaseModel):
    id: str
    ipAddress: str
    hostname: str | None = None
    port: int
    service: str
    serviceName: str
    hasTls: bool
    tlsVersion: str | None = None
    osFingerprint: str | None = None
    inventoried: bool
    shadowIt: bool
    scope: str
    firstSeen: str
    lastSeen: str
    agentId: str | None = None
    siteLabel: str | None = None


class DiscoverySummaryOut(BaseModel):
    total: int = 0
    inventoried: int = 0
    shadowIt: int = 0
    withTls: int = 0
    internal: int = 0
    external: int = 0


class ThresholdOut(BaseModel):
    daysBeforeExpiry: list[int]
    notifyOnCriticalFinding: bool
    notifyOnCompliance: bool
    criticalDays: int
    warningDays: int


class OrganizationSettingsOut(BaseModel):
    id: int
    name: str
    slug: str
    status: str
    aiMode: Literal["external", "template"]
    maxAgents: int
    maxCloudScansPerHour: int
    maxRecurringScans: int
    slaDaysCritical: int
    slaDaysHigh: int
    slaDaysMedium: int


class ComplianceWindowIn(BaseModel):
    model_config = ConfigDict(extra="ignore")

    name: str = Field(default="", max_length=128)
    framework: str = Field(default="PCI-DSS", max_length=64)
    auditDate: str = Field(default="", max_length=32)
    scopeFilter: list[str] = Field(default_factory=list)


class ComplianceWindowOut(ComplianceWindowIn):
    id: str


class IntegrationOut(BaseModel):
    id: str
    name: str
    type: str
    description: str
    status: str
    lastSyncAt: str | None = None


class ApiKeyOut(BaseModel):
    id: str
    name: str
    prefix: str
    createdAt: str
    lastUsedAt: str | None = None
    revoked: bool
    role: str = "lead"
    expiresAt: str | None = None


class ApiKeyCreated(ApiKeyOut):
    key: str


class ApiEndpointOut(BaseModel):
    method: str
    path: str
    description: str
    example: str


class CertificateDetailOut(BaseModel):
    certificate: CertificateInfoOut
    chain: list[dict]
    relatedServices: list[dict]
    relatedFindings: int


class AiRecommendationOut(BaseModel):
    recommendation: str
    source: str


# --------------------------------------------------------------------------
# Scans recurrentes
# --------------------------------------------------------------------------

class RecurringScanCreate(BaseModel):
    model_config = ConfigDict(extra="ignore")

    host: str
    port: int = 443
    alternatePorts: list[int] | None = None
    profile: str = "citizen-facing"
    intervalHours: float = 24.0
    enabled: bool = True
    agentId: str | None = None
    authorizationAccepted: bool = False
    authorizationVersion: str | None = None


class RecurringScanPatch(BaseModel):
    model_config = ConfigDict(extra="ignore")

    host: str | None = None
    port: int | None = None
    alternatePorts: list[int] | None = None
    profile: str | None = None
    intervalHours: float | None = None
    enabled: bool | None = None
    agentId: str | None = None
    authorizationAccepted: bool = False
    authorizationVersion: str | None = None


class RecurringScanOut(BaseModel):
    id: int
    host: str
    port: int
    alternatePorts: list[int] = Field(default_factory=list)
    profile: str = "citizen-facing"
    intervalHours: float = 24.0
    enabled: bool = True
    isRunning: bool = False
    consecutiveFailures: int = 0
    lastRunAt: str | None = None
    nextRunAt: str = ""
    serviceId: str | None = None
    agentId: str | None = None


class RecurringScanDetailOut(RecurringScanOut):
    recentScans: list[HistoryEntryOut] = Field(default_factory=list)


# --------------------------------------------------------------------------
# Auth / Users / Audit (Parte 1)
# --------------------------------------------------------------------------

class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    email: str
    password: str


class PasswordChange(BaseModel):
    model_config = ConfigDict(extra="ignore")

    currentPassword: str
    newPassword: str


class TokenPair(BaseModel):
    accessToken: str
    refreshToken: str
    tokenType: str = "bearer"
    mustChangePassword: bool = False


class UserOut(BaseModel):
    id: str
    email: str
    name: str
    role: str
    isActive: bool
    mustChangePassword: bool = False
    createdAt: str | None = None
    lastLoginAt: str | None = None
    organization_id: int | None = None


class UserCreate(BaseModel):
    model_config = ConfigDict(extra="ignore")

    email: str
    name: str = ""
    password: str
    role: str = "user"


class UserUpdate(BaseModel):
    model_config = ConfigDict(extra="ignore")

    name: str | None = None
    role: str | None = None
    isActive: bool | None = None


class UserDirectoryEntry(BaseModel):
    id: str
    name: str
    email: str
    role: str
    organization_id: int | None = None


class AuditLogOut(BaseModel):
    id: str
    ts: str | None = None
    actorUserId: str | None = None
    actorType: str = "user"
    action: str
    entityType: str | None = None
    entityId: str | None = None
    ip: str | None = None
    metadata: dict | None = None


class ApiKeyCreateV2(BaseModel):
    model_config = ConfigDict(extra="ignore")

    name: str = "default"
    role: str = "lead"
    expiresInDays: int | None = None


class AiStatusOut(BaseModel):
    provider: str
    enabled: bool
    anonymization: str
    logPrompts: bool


# --------------------------------------------------------------------------
# Issues y equipos (Parte 2)
# --------------------------------------------------------------------------

class IssueHistoryOut(BaseModel):
    id: str
    ts: str | None = None
    actorUserId: str | None = None
    actorType: str = "system"
    eventType: str
    fromValue: str | None = None
    toValue: str | None = None
    comment: str | None = None
    scanId: str | None = None


class IssueOut(BaseModel):
    id: str
    serviceId: str | None = None
    serviceHost: str | None = None
    servicePort: int | None = None
    agentId: str | None = None
    siteLabel: str | None = None
    sourceDocument: str | None = None
    ruleId: str
    title: str
    severity: str
    status: str
    ownerUserId: str | None = None
    ownerTeamId: str | None = None
    effectiveOwnerUserId: str | None = None
    effectiveOwnerTeamId: str | None = None
    ownerName: str | None = None
    firstSeenAt: str | None = None
    lastSeenAt: str | None = None
    dueAt: str | None = None
    isOverdue: bool = False
    resolvedAt: str | None = None
    resolvedBy: str | None = None
    verifiedAt: str | None = None
    cleanScansSinceResolved: int = 0
    riskAcceptedBy: str | None = None
    riskAcceptanceReason: str | None = None
    riskAcceptedUntil: str | None = None
    reopenedCount: int = 0
    lastCertificateFingerprint: str | None = None
    history: list[IssueHistoryOut] | None = None


class IssueUpdate(BaseModel):
    model_config = ConfigDict(extra="ignore")

    status: str | None = None
    ownerUserId: str | None = None
    ownerTeamId: str | None = None
    comment: str | None = None
    reason: str | None = None
    riskAcceptedUntil: str | None = None


class IssueAssign(BaseModel):
    model_config = ConfigDict(extra="ignore")

    issueIds: list[str]
    ownerUserId: str | None = None
    ownerTeamId: str | None = None


class TeamOut(BaseModel):
    id: str
    name: str
    description: str | None = None
    createdAt: str | None = None
    memberIds: list[str] | None = None
    leadIds: list[str] | None = None
    memberCount: int = 0


class TeamCreate(BaseModel):
    model_config = ConfigDict(extra="ignore")

    name: str
    description: str | None = None
    memberIds: list[str] | None = None


class TeamUpdate(BaseModel):
    model_config = ConfigDict(extra="ignore")

    name: str | None = None
    description: str | None = None


class TeamMemberAdd(BaseModel):
    model_config = ConfigDict(extra="ignore")

    userId: str
    isLead: bool = False


class ServiceOwnerPatch(BaseModel):
    model_config = ConfigDict(extra="ignore")

    ownerUserId: str | None = None
    ownerTeamId: str | None = None


# --------------------------------------------------------------------------
# Agentes on-premise (Parte 5)
# --------------------------------------------------------------------------

class AgentCreate(BaseModel):
    model_config = ConfigDict(extra="ignore")

    name: str = Field(min_length=1, max_length=255)
    siteLabel: str = Field(default="", max_length=128)


class AgentUpdate(BaseModel):
    model_config = ConfigDict(extra="ignore")

    name: str | None = Field(default=None, max_length=255)
    siteLabel: str | None = Field(default=None, max_length=128)


class AgentOut(BaseModel):
    id: str
    name: str
    siteLabel: str
    status: str
    version: str | None = None
    lastSeenAt: str | None = None
    lastIp: str | None = None
    createdAt: str
    revokedAt: str | None = None
    schemaVersion: int | None = None
    rulesVersion: str | None = None
    serviceCount: int = 0
    keyPrefix: str | None = None
    isOnline: bool = False
    reportedCapabilities: dict | None = None


class AgentCreated(AgentOut):
    apiKey: str


class AgentDetailOut(BaseModel):
    agent: AgentOut
    recentScans: list[dict]


# --- Ingesta (contrato con el agente; validacion estricta) ---

class AgentHeartbeatIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agentVersion: str = Field(default="", max_length=64)
    schemaVersion: int
    rulesVersion: str | None = Field(default=None, max_length=32)
    uptimeSeconds: int | None = Field(default=None, ge=0)
    capabilities: dict | None = None

    @field_validator("capabilities")
    @classmethod
    def _limit_capabilities(cls, value: dict | None) -> dict | None:
        if value is None:
            return None
        allowed = {
            "allowRemoteTasks",
            "networkCount",
            "portCount",
            "allowedNetworks",
            "allowedPorts",
        }
        if set(value) - allowed:
            raise ValueError("unsupported capability field")
        if "allowRemoteTasks" in value and not isinstance(
            value["allowRemoteTasks"], bool
        ):
            raise ValueError("allowRemoteTasks must be boolean")
        networks = value.get("allowedNetworks", [])
        ports = value.get("allowedPorts", [])
        if (
            not isinstance(networks, list)
            or len(networks) > 32
            or not all(isinstance(item, str) and len(item) <= 64 for item in networks)
        ):
            raise ValueError("allowedNetworks exceeds limit")
        if (
            not isinstance(ports, list)
            or len(ports) > 256
            or any(not isinstance(port, int) or not 1 <= port <= 65535 for port in ports)
        ):
            raise ValueError("allowedPorts exceeds limit")
        if any(
            not isinstance(value.get(key, 0), int)
            or value.get(key, 0) < 0
            or value.get(key, 0) > 256
            for key in ("networkCount", "portCount")
        ):
            raise ValueError("capability count out of range")
        return value


class AgentTaskClaimIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    maxTasks: int = Field(default=1, ge=1, le=16)
    agentVersion: str = Field(default="", max_length=64)


class AgentTaskStatusIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["running", "rejected", "failed"]
    reason: str | None = Field(default=None, max_length=255)

    @model_validator(mode="after")
    def _validate_rejection_reason(self):
        if self.status == "rejected" and self.reason != "target_not_allowed":
            raise ValueError("rejected tasks must use reason=target_not_allowed")
        return self


class AgentTaskOut(BaseModel):
    id: str
    agentId: str
    type: str
    status: str
    payload: dict
    createdAt: str
    expiresAt: str
    claimedAt: str | None = None
    leaseExpiresAt: str | None = None
    finishedAt: str | None = None
    attempts: int
    error: str | None = None
    resultScanId: str | None = None
    resultJobId: str | None = None
    recurringScanId: int | None = None


class AgentTaskAcceptedOut(BaseModel):
    taskId: str
    status: str = "queued"


class AgentTargetIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    host: str = Field(min_length=1, max_length=255)
    port: int = Field(ge=1, le=65535)
    profile: str | None = Field(default=None, max_length=32)


class AgentScanIngest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schemaVersion: int
    rulesVersion: str = Field(max_length=32)
    clientScanId: str = Field(min_length=8, max_length=64)
    taskId: str | None = Field(default=None, min_length=36, max_length=36)
    uploadLevel: Literal["minimal", "standard", "full"] = "standard"
    target: AgentTargetIn
    portIsAlternate: bool = False
    startedAt: str | None = Field(default=None, max_length=40)
    durationMs: int = Field(default=0, ge=0)
    status: str = Field(default="completed", max_length=20)
    score: int = Field(default=0, ge=0, le=100)
    connectionError: str | None = Field(default=None, max_length=500)
    ipAddress: str = Field(default="", max_length=64)
    negotiatedProtocol: str = Field(default="", max_length=32)
    negotiatedCipher: str = Field(default="", max_length=128)
    supportedProtocols: list[str] = Field(default_factory=list)
    findings: list[dict] = Field(default_factory=list)
    certificate: dict = Field(default_factory=dict)
    chain: list[dict] = Field(default_factory=list)
    handshake: dict = Field(default_factory=dict)
    osFingerprint: dict = Field(default_factory=dict)
    rawResult: dict = Field(default_factory=dict)

    @field_validator("supportedProtocols")
    @classmethod
    def _limit_protocols(cls, v: list[str]) -> list[str]:
        if len(v) > 32:
            raise ValueError("supportedProtocols exceeds limit (32)")
        return [str(p)[:32] for p in v]

    @field_validator("findings")
    @classmethod
    def _limit_findings(cls, v: list[dict]) -> list[dict]:
        from .config import settings

        if len(v) > settings.agent_max_findings:
            raise ValueError(
                f"findings exceeds limit ({settings.agent_max_findings})"
            )
        return v

    @field_validator("chain")
    @classmethod
    def _limit_chain(cls, v: list[dict]) -> list[dict]:
        if len(v) > 16:
            raise ValueError("chain exceeds limit (16)")
        return v


class AgentDiscoveryResultIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ipAddress: str = Field(min_length=1, max_length=64)
    hostname: str | None = Field(default=None, max_length=255)
    port: int = Field(ge=1, le=65535)
    service: str = Field(default="", max_length=64)
    serviceName: str = Field(default="", max_length=64)
    hasTls: bool = False
    tlsVersion: str | None = Field(default=None, max_length=32)
    osFingerprint: str | None = Field(default=None, max_length=255)


class AgentDiscoveryIngest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schemaVersion: int
    rulesVersion: str = Field(max_length=32)
    clientJobId: str = Field(min_length=8, max_length=64)
    taskId: str | None = Field(default=None, min_length=36, max_length=36)
    cidrOrTargets: list[str] = Field(default_factory=list)
    ports: list[int] = Field(default_factory=list)
    scanInternal: bool = False
    startedAt: str | None = Field(default=None, max_length=40)
    results: list[AgentDiscoveryResultIn] = Field(default_factory=list)

    @field_validator("cidrOrTargets")
    @classmethod
    def _limit_targets(cls, v: list[str]) -> list[str]:
        from .config import settings

        if len(v) > settings.agent_max_discovery_targets:
            raise ValueError(
                "cidrOrTargets exceeds limit "
                f"({settings.agent_max_discovery_targets})"
            )
        if any(not item or len(item) > 64 for item in v):
            raise ValueError("cidrOrTargets entries must be 1..64 chars")
        return v

    @field_validator("ports")
    @classmethod
    def _limit_ports(cls, v: list[int]) -> list[int]:
        from .config import settings

        if len(v) > settings.agent_max_discovery_ports:
            raise ValueError(
                f"ports exceeds limit ({settings.agent_max_discovery_ports})"
            )
        if any(not 1 <= port <= 65535 for port in v):
            raise ValueError("ports must be between 1 and 65535")
        return v

    @field_validator("results")
    @classmethod
    def _limit_results(cls, v: list) -> list:
        from .config import settings

        if len(v) > settings.agent_max_discovery_results:
            raise ValueError(
                f"results exceeds limit ({settings.agent_max_discovery_results})"
            )
        return v


class SlaSettingsIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    criticalDays: int = Field(ge=1, le=365)
    highDays: int = Field(ge=1, le=365)
    mediumDays: int = Field(ge=1, le=365)
