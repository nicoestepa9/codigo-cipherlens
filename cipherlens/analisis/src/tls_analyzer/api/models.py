"""Modelos ORM de la plataforma CryptoGuard.

Estructura central (según plan):
  Asset -> Service -> Certificate
  Scan -> Finding
  Alert / AlertThreshold / ComplianceWindow
  DiscoveryJob -> DiscoveryResult
  ApiKey / Integration
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    Index,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def _uuid() -> str:
    return str(uuid.uuid4())


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class TenantMixin:
    organization_id: Mapped[int] = mapped_column(
        ForeignKey("organizations.id"), nullable=False, index=True
    )


class Asset(TenantMixin, Base):
    __tablename__ = "assets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    ip_address: Mapped[str] = mapped_column(String(64), default="")
    hostname: Mapped[str | None] = mapped_column(String(255), default="")
    port: Mapped[int] = mapped_column(Integer, default=443)
    service: Mapped[str] = mapped_column(String(128), default="")
    tls_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    scope: Mapped[str] = mapped_column(String(20), default="external")
    inventory_status: Mapped[str] = mapped_column(String(20), default="shadow_it")
    source: Mapped[str] = mapped_column(String(20), default="manual")  # manual|discovery
    is_internal: Mapped[bool] = mapped_column(Boolean, default=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    # NULL = inventario escaneado por la propia plataforma (Parte 5).
    agent_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)

    __table_args__ = (
        Index(
            "uq_assets_agent_identity", "agent_id", "ip_address", "hostname", "port", unique=True,
            sqlite_where=text("agent_id IS NOT NULL"),
            postgresql_where=text("agent_id IS NOT NULL"),
        ),
        Index(
            "uq_assets_platform_identity", "organization_id", "ip_address", "hostname", "port", unique=True,
            sqlite_where=text("agent_id IS NULL"),
            postgresql_where=text("agent_id IS NULL"),
        ),
    )


class Service(TenantMixin, Base):
    __tablename__ = "services"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    asset_id: Mapped[str | None] = mapped_column(ForeignKey("assets.id"), nullable=True)
    host: Mapped[str] = mapped_column(String(255), default="")
    ip_address: Mapped[str] = mapped_column(String(64), default="")
    port: Mapped[int] = mapped_column(Integer, default=443)
    name: Mapped[str] = mapped_column(String(255), default="")
    protocol: Mapped[str] = mapped_column(String(64), default="https")
    service: Mapped[str] = mapped_column(String(128), default="")
    tls_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    tls_version: Mapped[str] = mapped_column(String(32), default="")
    cipher_suite: Mapped[str] = mapped_column(String(128), default="")
    security_status: Mapped[str] = mapped_column(String(20), default="unknown")
    os_fingerprint: Mapped[str | None] = mapped_column(String(255), nullable=True)
    certificate_id: Mapped[str | None] = mapped_column(ForeignKey("certificates.id"), nullable=True)
    scope: Mapped[str] = mapped_column(String(20), default="external")  # internal|external
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    vulnerability_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    default_owner_user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    default_owner_team_id: Mapped[str | None] = mapped_column(ForeignKey("teams.id"), nullable=True)
    # Identidad de Service: (agent_id, host, port). NULL = plataforma local.
    agent_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)

    asset: Mapped[Asset | None] = relationship()

    __table_args__ = (
        Index(
            "uq_services_agent_host_port", "agent_id", "host", "port", unique=True,
            sqlite_where=text("agent_id IS NOT NULL"),
            postgresql_where=text("agent_id IS NOT NULL"),
        ),
        Index(
            "uq_services_platform_host_port", "organization_id", "host", "port", unique=True,
            sqlite_where=text("agent_id IS NULL"),
            postgresql_where=text("agent_id IS NULL"),
        ),
    )


class Certificate(TenantMixin, Base):
    __tablename__ = "certificates"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    service_id: Mapped[str | None] = mapped_column(ForeignKey("services.id"), nullable=True)
    domain: Mapped[str] = mapped_column(String(255), default="")
    subject_cn: Mapped[str] = mapped_column(String(255), default="")
    issuer_cn: Mapped[str] = mapped_column(String(255), default="")
    serial_number: Mapped[str] = mapped_column(String(128), default="")
    not_before: Mapped[str] = mapped_column(String(64), default="")
    not_after: Mapped[str] = mapped_column(String(64), default="")
    days_until_expiry: Mapped[int] = mapped_column(Integer, default=0)
    is_expired: Mapped[bool] = mapped_column(Boolean, default=False)
    key_type: Mapped[str] = mapped_column(String(64), default="")
    key_size: Mapped[int] = mapped_column(Integer, default=0)
    signature_algorithm: Mapped[str] = mapped_column(String(128), default="")
    fingerprint_sha256: Mapped[str] = mapped_column(String(128), default="", index=True)
    fingerprint_sha1: Mapped[str] = mapped_column(String(128), default="")
    is_self_signed: Mapped[bool] = mapped_column(Boolean, default=False)
    san: Mapped[list] = mapped_column(JSON, default=list)
    subject: Mapped[dict] = mapped_column(JSON, default=dict)
    issuer: Mapped[dict] = mapped_column(JSON, default=dict)
    basic_constraints: Mapped[str] = mapped_column(String(128), default="")
    key_usage: Mapped[list] = mapped_column(JSON, default=list)
    extended_key_usage: Mapped[list] = mapped_column(JSON, default=list)
    ca_issuers: Mapped[list] = mapped_column(JSON, default=list)
    crl_distribution_points: Mapped[list] = mapped_column(JSON, default=list)
    ocsp_must_staple: Mapped[bool] = mapped_column(Boolean, default=False)
    origin: Mapped[str] = mapped_column(String(20), default="discovered")  # discovered|manual
    status: Mapped[str] = mapped_column(String(20), default="valid")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    # Owner propio solo cuando no hay service_id (carga manual). D9 del spec.
    owner_user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    owner_team_id: Mapped[str | None] = mapped_column(ForeignKey("teams.id"), nullable=True)


class Scan(TenantMixin, Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    service_id: Mapped[str | None] = mapped_column(ForeignKey("services.id"), nullable=True)
    origin: Mapped[str] = mapped_column(String(20), default="manual")  # manual|scheduled|agent
    recurring_scan_id: Mapped[int | None] = mapped_column(
        ForeignKey("recurring_scans.id", ondelete="SET NULL"), nullable=True
    )
    target: Mapped[str] = mapped_column(String(255), default="")
    host: Mapped[str] = mapped_column(String(255), default="")
    port: Mapped[int] = mapped_column(Integer, default=443)
    port_is_alternate: Mapped[bool] = mapped_column(Boolean, default=False)
    status: Mapped[str] = mapped_column(String(20), default="completed")  # running|completed|failed
    score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    profile: Mapped[str] = mapped_column(String(32), default="citizen-facing")
    started_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    ai_recommendation: Mapped[str | None] = mapped_column(Text, nullable=True)
    connection_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    raw_result: Mapped[dict] = mapped_column(JSON, default=dict)
    # Parte 5: scans enviados por un agente (origin="agent") son idempotentes.
    agent_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    client_scan_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # Resultado de una tarea remota; NULL para scans iniciados por flujos previos.
    task_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    # Parte 5.6: nivel de carga efectivo y version de reglas del agente.
    upload_level: Mapped[str | None] = mapped_column(String(16), nullable=True)
    rules_version: Mapped[str | None] = mapped_column(String(32), nullable=True)

    findings: Mapped[list["Finding"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    service: Mapped["Service | None"] = relationship()

    __table_args__ = (
        Index("uq_scans_agent_client", "agent_id", "client_scan_id", unique=True),
        Index(
            "uq_scans_task_id", "task_id", unique=True,
            sqlite_where=text("task_id IS NOT NULL"),
            postgresql_where=text("task_id IS NOT NULL"),
        ),
    )


class Finding(TenantMixin, Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"))
    rule_id: Mapped[str] = mapped_column(String(64), default="")
    title: Mapped[str] = mapped_column(String(255), default="")
    description: Mapped[str] = mapped_column(Text, default="")
    evidence: Mapped[str] = mapped_column(Text, default="")
    recommendation: Mapped[str] = mapped_column(Text, default="")
    section_reference: Mapped[str] = mapped_column(String(128), default="")
    citation: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(20), default="info")
    category: Mapped[str] = mapped_column(String(64), default="")
    affected_host: Mapped[str] = mapped_column(String(255), default="")
    source_document: Mapped[str] = mapped_column(String(32), default="")  # 80052|80057|800131a
    evaluable: Mapped[bool] = mapped_column(Boolean, default=True)
    status: Mapped[str | None] = mapped_column(String(32), nullable=True)  # Acceptable|...
    detection_date: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    issue_id: Mapped[str | None] = mapped_column(ForeignKey("issues.id"), nullable=True, index=True)

    scan: Mapped[Scan] = relationship(back_populates="findings")
    issue: Mapped["Issue | None"] = relationship(back_populates="findings")


class Team(TenantMixin, Base):
    __tablename__ = "teams"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)

    members: Mapped[list["TeamMember"]] = relationship(
        back_populates="team", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("uq_teams_org_name", "organization_id", "name", unique=True),
    )


class TeamMember(TenantMixin, Base):
    __tablename__ = "team_members"

    team_id: Mapped[str] = mapped_column(ForeignKey("teams.id"), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), primary_key=True)
    is_lead: Mapped[bool] = mapped_column(Boolean, default=False)
    added_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)

    team: Mapped[Team] = relationship(back_populates="members")


class Issue(TenantMixin, Base):
    __tablename__ = "issues"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    service_id: Mapped[str] = mapped_column(ForeignKey("services.id"), nullable=False, index=True)
    source_document: Mapped[str] = mapped_column(String(32), default="")
    rule_id: Mapped[str] = mapped_column(String(64), default="")
    title: Mapped[str] = mapped_column(String(255), default="")
    severity: Mapped[str] = mapped_column(String(20), default="medium")  # critical|high|medium|low
    status: Mapped[str] = mapped_column(
        String(32),
        default="open",
    )  # open|assigned|in_progress|resolved|verified|risk_accepted|false_positive

    owner_user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    owner_team_id: Mapped[str | None] = mapped_column(ForeignKey("teams.id"), nullable=True)

    first_seen_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_scan_id: Mapped[str | None] = mapped_column(ForeignKey("scans.id"), nullable=True)
    due_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    resolved_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    resolved_by: Mapped[str | None] = mapped_column(String(16), nullable=True)  # system|user
    verified_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    clean_scans_since_resolved: Mapped[int] = mapped_column(Integer, default=0)

    risk_accepted_by: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    risk_acceptance_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    risk_accepted_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    reopened_count: Mapped[int] = mapped_column(Integer, default=0)
    last_certificate_fingerprint: Mapped[str | None] = mapped_column(String(128), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow, onupdate=_utcnow)

    service: Mapped[Service] = relationship()
    owner_user: Mapped[User | None] = relationship(foreign_keys=[owner_user_id])
    owner_team: Mapped[Team | None] = relationship(foreign_keys=[owner_team_id])

    findings: Mapped[list["Finding"]] = relationship(back_populates="issue")
    history: Mapped[list["IssueHistory"]] = relationship(
        back_populates="issue", order_by="IssueHistory.ts", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index(
            "uq_issues_identity",
            "organization_id",
            "service_id",
            "source_document",
            "rule_id",
            unique=True,
        ),
    )


class IssueHistory(TenantMixin, Base):
    __tablename__ = "issue_history"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    issue_id: Mapped[str] = mapped_column(ForeignKey("issues.id"), nullable=False, index=True)
    ts: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    actor_user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    actor_type: Mapped[str] = mapped_column(String(16), default="user")  # user|system
    event_type: Mapped[str] = mapped_column(String(32), default="")
    from_value: Mapped[str | None] = mapped_column(String(64), nullable=True)
    to_value: Mapped[str | None] = mapped_column(String(64), nullable=True)
    comment: Mapped[str | None] = mapped_column(Text, nullable=True)
    scan_id: Mapped[str | None] = mapped_column(ForeignKey("scans.id"), nullable=True)

    issue: Mapped[Issue] = relationship(back_populates="history")

    __table_args__ = (Index("ix_issue_history_ts", "ts"),)


class Alert(TenantMixin, Base):
    __tablename__ = "alerts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    type: Mapped[str] = mapped_column(String(40), default="vulnerability")  # expiration|compliance|vulnerability|discovery|system
    severity: Mapped[str] = mapped_column(String(20), default="info")
    title: Mapped[str] = mapped_column(String(255), default="")
    description: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(20), default="unread")  # unread|read|resolved|ignored
    related_target: Mapped[str | None] = mapped_column(String(255), nullable=True)
    related_certificate_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    related_scan_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    related_issue_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    action_label: Mapped[str | None] = mapped_column(String(64), nullable=True)
    action_href: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class AlertThreshold(TenantMixin, Base):
    __tablename__ = "alert_thresholds"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    days_before_expiry: Mapped[list] = mapped_column(JSON, default=lambda: [30, 15, 7])
    notify_on_critical_finding: Mapped[bool] = mapped_column(Boolean, default=True)
    notify_on_compliance: Mapped[bool] = mapped_column(Boolean, default=True)
    critical_days: Mapped[int] = mapped_column(Integer, default=7)
    warning_days: Mapped[int] = mapped_column(Integer, default=30)


class ComplianceWindow(TenantMixin, Base):
    __tablename__ = "compliance_windows"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(128), default="")
    framework: Mapped[str] = mapped_column(String(64), default="PCI-DSS")
    audit_date: Mapped[str] = mapped_column(String(32), default="")  # ISO date
    scope_filter: Mapped[list] = mapped_column(JSON, default=list)  # lista de dominios/hosts


class DiscoveryJob(TenantMixin, Base):
    __tablename__ = "discovery_jobs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    cidr_or_targets: Mapped[list] = mapped_column(JSON, default=list)
    port_list: Mapped[list] = mapped_column(JSON, default=list)
    domains: Mapped[list] = mapped_column(JSON, default=list)
    # Cloud jobs store immutable IP/hostname pairs resolved at admission time.
    resolved_targets: Mapped[list | None] = mapped_column(JSON, nullable=True)
    scan_internal: Mapped[bool] = mapped_column(Boolean, default=False)
    status: Mapped[str] = mapped_column(String(20), default="queued")  # queued|running|completed|failed
    progress: Mapped[int] = mapped_column(Integer, default=0)
    total_found: Mapped[int] = mapped_column(Integer, default=0)
    shadow_it_count: Mapped[int] = mapped_column(Integer, default=0)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Parte 5: jobs enviados por un agente son idempotentes por (agent_id, client_job_id).
    agent_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    client_job_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    task_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)

    results: Mapped[list["DiscoveryResult"]] = relationship(
        back_populates="job", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("uq_discovery_jobs_agent_client", "agent_id", "client_job_id", unique=True),
        Index(
            "uq_discovery_jobs_task_id", "task_id", unique=True,
            sqlite_where=text("task_id IS NOT NULL"),
            postgresql_where=text("task_id IS NOT NULL"),
        ),
    )


class DiscoveryResult(TenantMixin, Base):
    __tablename__ = "discovery_results"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    discovery_job_id: Mapped[str] = mapped_column(ForeignKey("discovery_jobs.id"))
    ip_address: Mapped[str] = mapped_column(String(64), default="")
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    port: Mapped[int] = mapped_column(Integer, default=0)
    service: Mapped[str] = mapped_column(String(64), default="")
    service_name: Mapped[str] = mapped_column(String(64), default="")
    has_tls: Mapped[bool] = mapped_column(Boolean, default=False)
    tls_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    os_fingerprint: Mapped[str | None] = mapped_column(String(255), nullable=True)
    inventory_status: Mapped[str] = mapped_column(String(20), default="shadow_it")  # inventoried|shadow_it
    matched_asset_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    scope: Mapped[str] = mapped_column(String(20), default="external")
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)

    job: Mapped[DiscoveryJob] = relationship(back_populates="results")


class ApiKey(TenantMixin, Base):
    __tablename__ = "api_keys"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(128), default="")
    key_hash: Mapped[str] = mapped_column(String(128), default="")
    prefix: Mapped[str] = mapped_column(String(16), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    role: Mapped[str] = mapped_column(String(32), default="lead")  # admin|lead|user, nunca admin
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class Integration(TenantMixin, Base):
    __tablename__ = "integrations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(128), default="")
    type: Mapped[str] = mapped_column(String(64), default="")
    description: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(20), default="disconnected")  # connected|disconnected|pending
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class Agent(TenantMixin, Base):
    """Agente on-premise enrolado (Parte 5).

    Cada agente tiene su propia ApiKey con ``role="agent"``; el ``agent_id``
    identifica el inventario que recolecto (Service/Scan/DiscoveryJob/Asset).
    """
    __tablename__ = "agents"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(255), default="")
    site_label: Mapped[str] = mapped_column(String(128), default="")
    api_key_id: Mapped[str | None] = mapped_column(ForeignKey("api_keys.id"), nullable=True)
    version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="active")  # active|revoked
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    schema_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    rules_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    reported_capabilities: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    api_key: Mapped["ApiKey | None"] = relationship()


class AgentTask(TenantMixin, Base):
    """Trabajo remoto, limitado a scans TLS/discovery y a un agente inscrito."""

    __tablename__ = "agent_tasks"
    __table_args__ = (
        CheckConstraint(
            "type IN ('scan', 'discovery')", name="ck_agent_tasks_type"
        ),
        CheckConstraint(
            "status IN ('queued', 'claimed', 'running', 'done', 'failed', "
            "'rejected', 'expired', 'cancelled')",
            name="ck_agent_tasks_status",
        ),
        Index("ix_agent_tasks_agent_status", "agent_id", "status", "created_at"),
        Index("ix_agent_tasks_org_status", "organization_id", "status", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    agent_id: Mapped[str] = mapped_column(ForeignKey("agents.id"), nullable=False)
    type: Mapped[str] = mapped_column(String(16), nullable=False)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="queued")
    requested_by_user_id: Mapped[str | None] = mapped_column(
        ForeignKey("users.id"), nullable=True
    )
    recurring_scan_id: Mapped[int | None] = mapped_column(
        ForeignKey("recurring_scans.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    result_scan_id: Mapped[str | None] = mapped_column(
        ForeignKey("scans.id", ondelete="SET NULL"), nullable=True
    )
    result_job_id: Mapped[str | None] = mapped_column(
        ForeignKey("discovery_jobs.id", ondelete="SET NULL"), nullable=True
    )


class Cve(Base):
    """Detalle cacheado de un CVE desde NVD."""
    __tablename__ = "cves"

    cve_id: Mapped[str] = mapped_column(String(20), primary_key=True)
    name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    cvss_v3_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_v3_vector: Mapped[str | None] = mapped_column(String(128), nullable=True)
    summary: Mapped[str] = mapped_column(Text, default="")
    published_date: Mapped[str | None] = mapped_column(String(32), nullable=True)
    last_modified_date: Mapped[str | None] = mapped_column(String(32), nullable=True)
    source_url: Mapped[str] = mapped_column(String(256), default="")
    fetched_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)


class ScanCveMatch(TenantMixin, Base):
    """Asociación entre un scan y los CVEs encontrados (estáticos + live)."""
    __tablename__ = "scan_cve_matches"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"))
    cve_id: Mapped[str] = mapped_column(ForeignKey("cves.cve_id"))
    match_type: Mapped[str] = mapped_column(String(20), default="static")  # static|cpe|keyword
    stale: Mapped[bool] = mapped_column(Boolean, default=False)
    keyword: Mapped[str | None] = mapped_column(String(200), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)

    scan: Mapped[Scan] = relationship()
    cve: Mapped[Cve] = relationship()


class CveQueryCache(Base):
    """Cache de queries a NVD (por CPE o keyword) para evitar requests repetidos."""
    __tablename__ = "cve_query_cache"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    query_type: Mapped[str] = mapped_column(String(20), default="cpe")  # cpe|keyword
    query_value: Mapped[str] = mapped_column(String(256), default="")
    cve_ids: Mapped[list] = mapped_column(JSON, default=list)
    fetched_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)


class RecurringScan(TenantMixin, Base):
    """Target programado: se escanea periodicamente por el ScanScheduler."""

    __tablename__ = "recurring_scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    host: Mapped[str] = mapped_column(String(255), default="")
    port: Mapped[int] = mapped_column(Integer, default=443)
    alternate_ports: Mapped[list | None] = mapped_column(JSON, nullable=True)
    profile: Mapped[str] = mapped_column(String(32), default="citizen-facing")
    interval_hours: Mapped[float] = mapped_column(Float, default=24.0)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    is_running: Mapped[bool] = mapped_column(Boolean, default=False)
    consecutive_failures: Mapped[int] = mapped_column(Integer, default=0)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    next_run_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    service_id: Mapped[str | None] = mapped_column(ForeignKey("services.id"), nullable=True)
    # NULL = ejecuta la plataforma; no nulo = el agente pide la tarea.
    agent_id: Mapped[str | None] = mapped_column(
        ForeignKey("agents.id", ondelete="SET NULL"), nullable=True, index=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)


class Organization(Base):
    """Organizacion."""
    __tablename__ = "organizations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    slug: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, default="")
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="active")  # active|disabled
    ai_mode: Mapped[str] = mapped_column(String(16), nullable=False, default="template")  # external|template
    max_agents: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    max_cloud_scans_per_hour: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    max_recurring_scans: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    sla_days_critical: Mapped[int | None] = mapped_column(Integer, nullable=True)
    sla_days_high: Mapped[int | None] = mapped_column(Integer, nullable=True)
    sla_days_medium: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("CURRENT_TIMESTAMP"), nullable=False
    )


class User(Base):
    """Usuario del sistema con roles."""
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    organization_id: Mapped[int | None] = mapped_column(
        ForeignKey("organizations.id"), nullable=True, index=True
    )
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    password_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(32), default="user")  # admin|lead|user|viewer|operator
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    failed_login_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), 
        server_default=text("CURRENT_TIMESTAMP"), 
        nullable=True,
        default=lambda: datetime.now(timezone.utc)
    )
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    organization: Mapped[Organization | None] = relationship()


class RefreshToken(TenantMixin, Base):
    """Refresh token opaco con rotacion."""
    __tablename__ = "refresh_tokens"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("CURRENT_TIMESTAMP"), nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    replaced_by_id: Mapped[str | None] = mapped_column(String(36))
    user_agent: Mapped[str | None] = mapped_column(String(512))
    ip: Mapped[str | None] = mapped_column(String(64))

    user: Mapped[User] = relationship()


class AuditLog(TenantMixin, Base):
    """Auditoria inmutable."""
    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    ts: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("CURRENT_TIMESTAMP"), nullable=False
    )
    actor_user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"))
    actor_type: Mapped[str] = mapped_column(String(32), default="user")  # user|system|api_key|agent
    action: Mapped[str] = mapped_column(String(128), nullable=False)
    entity_type: Mapped[str | None] = mapped_column(String(64))
    entity_id: Mapped[str | None] = mapped_column(String(128))
    ip: Mapped[str | None] = mapped_column(String(64))
    meta: Mapped[dict | None] = mapped_column(JSON, name="metadata")

    __table_args__ = (Index("ix_audit_logs_ts", "ts"),)
