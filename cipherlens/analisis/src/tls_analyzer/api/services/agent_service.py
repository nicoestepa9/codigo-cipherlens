"""Servicio de agentes on-premise (Parte 5): gestion (admin) e ingesta."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from ... import analysis
from ...discovery import is_internal_ip
from ..config import settings
from ..deps import generate_api_key, hash_api_key
from ..finding_catalog import canonicalize_findings
from ..models import (
    Agent,
    ApiKey,
    Asset,
    DiscoveryJob,
    DiscoveryResult,
    Organization,
    Scan,
    Service,
    User,
)
from ..tenancy import get_session_org_id
from . import auth_service, scan_service


def _get_default_org_id(db: Session) -> int:
    session_org_id = get_session_org_id(db)
    if session_org_id is not None:
        return int(session_org_id)
    org = db.query(Organization).first()
    if org is None:
        org = Organization(name="Default Org", slug="default", status="active")
        db.add(org)
        db.flush()
    return org.id

logger = logging.getLogger(__name__)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt


def is_online(agent: Agent) -> bool:
    last = _as_utc(agent.last_seen_at)
    if last is None or agent.status != "active":
        return False
    return (_utcnow() - last).total_seconds() <= settings.agent_offline_seconds


def _agent_dto(db: Session, agent: Agent, *, service_count: int | None = None) -> dict:
    key = db.get(ApiKey, agent.api_key_id) if agent.api_key_id else None
    if service_count is None:
        service_count = (
            db.query(Service).filter(Service.agent_id == agent.id).count()
        )
    return {
        "id": agent.id,
        "name": agent.name,
        "siteLabel": agent.site_label or "",
        "status": agent.status,
        "version": agent.version,
        "lastSeenAt": agent.last_seen_at.isoformat() if agent.last_seen_at else None,
        "lastIp": agent.last_ip,
        "createdAt": agent.created_at.isoformat() if agent.created_at else "",
        "revokedAt": agent.revoked_at.isoformat() if agent.revoked_at else None,
        "schemaVersion": agent.schema_version,
        "rulesVersion": agent.rules_version,
        "serviceCount": service_count,
        "keyPrefix": key.prefix if key else None,
        "isOnline": is_online(agent),
        "reportedCapabilities": agent.reported_capabilities,
    }


def _new_agent_key(db: Session, name: str, organization_id: int | None = None) -> tuple[ApiKey, str]:
    if organization_id is None:
        organization_id = _get_default_org_id(db)
    plain = generate_api_key()
    key = ApiKey(
        name=f"agent:{name}"[:128],
        key_hash=hash_api_key(plain),
        prefix=plain[:8] + "...",
        role="agent",
        user_id=None,
        organization_id=organization_id,
    )
    db.add(key)
    db.flush()
    return key, plain


def create_agent(db: Session, name: str, site_label: str, *, actor_user_id: str | None) -> tuple[dict, str]:
    org_id = None
    if actor_user_id:
        u = db.get(User, actor_user_id)
        if u and getattr(u, "organization_id", None):
            org_id = u.organization_id
    if org_id is None:
        org_id = _get_default_org_id(db)
    key, plain = _new_agent_key(db, name, org_id)
    agent = Agent(
        name=name,
        site_label=site_label or "",
        api_key_id=key.id,
        status="active",
        organization_id=org_id,
    )
    db.add(agent)
    db.flush()
    try:
        auth_service.audit(
            db, "agent.enrolled", actor_user_id=actor_user_id, actor_type="user",
            entity_type="agent", entity_id=agent.id, meta={"name": name},
        )
    except Exception:
        pass
    db.commit()
    db.refresh(agent)
    dto = _agent_dto(db, agent, service_count=0)
    return dto, plain


def list_agents(db: Session) -> list[dict]:
    agents = db.query(Agent).order_by(Agent.created_at.desc()).all()
    # Conteo de servicios por agente en una sola consulta.
    counts: dict[str, int] = {}
    for agent_id, in db.query(Service.agent_id).filter(Service.agent_id.isnot(None)).all():
        counts[agent_id] = counts.get(agent_id, 0) + 1
    return [_agent_dto(db, a, service_count=counts.get(a.id, 0)) for a in agents]


def get_agent(db: Session, agent_id: str) -> dict | None:
    agent = db.get(Agent, agent_id)
    if agent is None:
        return None
    recent = (
        db.query(Scan)
        .filter(Scan.agent_id == agent_id)
        .order_by(Scan.started_at.desc())
        .limit(20)
        .all()
    )
    return {
        "agent": _agent_dto(db, agent),
        "recentScans": [
            {
                "id": s.id,
                "target": s.target,
                "status": s.status,
                "score": s.score,
                "origin": s.origin,
                "startedAt": s.started_at.isoformat() if s.started_at else None,
                "uploadLevel": s.upload_level,
            }
            for s in recent
        ],
    }


def update_agent(
    db: Session, agent_id: str, *, name: str | None, site_label: str | None
) -> dict | None:
    agent = db.get(Agent, agent_id)
    if agent is None:
        return None
    if name is not None:
        agent.name = name
    if site_label is not None:
        agent.site_label = site_label
    db.commit()
    db.refresh(agent)
    return _agent_dto(db, agent)


def rotate_key(db: Session, agent_id: str, *, actor_user_id: str | None) -> tuple[dict, str] | None:
    agent = db.get(Agent, agent_id)
    if agent is None or agent.status != "active":
        return None
    if agent.api_key_id:
        old = db.get(ApiKey, agent.api_key_id)
        if old is not None:
            old.revoked = True
    org_id = getattr(agent, "organization_id", None) or _get_default_org_id(db)
    key, plain = _new_agent_key(db, agent.name, org_id)
    agent.api_key_id = key.id
    auth_service.audit(
        db, "agent.key_rotated", actor_user_id=actor_user_id, actor_type="user",
        entity_type="agent", entity_id=agent.id,
    )
    db.commit()
    db.refresh(agent)
    return _agent_dto(db, agent), plain


def revoke_agent(db: Session, agent_id: str, *, actor_user_id: str | None) -> bool:
    agent = db.get(Agent, agent_id)
    if agent is None:
        return False
    agent.status = "revoked"
    agent.revoked_at = _utcnow()
    if agent.api_key_id:
        key = db.get(ApiKey, agent.api_key_id)
        if key is not None:
            key.revoked = True
    auth_service.audit(
        db, "agent.revoked", actor_user_id=actor_user_id, actor_type="user",
        entity_type="agent", entity_id=agent.id,
    )
    db.commit()
    return True


def record_heartbeat(
    db: Session, agent: Agent, payload, *, ip: str | None
) -> None:
    agent.last_seen_at = _utcnow()
    agent.version = getattr(payload, "agentVersion", None) or agent.version
    agent.last_ip = ip or agent.last_ip
    agent.schema_version = getattr(payload, "schemaVersion", None)
    if getattr(payload, "rulesVersion", None):
        agent.rules_version = payload.rulesVersion
    if getattr(payload, "capabilities", None) and isinstance(payload.capabilities, dict):
        try:
            agent.reported_capabilities = payload.capabilities
        except Exception:
            pass
    db.commit()


def _sync_agent_asset(
    db: Session, agent_id: str, host: str, ip: str, port: int, when: datetime
) -> None:
    """Registra el host del agente en su inventario de Assets (para discovery)."""
    if not ip and not host:
        return

    agent = db.get(Agent, agent_id)
    org_id = getattr(agent, "organization_id", None) if agent else None
    if org_id is None:
        org_id = _get_default_org_id(db)

    q = db.query(Asset).filter(Asset.agent_id == agent_id, Asset.port == port)
    if ip:
        q = q.filter(Asset.ip_address == ip)
    else:
        q = q.filter(Asset.hostname == host)
    asset = q.first()
    if asset is None:
        asset = Asset(
            ip_address=ip or "",
            hostname=host or "",
            port=port,
            is_internal=is_internal_ip(ip) if ip else False,
            agent_id=agent_id,
            organization_id=org_id,
        )
        db.add(asset)
    if not getattr(asset, "organization_id", None):
        asset.organization_id = org_id
    asset.last_seen = when


def ingest_scan(
    db: Session,
    agent: Agent,
    payload,
    *,
    task_id: str | None = None,
    recurring_scan_id: int | None = None,
) -> tuple[Scan, bool]:
    """Persiste un scan enviado por el agente. Devuelve ``(scan, created)``."""
    raw_result = dict(payload.rawResult or {})
    if not raw_result.get("handshake"):
        raw_result["handshake"] = dict(payload.handshake or {})
    handshake = raw_result["handshake"]
    for key, value in (
        ("ip_address", payload.ipAddress),
        ("negotiated_protocol", payload.negotiatedProtocol),
        ("negotiated_cipher", payload.negotiatedCipher),
        ("supported_protocols", payload.supportedProtocols),
    ):
        if value and not handshake.get(key):
            handshake[key] = value
    if not raw_result.get("certificate_chain"):
        chain = list(payload.chain or [])
        if not chain and payload.certificate:
            chain = [dict(payload.certificate)]
        raw_result["certificate_chain"] = chain
    findings, suspicious = canonicalize_findings(
        payload.findings,
        host=payload.target.host,
    )
    if suspicious:
        logger.warning(
            "Intento de prompt injection en findings de agente agent=%s findings=%d",
            agent.id,
            len(findings),
        )
    ar = analysis.AnalysisResult(
        host=payload.target.host,
        port=payload.target.port,
        port_is_alternate=payload.portIsAlternate,
        profile=payload.target.profile or analysis.nist.DEFAULT_PROFILE,
        score=payload.score,
        status=payload.status or "completed",
        started_at=payload.startedAt or _utcnow().isoformat(),
        duration_ms=payload.durationMs,
        connection_error=payload.connectionError,
        ip_address=payload.ipAddress,
        negotiated_protocol=payload.negotiatedProtocol,
        negotiated_cipher=payload.negotiatedCipher,
        supported_protocols=payload.supportedProtocols,
        findings=findings,
        certificate=payload.certificate or {},
        chain=payload.chain,
        handshake=payload.handshake,
        os_fingerprint=payload.osFingerprint,
        raw_result=raw_result,
    )
    _sync_agent_asset(
        db,
        agent.id,
        payload.target.host,
        payload.ipAddress,
        payload.target.port,
        _utcnow(),
    )
    return scan_service.ingest_scan_result(
        db,
        ar,
        agent_id=agent.id,
        client_scan_id=payload.clientScanId,
        task_id=task_id,
        recurring_scan_id=recurring_scan_id,
        upload_level=payload.uploadLevel,
        rules_version=payload.rulesVersion,
    )


def ingest_discovery(
    db: Session, agent: Agent, payload, *, task_id: str | None = None
) -> tuple[DiscoveryJob, bool]:
    """Persiste un job de discovery enviado por el agente.

    La clasificacion ``inventoried``/``shadow_it`` se hace contra los Assets del
    MISMO ``agent_id``. Idempotente por ``(agent_id, client_job_id)``.
    """
    existing = (
        db.query(DiscoveryJob).filter(DiscoveryJob.task_id == task_id).first()
        if task_id
        else None
    )
    if existing is None:
        existing = (
            db.query(DiscoveryJob)
            .filter(
                DiscoveryJob.agent_id == agent.id,
                DiscoveryJob.client_job_id == payload.clientJobId,
            )
            .first()
        )
        if task_id and existing is not None and existing.task_id != task_id:
            raise ValueError("clientJobId already belongs to another task")
    if existing is not None:
        return existing, False

    now = _utcnow()
    org_id = getattr(agent, "organization_id", None) or _get_default_org_id(db)
    job = DiscoveryJob(
        cidr_or_targets=list(payload.cidrOrTargets),
        port_list=list(payload.ports or [443]),
        domains=[],
        scan_internal=bool(payload.scanInternal),
        status="completed",
        agent_id=agent.id,
        client_job_id=payload.clientJobId,
        task_id=task_id,
        started_at=now,
        completed_at=now,
        progress=100,
        organization_id=org_id,
    )
    db.add(job)
    db.flush()

    assets = (
        db.query(Asset).filter(Asset.agent_id == agent.id).all()
    )
    by_ip = {(a.ip_address, a.port): a for a in assets if a.ip_address}
    by_host = {(a.hostname, a.port): a for a in assets if a.hostname}

    org_id = getattr(agent, "organization_id", None) or _get_default_org_id(db)
    if not getattr(job, "organization_id", None):
        job.organization_id = org_id

    matched = 0
    for r in payload.results:
        asset = by_ip.get((r.ipAddress, r.port)) or (
            by_host.get((r.hostname, r.port)) if r.hostname else None
        )
        if asset and not getattr(asset, "organization_id", None):
            try:
                asset.organization_id = org_id
            except Exception:
                pass
        if asset and r.tlsVersion:
            asset.tls_version = r.tlsVersion
        inventoried = asset is not None
        if inventoried:
            matched += 1
        db.add(DiscoveryResult(
            discovery_job_id=job.id,
            ip_address=r.ipAddress,
            hostname=r.hostname,
            port=r.port,
            service=r.service,
            service_name=r.serviceName,
            has_tls=r.hasTls,
            tls_version=r.tlsVersion,
            os_fingerprint=r.osFingerprint,
            inventory_status="inventoried" if inventoried else "shadow_it",
            matched_asset_id=asset.id if asset else None,
            scope="internal" if is_internal_ip(r.ipAddress) else "external",
            first_seen=now,
            last_seen=now,
        ))

    job.total_found = len(payload.results)
    job.shadow_it_count = len(payload.results) - matched
    db.commit()
    db.refresh(job)
    return job, True
