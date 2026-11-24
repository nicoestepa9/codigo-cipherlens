"""Servicio de servicios: inventario y detalle."""

from __future__ import annotations

from typing import Optional

from sqlalchemy import or_
from sqlalchemy.orm import Session

from ..models import Agent, Certificate, Service


def _service_to_dto(db: Session, s: Service) -> dict:
    cert = db.get(Certificate, s.certificate_id) if s.certificate_id else None
    asset = s.asset
    agent = db.get(Agent, s.agent_id) if s.agent_id else None
    return {
        "id": s.id,
        "name": s.name or f"{s.host}:{s.port}",
        "host": s.host,
        "ipAddress": s.ip_address,
        "port": s.port,
        "protocol": s.protocol or ("https" if s.tls_enabled else "tcp"),
        "service": s.service or ("HTTPS" if s.tls_enabled else "TCP"),
        "tlsVersion": s.tls_version,
        "cipherSuite": s.cipher_suite,
        "securityStatus": s.security_status or "unknown",
        "certificateId": s.certificate_id,
        "certificateDomain": cert.domain if cert else "",
        "certificateStatus": cert.status if cert else "unknown",
        "certificateDaysLeft": cert.days_until_expiry if cert else 0,
        "asset": {
            "id": asset.id if asset else s.asset_id or "",
            "name": asset.hostname if asset else s.host,
            "type": "server",
            "owner": "",
            "department": "",
            "declared": (asset is not None),
        },
        "scope": s.scope or "external",
        "lastSeen": s.last_seen.isoformat() if s.last_seen else "",
        "osFingerprint": s.os_fingerprint,
        "vulnerabilityCount": s.vulnerability_count or 0,
        "findingsSeverity": s.security_status if s.vulnerability_count else None,
        "agentId": s.agent_id,
        "siteLabel": agent.site_label if agent else None,
    }


def list_services(
    db: Session,
    search: Optional[str] = None,
    status: Optional[str] = None,
    scope: Optional[str] = None,
    tls_version: Optional[str] = None,
    agent_id: Optional[str] = None,
    site_label: Optional[str] = None,
    page: int = 1,
    page_size: int = 12,
) -> dict:
    q = db.query(Service)
    if search:
        s = f"%{search.strip().lower()}%"
        q = q.filter(or_(
            Service.host.ilike(s), Service.name.ilike(s), Service.ip_address.ilike(s),
        ))
    if status and status != "all":
        q = q.filter(Service.security_status == status)
    if scope and scope != "all":
        q = q.filter(Service.scope == scope)
    if tls_version:
        q = q.filter(Service.tls_version == tls_version)
    if agent_id:
        q = q.filter(Service.agent_id == agent_id)
    if site_label:
        q = q.join(Agent, Agent.id == Service.agent_id).filter(
            Agent.site_label.ilike(f"%{site_label.strip()}%")
        )
    total = q.count()
    rows = (
        q.order_by(Service.last_seen.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    return {
        "items": [_service_to_dto(db, s) for s in rows],
        "total": total,
        "page": page,
        "pageSize": page_size,
    }


def get_service(db: Session, service_id: str) -> Optional[dict]:
    s = db.get(Service, service_id)
    if s is None:
        return None
    return _service_to_dto(db, s)
