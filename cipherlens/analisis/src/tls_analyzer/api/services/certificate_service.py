"""Servicio de certificados: inventario, detalle, expiración e issuers."""

from __future__ import annotations

from typing import Optional

from sqlalchemy import or_
from sqlalchemy.orm import Session

from ..models import Agent, Certificate, Finding, Service
from .alert_service import resolve_thresholds


def _cert_status(c: Certificate, warning_days: int) -> str:
    if c.is_expired or (c.days_until_expiry is not None and c.days_until_expiry < 0):
        return "expired"
    if c.days_until_expiry is not None and c.days_until_expiry <= warning_days:
        return "expiring_soon"
    return "valid"


def _cert_to_dto(c: Certificate, warning_days: int | None = None) -> dict:
    return {
        "id": c.id,
        "domain": c.domain or c.subject_cn,
        "commonName": c.subject_cn,
        "subject": c.subject or {},
        "issuerName": c.issuer_cn,
        "issuer": c.issuer or {},
        "serialNumber": c.serial_number,
        "notBefore": c.not_before,
        "notAfter": c.not_after,
        "daysUntilExpiry": c.days_until_expiry,
        "isExpired": c.is_expired,
        "san": c.san or [],
        "keyType": c.key_type,
        "keySize": c.key_size,
        "signatureAlgorithm": c.signature_algorithm,
        "fingerprintSha256": c.fingerprint_sha256,
        "fingerprintSha1": c.fingerprint_sha1,
        "isSelfSigned": c.is_self_signed,
        "basicConstraints": c.basic_constraints or "",
        "keyUsage": c.key_usage or [],
        "extendedKeyUsage": c.extended_key_usage or [],
        "caIssuers": c.ca_issuers or [],
        "crlDistributionPoints": c.crl_distribution_points or [],
        "ocspMustStaple": c.ocsp_must_staple,
        "status": _cert_status(c, warning_days) if warning_days is not None else (c.status or "valid"),
        "origin": c.origin or "discovered",
        "serviceId": c.service_id,
        "serviceName": None,
        "agentId": None,
        "siteLabel": None,
    }


def _cert_to_dto_enriched(db: Session, c: Certificate, warning_days: int | None = None) -> dict:
    dto = _cert_to_dto(c, warning_days)
    svc = db.get(Service, c.service_id) if c.service_id else None
    if svc:
        dto["serviceName"] = svc.name or svc.host
        dto["agentId"] = svc.agent_id
        if svc.agent_id:
            agent = db.get(Agent, svc.agent_id)
            if agent:
                dto["siteLabel"] = agent.site_label
    return dto


def list_certificates(
    db: Session,
    search: Optional[str] = None,
    status: Optional[str] = None,
    issuer: Optional[str] = None,
    origin: Optional[str] = None,
    agent_id: Optional[str] = None,
    site_label: Optional[str] = None,
    page: int = 1,
    page_size: int = 12,
    organization_id: int | None = None,
) -> dict:
    _, warning_days = resolve_thresholds(db, organization_id)
    q = db.query(Certificate)
    if search:
        s = f"%{search.strip().lower()}%"
        q = q.filter(or_(
            Certificate.domain.ilike(s),
            Certificate.subject_cn.ilike(s),
            Certificate.issuer_cn.ilike(s),
            Certificate.serial_number.ilike(s),
        ))
    if status and status != "all":
        if status == "expired":
            q = q.filter(or_(
                Certificate.is_expired.is_(True),
                Certificate.days_until_expiry < 0,
            ))
        elif status == "expiring_soon":
            q = q.filter(
                Certificate.is_expired.is_(False),
                Certificate.days_until_expiry >= 0,
                Certificate.days_until_expiry <= warning_days,
            )
        elif status == "valid":
            q = q.filter(
                Certificate.is_expired.is_(False),
                Certificate.days_until_expiry > warning_days,
            )
        else:
            q = q.filter(Certificate.status == status)
    if issuer and issuer != "all":
        q = q.filter(Certificate.issuer_cn == issuer)
    if origin and origin != "all":
        q = q.filter(Certificate.origin == origin)
    if agent_id or site_label:
        q = q.join(Service, Service.id == Certificate.service_id).join(
            Agent, Agent.id == Service.agent_id
        )
        if agent_id:
            q = q.filter(Service.agent_id == agent_id)
        if site_label:
            q = q.filter(Agent.site_label.ilike(f"%{site_label.strip()}%"))
    total = q.count()
    rows = (
        q.order_by(Certificate.not_after.asc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    items = [_cert_to_dto_enriched(db, c, warning_days) for c in rows]
    return {"items": items, "total": total, "page": page, "pageSize": page_size}


def get_certificate_detail(
    db: Session,
    cert_id: str,
    organization_id: int | None = None,
) -> Optional[dict]:
    cert = db.get(Certificate, cert_id)
    if cert is None:
        return None

    _, warning_days = resolve_thresholds(db, organization_id)
    root_name = cert.issuer_cn.replace("G2", "Root").replace("WE1", "Root G2") or "Root CA"
    chain = [
        {
            "id": f"{cert.id}_root",
            "commonName": root_name,
            "issuerName": root_name,
            "isRoot": True,
            "isLeaf": False,
            "selfSigned": True,
            "notBefore": "2019-01-01T00:00:00Z",
            "notAfter": "2039-01-01T00:00:00Z",
        },
        {
            "id": f"{cert.id}_intermediate",
            "commonName": cert.issuer_cn,
            "issuerName": root_name,
            "isRoot": False,
            "isLeaf": False,
            "selfSigned": False,
            "notBefore": cert.not_before,
            "notAfter": cert.not_after,
        },
        {
            "id": cert.id,
            "commonName": cert.subject_cn,
            "issuerName": cert.issuer_cn,
            "isRoot": False,
            "isLeaf": True,
            "selfSigned": cert.is_self_signed,
            "notBefore": cert.not_before,
            "notAfter": cert.not_after,
        },
    ]

    related_services = []
    service_filter = Service.certificate_id == cert.id
    if cert.service_id:
        service_filter = or_(service_filter, Service.id == cert.service_id)
    for s in db.query(Service).filter(service_filter).all():
        related_services.append({
            "id": s.id,
            "name": s.name or s.host,
            "host": s.host,
            "port": s.port,
            "tlsVersion": s.tls_version,
            "securityStatus": s.security_status,
        })

    related_findings = db.query(Finding).filter(
        Finding.affected_host.in_([cert.domain, cert.subject_cn, *cert.san])
    ).count()

    return {
        "certificate": _cert_to_dto_enriched(db, cert, warning_days),
        "chain": chain,
        "relatedServices": related_services,
        "relatedFindings": related_findings,
    }


def expiration_stats(
    db: Session,
    critical_days: int | None = None,
    warning_days: int | None = None,
    organization_id: int | None = None,
) -> dict:
    critical_days, warning_days = resolve_thresholds(
        db, organization_id, critical_days, warning_days
    )
    certs = db.query(Certificate).all()

    def is_expired(c: Certificate) -> bool:
        return bool(c.is_expired) or (
            c.days_until_expiry is not None and c.days_until_expiry < 0
        )

    expired = sum(1 for c in certs if is_expired(c))
    critical = sum(
        1 for c in certs
        if not is_expired(c) and 0 <= c.days_until_expiry <= critical_days
    )
    warning = sum(
        1 for c in certs
        if not is_expired(c) and critical_days < c.days_until_expiry <= warning_days
    )
    healthy = sum(
        1 for c in certs if not is_expired(c) and c.days_until_expiry > warning_days
    )

    windows = [
        {"label": "Expired", "min": -9999, "max": 0, "count": expired},
        {"label": f"0-{critical_days} days", "min": 0, "max": critical_days, "count": critical},
        {
            "label": f"{critical_days + 1}-{warning_days} days",
            "min": critical_days + 1,
            "max": warning_days,
            "count": warning,
        },
        {
            "label": f">{warning_days} days",
            "min": warning_days + 1,
            "max": 9999,
            "count": healthy,
        },
    ]
    return {
        "expired": expired,
        "critical": critical,
        "warning": warning,
        "healthy": healthy,
        "total": len(certs),
        "criticalDays": critical_days,
        "warningDays": warning_days,
        "byWindow": windows,
    }


def issuers(db: Session) -> list[str]:
    rows = db.query(Certificate.issuer_cn).distinct().all()
    return sorted({r[0] for r in rows if r[0]})


def certificate_by_service(db: Session, service_id: str) -> Optional[Certificate]:
    return db.query(Certificate).filter(Certificate.service_id == service_id).first()
