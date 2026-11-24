"""Servicio del dashboard: metricas agregadas desde la base."""

from __future__ import annotations

from sqlalchemy import and_, func, or_
from sqlalchemy.orm import Session

from ..models import (
    Agent,
    Alert,
    Certificate,
    DiscoveryJob,
    DiscoveryResult,
    Finding,
    Issue,
    Scan,
    Service,
)
from .alert_service import resolve_thresholds


def dashboard_summary(
    db: Session,
    agent_id: str | None = None,
    site_label: str | None = None,
    organization_id: int | None = None,
) -> dict:
    critical_days, warning_days = resolve_thresholds(db, organization_id)
    if hasattr(agent_id, 'strip'):
        agent_id_val = agent_id.strip() or None
    else:
        agent_id_val = None
    if hasattr(site_label, 'strip'):
        site_label_val = site_label.strip() or None
    else:
        site_label_val = None
    sq = db.query(Service)
    if agent_id_val:
        sq = sq.filter(Service.agent_id == agent_id_val)
    if site_label_val:
        sq = sq.join(Agent, Agent.id == Service.agent_id).filter(
            Agent.site_label.ilike(f"%{site_label_val}%")
        )
    total_services = sq.count()

    cq = db.query(Certificate)
    if agent_id_val or site_label_val:
        cq = cq.join(Service, Service.id == Certificate.service_id).join(
            Agent, Agent.id == Service.agent_id
        )
        if agent_id_val:
            cq = cq.filter(Service.agent_id == agent_id_val)
        if site_label_val:
            cq = cq.filter(Agent.site_label.ilike(f"%{site_label_val}%"))
    total_certificates = cq.count()
    expiring_soon = cq.filter(
        Certificate.is_expired.is_(False),
        Certificate.days_until_expiry >= 0,
        Certificate.days_until_expiry <= warning_days,
    ).count()

    fq = db.query(Finding).join(Scan, Scan.id == Finding.scan_id)
    if agent_id_val or site_label_val:
        fq = fq.outerjoin(Service, Service.id == Scan.service_id)
        if agent_id_val:
            fq = fq.filter(
                or_(Scan.agent_id == agent_id_val, Service.agent_id == agent_id_val)
            )
        if site_label_val:
            matching_agents = db.query(Agent.id).filter(
                Agent.site_label.ilike(f"%{site_label_val}%")
            )
            fq = fq.filter(
                or_(
                    Scan.agent_id.in_(matching_agents),
                    Service.agent_id.in_(matching_agents),
                )
            )
    critical_vulns = fq.filter(Finding.severity == "critical").count()
    high_vulns = fq.filter(Finding.severity == "high").count()

    dq = db.query(DiscoveryResult.ip_address)
    if agent_id_val or site_label_val:
        dq = dq.join(DiscoveryJob, DiscoveryJob.id == DiscoveryResult.discovery_job_id).join(
            Agent, Agent.id == DiscoveryJob.agent_id
        )
        if agent_id_val:
            dq = dq.filter(DiscoveryJob.agent_id == agent_id_val)
        if site_label_val:
            dq = dq.filter(Agent.site_label.ilike(f"%{site_label_val}%"))
    shadow_it = (
        dq.filter(DiscoveryResult.inventory_status == "shadow_it")
        .distinct()
        .count()
    )

    rq = db.query(func.max(Scan.started_at))
    if agent_id_val:
        rq = rq.filter(Scan.agent_id == agent_id_val)
    if site_label_val:
        rq = rq.join(Service, Service.id == Scan.service_id, isouter=True).filter(
            or_(
                Scan.agent_id.in_(
                    db.query(Agent.id).filter(Agent.site_label.ilike(f"%{site_label_val}%"))
                ),
                Service.agent_id.in_(
                    db.query(Agent.id).filter(Agent.site_label.ilike(f"%{site_label_val}%"))
                ),
            )
        )
    last_scan = rq.scalar()
    last_scan_at = last_scan.isoformat() if last_scan else None

    aq = db.query(func.avg(Scan.score))
    if agent_id_val:
        aq = aq.filter(Scan.agent_id == agent_id_val)
    if site_label_val:
        aq = aq.join(Service, Service.id == Scan.service_id, isouter=True).filter(
            or_(
                Scan.agent_id.in_(
                    db.query(Agent.id).filter(Agent.site_label.ilike(f"%{site_label_val}%"))
                ),
                Service.agent_id.in_(
                    db.query(Agent.id).filter(Agent.site_label.ilike(f"%{site_label_val}%"))
                ),
            )
        )
    avg_score = aq.scalar()
    security_score = int(round(avg_score)) if avg_score is not None else 0

    secure = sq.filter(Service.security_status == "secure").count()
    warning = sq.filter(Service.security_status == "warning").count()
    critical = sq.filter(Service.security_status == "critical").count()

    alq = db.query(Alert)
    if agent_id_val or site_label_val:
        matching_agents = db.query(Agent.id)
        if agent_id_val:
            matching_agents = matching_agents.filter(Agent.id == agent_id_val)
        if site_label_val:
            matching_agents = db.query(Agent.id).filter(
                Agent.site_label.ilike(f"%{site_label_val}%")
            )
        scan_ids = (
            db.query(Scan.id)
            .outerjoin(Service, Service.id == Scan.service_id)
            .filter(
                or_(
                    Scan.agent_id.in_(matching_agents),
                    Service.agent_id.in_(matching_agents),
                )
            )
        )
        certificate_ids = (
            db.query(Certificate.id)
            .join(Service, Service.id == Certificate.service_id)
            .filter(Service.agent_id.in_(matching_agents))
        )
        issue_ids = (
            db.query(Issue.id)
            .join(Service, Service.id == Issue.service_id)
            .filter(Service.agent_id.in_(matching_agents))
        )
        alq = alq.filter(
            or_(
                Alert.related_scan_id.in_(scan_ids),
                Alert.related_certificate_id.in_(certificate_ids),
                Alert.related_issue_id.in_(issue_ids),
                and_(
                    Alert.type == "agent_offline",
                    Alert.related_target.in_(matching_agents),
                ),
            )
        )
    unread_alerts = alq.filter(Alert.status == "unread").count()

    return {
        "totalServices": total_services,
        "totalCertificates": total_certificates,
        "certificatesExpiringSoon": expiring_soon,
        "criticalVulnerabilities": critical_vulns,
        "highVulnerabilities": high_vulns,
        "shadowItDetected": shadow_it,
        "lastScanAt": last_scan_at,
        "securityScore": security_score,
        "secure": secure,
        "warning": warning,
        "critical": critical,
        "unreadAlerts": unread_alerts,
        "certificateCriticalDays": critical_days,
        "certificateWarningDays": warning_days,
    }
