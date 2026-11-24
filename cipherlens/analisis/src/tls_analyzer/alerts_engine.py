"""Motor de alertas: vencimiento, compliance y vulnerabilidades.

- ``generate_expiration_alerts``: recorre Certificate vs AlertThreshold.
- ``generate_compliance_alerts``: cruza ComplianceWindow proximas con findings
  CRITICAL/HIGH abiertos en su scope.
- ``generate_scan_alerts``: crea alertas en el mismo flujo de POST /api/scans.
- ``scheduler``: job periodico in-process (APScheduler) que corre los dos
  primeros. Sin infraestructura externa.
"""

from __future__ import annotations

import logging
from datetime import date, datetime, timezone

from sqlalchemy.orm import Session

from .api.config import settings
from .api.db import SessionLocal
from .api.models import (
    Agent,
    Alert,
    AlertThreshold,
    Certificate,
    ComplianceWindow,
    Finding,
    Organization,
)
from .api.tenancy import set_system_session, set_tenant_session, get_session_org_id


def _get_default_org_id(db: Session):
    org_id = get_session_org_id(db)
    if org_id is None:
        raise RuntimeError("Alert generation requires an explicit tenant session")
    return int(org_id)

logger = logging.getLogger(__name__)

_DEFAULT_THRESHOLD = {"days_before_expiry": [30, 15, 7], "critical_days": 7, "warning_days": 30}


def _get_threshold(db: Session) -> AlertThreshold:
    threshold = db.query(AlertThreshold).first()
    if threshold is None:
        org_id = _get_default_org_id(db)
        threshold = AlertThreshold(
            days_before_expiry=_DEFAULT_THRESHOLD["days_before_expiry"],
            critical_days=_DEFAULT_THRESHOLD["critical_days"],
            warning_days=_DEFAULT_THRESHOLD["warning_days"],
        )
        db.add(threshold)
        db.commit()
        db.refresh(threshold)
    return threshold


def _alert(
    type_: str,
    severity: str,
    title: str,
    description: str,
    *,
    related_target: str | None = None,
    related_certificate_id: str | None = None,
    related_scan_id: str | None = None,
    action_label: str | None = None,
    action_href: str | None = None,
    organization_id: int | None = None,
) -> Alert:
    return Alert(
        type=type_,
        severity=severity,
        title=title,
        description=description,
        status="unread",
        related_target=related_target,
        related_certificate_id=related_certificate_id,
        related_scan_id=related_scan_id,
        action_label=action_label,
        action_href=action_href,
        organization_id=organization_id,
    )


def generate_expiration_alerts(db: Session) -> int:
    """Genera/actualiza alertas de vencimiento. Devuelve cantidad creada."""
    threshold = _get_threshold(db)
    days_list = sorted(set(threshold.days_before_expiry or [30, 15, 7]))
    created = 0
    for cert in db.query(Certificate).all():
        if cert.is_expired:
            title = f"Certificate expired ({cert.domain or cert.subject_cn})"
            severity = "critical"
            description = (
                f"Certificate for {cert.domain or cert.subject_cn} expired on {cert.not_after}. "
                "Renew and re-deploy as soon as possible."
            )
            action = ("View Certificate", f"/certificates/{cert.id}")
        else:
            days = cert.days_until_expiry
            matched = next((d for d in days_list if days <= d), None)
            if matched is None:
                continue
            severity = (
                "critical" if days <= threshold.critical_days
                else "high" if days <= threshold.warning_days
                else "medium"
            )
            title = f"Certificate expires in {days} days ({cert.domain or cert.subject_cn})"
            description = (
                f"Certificate for {cert.domain or cert.subject_cn} expires in {days} days "
                f"({cert.not_after}). Renew before expiration."
            )
            action = ("Renew / View Certificate", f"/certificates/{cert.id}")

        existing = (
            db.query(Alert)
            .filter(
                Alert.type == "expiration",
                Alert.related_certificate_id == cert.id,
                Alert.status.in_(["unread", "read"]),
            )
            .first()
        )
        if existing:
            existing.severity = severity
            existing.title = title
            existing.description = description
        else:
            db.add(_alert(
                "expiration", severity, title, description,
                related_target=cert.domain or cert.subject_cn,
                related_certificate_id=cert.id,
                action_label=action[0], action_href=action[1],
            ))
            created += 1
    db.commit()
    return created


def generate_compliance_alerts(db: Session) -> int:
    """Genera alertas de compliance para ventanas de auditoria proximas."""
    threshold = _get_threshold(db)
    if not threshold.notify_on_compliance:
        return 0
    created = 0
    today = date.today()
    for window in db.query(ComplianceWindow).all():
        try:
            audit = date.fromisoformat(window.audit_date)
        except ValueError:
            continue
        days = (audit - today).days
        if days < 0 or days > 30:
            continue
        q = db.query(Finding).filter(
            Finding.severity.in_(["critical", "high"]),
            Finding.evaluable.is_(True),
        )
        if window.scope_filter:
            q = q.filter(Finding.affected_host.in_(window.scope_filter))
        count = q.count()
        if count == 0:
            continue
        title = f"{window.framework} audit in {days} days ({window.name})"
        description = (
            f"Audit {window.framework} scheduled in {days} days: {count} open "
            f"critical/high finding(s) within scope of {window.name}."
        )
        existing = (
            db.query(Alert)
            .filter(
                Alert.type == "compliance",
                Alert.title.like(f"%{window.name}%"),
                Alert.status.in_(["unread", "read"]),
            )
            .first()
        )
        if existing:
            existing.title = title
            existing.description = description
            existing.severity = "info"
        else:
            try:
                db.add(_alert("compliance", "info", title, description, action_label="View Vulnerabilities", action_href="/vulnerabilities"))
            except Exception:
                pass
            created += 1
    try:
        db.commit()
    except Exception:
        db.rollback()
    return created


def generate_agent_offline_alerts(db: Session) -> int:
    """Alerta ``agent_offline`` por cada agente activo sin reportar.

    Se genera una sola vez y se resuelve sola cuando el agente vuelve a
    reportar (heartbeat o ingesta). Parte 5.7.
    """
    now = datetime.now(timezone.utc)
    window = settings.agent_offline_seconds
    created = 0
    for agent in db.query(Agent).filter(Agent.status == "active").all():
        last = agent.last_seen_at
        if last is not None and last.tzinfo is None:
            last = last.replace(tzinfo=timezone.utc)
        offline = last is None or (now - last).total_seconds() > window
        existing = (
            db.query(Alert)
            .filter(
                Alert.type == "agent_offline",
                Alert.related_target == agent.id,
                Alert.status.in_(["unread", "read"]),
            )
            .first()
        )
        if offline and existing is None:
            seen = last.isoformat() if last else "never"
            db.add(_alert(
                "agent_offline",
                "high",
                f"Agent offline: {agent.name}",
                f"Agent '{agent.name}' ({agent.site_label or 'sin sitio'}) has not "
                f"reported since {seen}. Check the agent process and egress.",
                related_target=agent.id,
                action_label="View Agents",
                action_href=f"/agents/{agent.id}",
                organization_id=agent.organization_id,
            ))
            created += 1
        elif not offline and existing is not None:
            existing.status = "resolved"
    try:
        db.commit()
    except Exception:
        db.rollback()
    return created


def generate_scan_alerts(db: Session, scan_row: object, findings: list[dict]) -> int:
    """Crea alertas de vulnerabilidad para findings CRITICAL/HIGH de un scan."""
    created = 0
    for f in findings:
        if f.get("severity") not in ("critical", "high") or not f.get("evaluable", True):
            continue
        db.add(_alert(
            "vulnerability",
            f.get("severity", "high"),
            f"{f.get('severity', 'high').title()} finding: {f.get('title', '')}",
            f"{f.get('description', '')}\nAffected host: {f.get('affectedHost', scan_row.host)}",
            related_target=scan_row.host,
            related_scan_id=scan_row.id,
            action_label="View Analysis",
            action_href=f"/scanner/{scan_row.id}",
        ))
        created += 1
    db.commit()
    return created


def run_scheduled_alerts() -> None:
    """Ronda periodica de alertas (vencimiento + compliance)."""
    system_db = SessionLocal()
    try:
        set_system_session(system_db)
        organizations = (
            system_db.query(Organization.id)
            .filter(Organization.status == "active")
            .order_by(Organization.id)
            .all()
        )
        organization_ids = [row[0] for row in organizations]
    except Exception as exc:  # pragma: no cover - nunca debe tumbar la app
        logger.exception("Could not enumerate organizations for alert round: %s", exc)
        return
    finally:
        system_db.close()

    for organization_id in organization_ids:
        db = SessionLocal()
        try:
            set_tenant_session(db, organization_id)
            n1 = generate_expiration_alerts(db)
            n2 = generate_compliance_alerts(db)
            n3 = generate_agent_offline_alerts(db)
            logger.info(
                "Alerts round org=%s: %d expiration, %d compliance, %d agent offline",
                organization_id, n1, n2, n3,
            )
        except Exception as exc:  # pragma: no cover - isolate a failing tenant
            db.rollback()
            logger.exception(
                "Scheduled alerts round failed for organization %s: %s",
                organization_id, exc,
            )
        finally:
            db.close()


class AlertScheduler:
    """Scheduler in-process basado en APScheduler (BackgroundScheduler)."""

    def __init__(self) -> None:
        self._scheduler = None
        self._job = None

    @property
    def running(self) -> bool:
        return self._scheduler is not None and self._scheduler.running

    def start(self) -> None:
        if self.running or not (settings.alerts_enabled or settings.recurring_scans_enabled):
            return
        try:
            from apscheduler.schedulers.background import BackgroundScheduler
            from apscheduler.triggers.interval import IntervalTrigger
        except ImportError:  # pragma: no cover - dependencia opcional
            logger.warning("APScheduler no instalado; tareas periodicas desactivadas")
            return
        from .api.services.recurring_scan_service import run_scheduled_scans_tick

        self._scheduler = BackgroundScheduler()
        if settings.alerts_enabled:
            self._scheduler.add_job(run_scheduled_alerts, IntervalTrigger(minutes=settings.alerts_interval_minutes))
            self._scheduler.add_job(run_scheduled_alerts, "date")
        if settings.recurring_scans_enabled:
            self._scheduler.add_job(
                run_scheduled_scans_tick,
                IntervalTrigger(minutes=settings.scan_tick_interval_minutes),
            )
        self._scheduler.start()
        logger.info("Scheduler started (alerts enabled: %s, recurring scans enabled: %s)",
                    settings.alerts_enabled, settings.recurring_scans_enabled)

    def shutdown(self) -> None:
        if self._scheduler and self._scheduler.running:
            self._scheduler.shutdown(wait=False)
            self._scheduler = None


scheduler = AlertScheduler()
