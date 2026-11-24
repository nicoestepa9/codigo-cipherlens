"""Servicio de alertas y settings de umbrales."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.orm import Session

from ..models import Alert, AlertThreshold


def _alert_to_dto(a: Alert) -> dict:
    return {
        "id": a.id,
        "severity": a.severity,
        "type": a.type,
        "title": a.title,
        "description": a.description,
        "createdAt": a.created_at.isoformat() if a.created_at else "",
        "status": a.status,
        "relatedTarget": a.related_target,
        "relatedCertificateId": a.related_certificate_id,
        "relatedScanId": a.related_scan_id,
        "actionLabel": a.action_label,
        "actionHref": a.action_href,
    }


def list_alerts(
    db: Session,
    type_: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
) -> list[dict]:
    q = db.query(Alert)
    if type_ and type_ != "all":
        q = q.filter(Alert.type == type_)
    if severity and severity != "all":
        q = q.filter(Alert.severity == severity)
    if status and status != "all":
        q = q.filter(Alert.status == status)
    rows = q.order_by(Alert.created_at.desc()).all()
    return [_alert_to_dto(a) for a in rows]


def set_alert_status(db: Session, alert_id: str, status: str) -> Optional[dict]:
    alert = db.get(Alert, alert_id)
    if alert is None:
        return None
    alert.status = status
    if status == "resolved":
        alert.resolved_at = datetime.now(timezone.utc)
    db.commit()
    return _alert_to_dto(alert)


def unread_count(db: Session) -> int:
    return db.query(Alert).filter(Alert.status == "unread").count()


def _threshold_to_dto(t: AlertThreshold) -> dict:
    return {
        "daysBeforeExpiry": list(t.days_before_expiry or [30, 15, 7]),
        "notifyOnCriticalFinding": t.notify_on_critical_finding,
        "notifyOnCompliance": t.notify_on_compliance,
        "criticalDays": t.critical_days,
        "warningDays": t.warning_days,
    }


def resolve_thresholds(
    db: Session,
    organization_id: int | None = None,
    critical_days: int | None = None,
    warning_days: int | None = None,
) -> tuple[int, int]:
    """Resuelve los umbrales efectivos: explicitos, de la organizacion o default."""
    if critical_days is not None and warning_days is not None:
        critical = max(0, int(critical_days))
        warning = max(critical, int(warning_days))
        return critical, warning

    q = db.query(AlertThreshold)
    if organization_id is not None:
        q = q.filter(AlertThreshold.organization_id == organization_id)
    else:
        q = q.filter(AlertThreshold.organization_id.is_(None))
    t = q.first()

    critical = (
        max(0, int(critical_days))
        if critical_days is not None
        else (t.critical_days if t and t.critical_days is not None else 7)
    )
    warning = (
        max(0, int(warning_days))
        if warning_days is not None
        else (t.warning_days if t and t.warning_days is not None else 30)
    )
    return critical, max(critical, warning)


def get_thresholds(db: Session, organization_id: int | None = None) -> dict:
    q = db.query(AlertThreshold)
    if organization_id is not None:
        q = q.filter(AlertThreshold.organization_id == organization_id)
    else:
        q = q.filter(AlertThreshold.organization_id.is_(None))
    t = q.first()
    if t is None:
        t = AlertThreshold(organization_id=organization_id)
        db.add(t)
        db.commit()
        db.refresh(t)
    return _threshold_to_dto(t)


def update_thresholds(db: Session, data: dict, organization_id: int | None = None) -> dict:
    if organization_id is not None:
        t = db.query(AlertThreshold).filter(AlertThreshold.organization_id == organization_id).first()
    else:
        t = db.query(AlertThreshold).first()
    if t is None:
        t = AlertThreshold(organization_id=organization_id)
        db.add(t)
    t.days_before_expiry = data.get("daysBeforeExpiry", t.days_before_expiry or [30, 15, 7])
    t.notify_on_critical_finding = data.get("notifyOnCriticalFinding", t.notify_on_critical_finding)
    t.notify_on_compliance = data.get("notifyOnCompliance", t.notify_on_compliance)
    t.critical_days = data.get("criticalDays", t.critical_days)
    t.warning_days = data.get("warningDays", t.warning_days)
    db.commit()
    db.refresh(t)
    return _threshold_to_dto(t)
