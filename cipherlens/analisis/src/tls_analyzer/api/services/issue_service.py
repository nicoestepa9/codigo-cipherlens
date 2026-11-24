"""Servicio de Issues: reconciliacion, transiciones, SLA y owner efectivo (Parte 2)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy import func
from sqlalchemy.orm import Session

from ..config import settings
from ..models import (
    Agent,
    Alert,
    Finding,
    Issue,
    IssueHistory,
    Organization,
    Service,
    Team,
    User,
)
from ..tenancy import get_session_org_id

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
OPEN_STATUSES = {"open", "assigned", "in_progress"}
RESOLVED_LIKE = {"resolved", "verified"}
TERMINAL_SUPPRESSED = {"false_positive"}
RISK_ACCEPTED = "risk_accepted"

VALID_STATUSES = {
    "open", "assigned", "in_progress", "resolved", "verified", RISK_ACCEPTED, "false_positive",
    "reopened",
}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def severity_rank(sev: str | None) -> int:
    return SEVERITY_RANK.get((sev or "").lower(), -1)


def min_severity_rank() -> int:
    return severity_rank(settings.issue_min_severity)


def sla_days_for(severity: str, organization: Organization | None = None) -> int:
    s = (severity or "").lower()
    if s == "critical":
        configured = getattr(organization, "sla_days_critical", None)
        return configured if configured is not None else settings.sla_days_critical
    if s == "high":
        configured = getattr(organization, "sla_days_high", None)
        return configured if configured is not None else settings.sla_days_high
    configured = getattr(organization, "sla_days_medium", None)
    return configured if configured is not None else settings.sla_days_medium


def compute_due_at(
    first_seen: datetime,
    severity: str,
    organization: Organization | None = None,
) -> datetime:
    return _as_utc(first_seen) + timedelta(
        days=sla_days_for(severity, organization)
    )


def effective_owner(issue: Issue, service: Service | None = None) -> tuple[Optional[str], Optional[str]]:
    """Owner efectivo: el del issue; si es nulo, el default del Service (D9)."""
    uid = issue.owner_user_id
    tid = issue.owner_team_id
    if uid is None and tid is None and service is not None:
        uid = service.default_owner_user_id
        tid = service.default_owner_team_id
    return uid, tid


def is_overdue(issue: Issue, now: datetime | None = None) -> bool:
    now = now or _utcnow()
    if issue.status not in OPEN_STATUSES:
        return False
    due = _as_utc(issue.due_at)
    return due is not None and now > due


def default_org_id(db: Session) -> int | None:
    session_org_id = get_session_org_id(db)
    if session_org_id is not None:
        return int(session_org_id)
    org = db.query(Organization).order_by(Organization.id).first()
    if org is None:
        try:
            org = Organization(name="Default Org", slug="default", status="active")
            db.add(org)
            db.flush()
        except Exception:
            return None
    if getattr(org, "slug", None) in (None, ""):
        try:
            org.slug = "default" if org.id == 1 else f"org-{org.id}"
        except Exception:
            pass
    return org.id if org else None


def _history(
    db: Session,
    issue_id: str,
    event_type: str,
    *,
    actor_user_id: str | None = None,
    actor_type: str = "system",
    from_value: str | None = None,
    to_value: str | None = None,
    comment: str | None = None,
    scan_id: str | None = None,
) -> None:
    db.add(
        IssueHistory(
            issue_id=issue_id,
            actor_user_id=actor_user_id,
            actor_type=actor_type,
            event_type=event_type,
            from_value=from_value,
            to_value=to_value,
            comment=comment,
            scan_id=scan_id,
        )
    )


def _status_for_new(service: Service | None) -> str:
    if service is not None and (
        service.default_owner_user_id or service.default_owner_team_id
    ):
        return "assigned"
    return "open"


def find_issue(db: Session, service_id: str, source_document: str, rule_id: str) -> Issue | None:
    return (
        db.query(Issue)
        .filter(
            Issue.service_id == service_id,
            Issue.source_document == source_document,
            Issue.rule_id == rule_id,
        )
        .first()
    )


def reconcile_scan(
    db: Session,
    scan_row,
    findings_dtos: list[dict],
    *,
    certificate_fingerprint: str | None = None,
) -> None:
    """Reconcilia Issues con los findings de un scan COMPLETADO.

    No se invoca para scans fallidos / connection_error.
    """
    service = db.get(Service, scan_row.service_id) if scan_row.service_id else None
    org_id = default_org_id(db)
    organization = db.get(Organization, org_id) if org_id else None
    now = _utcnow()
    min_rank = min_severity_rank()

    eligible: list[dict] = []
    for dto in findings_dtos:
        if not dto.get("evaluable", True):
            continue
        if severity_rank(dto.get("severity")) < min_rank:
            continue
        eligible.append(dto)

    seen_keys: set[tuple[str, str]] = set()
    finding_rows = (
        db.query(Finding).filter(Finding.scan_id == scan_row.id).all()
    )
    row_by_key: dict[tuple[str, str], Finding] = {
        (f.source_document or "", f.rule_id): f for f in finding_rows
    }

    for dto in eligible:
        source_document = dto.get("sourceDocument") or ""
        rule_id = dto.get("ruleId") or ""
        key = (source_document, rule_id)
        seen_keys.add(key)

        issue = find_issue(db, scan_row.service_id, source_document, rule_id)
        finding_row = row_by_key.get(key)

        if issue is None:
            severity = (dto.get("severity") or "medium").lower()
            issue = Issue(
                organization_id=org_id,
                service_id=scan_row.service_id,
                source_document=source_document,
                rule_id=rule_id,
                title=dto.get("title") or rule_id,
                severity=severity,
                status=_status_for_new(service),
                first_seen_at=now,
                last_seen_at=now,
                last_scan_id=scan_row.id,
                last_certificate_fingerprint=certificate_fingerprint,
            )
            issue.due_at = compute_due_at(now, severity, organization)
            db.add(issue)
            db.flush()
            _history(
                db, issue.id, "created", actor_type="system", scan_id=scan_row.id,
                to_value=issue.status,
            )
        else:
            _reconcile_present(
                db, issue, dto, scan_row, now, service,
                certificate_fingerprint, organization,
            )

        if finding_row is not None:
            finding_row.issue_id = issue.id

    # Issues abiertos que no aparecieron en este scan -> auto-resolved
    open_issues = (
        db.query(Issue)
        .filter(
            Issue.service_id == scan_row.service_id,
            Issue.status.in_(list(OPEN_STATUSES)),
        )
        .all()
    )
    for issue in open_issues:
        key = (issue.source_document or "", issue.rule_id)
        if key in seen_keys:
            continue
        issue.status = "resolved"
        issue.resolved_at = now
        issue.resolved_by = "system"
        issue.clean_scans_since_resolved = 1
        issue.last_scan_id = scan_row.id
        _history(
            db, issue.id, "auto_resolved", actor_type="system", scan_id=scan_row.id,
            from_value="open", to_value="resolved",
        )

    # Resolved ausentes: incrementar limpios; al llegar al umbral -> verified
    verify_after = max(1, settings.issue_verify_after_clean_scans)
    resolved_issues = (
        db.query(Issue)
        .filter(
            Issue.service_id == scan_row.service_id,
            Issue.status == "resolved",
        )
        .all()
    )
    for issue in resolved_issues:
        key = (issue.source_document or "", issue.rule_id)
        if key in seen_keys:
            continue
        issue.clean_scans_since_resolved = (issue.clean_scans_since_resolved or 0) + 1
        issue.last_scan_id = scan_row.id
        if issue.clean_scans_since_resolved >= verify_after:
            issue.status = "verified"
            issue.verified_at = now
            _history(
                db, issue.id, "auto_verified", actor_type="system", scan_id=scan_row.id,
                from_value="resolved", to_value="verified",
            )

    raise_overdue_alerts(db, open_issues)
    db.flush()


def _reconcile_present(
    db: Session,
    issue: Issue,
    dto: dict,
    scan_row,
    now: datetime,
    service: Service | None,
    certificate_fingerprint: str | None,
    organization: Organization | None,
) -> None:
    """Actualiza un issue existente que SI aparece en este scan."""
    issue.last_seen_at = now
    issue.last_scan_id = scan_row.id
    if dto.get("title"):
        issue.title = dto["title"]
    if certificate_fingerprint:
        issue.last_certificate_fingerprint = certificate_fingerprint

    # Severidad
    new_sev = (dto.get("severity") or issue.severity or "medium").lower()
    old_sev = (issue.severity or "").lower()
    if new_sev != old_sev:
        issue.severity = new_sev
        _history(
            db, issue.id, "severity_changed", actor_type="system", scan_id=scan_row.id,
            from_value=old_sev, to_value=new_sev,
        )
        if severity_rank(new_sev) > severity_rank(old_sev):
            issue.due_at = compute_due_at(now, new_sev, organization)
            _history(
                db, issue.id, "sla_changed", actor_type="system", scan_id=scan_row.id,
                from_value=old_sev, to_value=new_sev,
            )

    status = issue.status
    if status in ("resolved", "verified"):
        prev = status
        issue.status = "assigned" if (
            issue.owner_user_id or issue.owner_team_id
            or (service and (service.default_owner_user_id or service.default_owner_team_id))
        ) else "open"
        issue.reopened_count = (issue.reopened_count or 0) + 1
        issue.clean_scans_since_resolved = 0
        issue.resolved_at = None
        issue.resolved_by = None
        issue.verified_at = None
        _history(
            db, issue.id, "reopened", actor_type="system", scan_id=scan_row.id,
            from_value=prev, to_value=issue.status,
        )
    elif status == RISK_ACCEPTED:
        until = _as_utc(issue.risk_accepted_until)
        if until is not None and now > until:
            issue.status = "assigned" if (
                issue.owner_user_id or issue.owner_team_id
                or (service and (service.default_owner_user_id or service.default_owner_team_id))
            ) else "open"
            issue.risk_accepted_until = None
            _history(
                db, issue.id, "risk_acceptance_expired", actor_type="system",
                scan_id=scan_row.id, from_value=RISK_ACCEPTED, to_value=issue.status,
            )
    # open/assigned/in_progress/false_positive: sin cambio de estado


def remove_owner_from_issues(db: Session, user_id: str, *, actor_user_id: str | None = None) -> list[Issue]:
    """Cuando se borra un usuario, sus issues quedan sin owner (Parte 1.8 / 2)."""
    issues = db.query(Issue).filter(Issue.owner_user_id == user_id).all()
    for issue in issues:
        issue.owner_user_id = None
        if issue.status == "assigned":
            issue.status = "open"
        _history(
            db, issue.id, "owner_removed", actor_user_id=actor_user_id,
            actor_type="user", from_value=user_id, to_value=None,
        )
    db.flush()
    return issues


def _owner_name(db: Session, user_id: str | None, team_id: str | None) -> str | None:
    if user_id:
        u = db.get(User, user_id)
        if u is not None:
            return u.name or u.email
    if team_id:
        t = db.get(Team, team_id)
        if t is not None:
            return t.name
    return None


def to_out(db: Session, issue: Issue, *, with_history: bool = False) -> dict:
    service = db.get(Service, issue.service_id) if issue.service_id else None
    agent = (
        db.get(Agent, service.agent_id)
        if service is not None and service.agent_id
        else None
    )
    eff_user, eff_team = effective_owner(issue, service)
    now = _utcnow()
    data = {
        "id": issue.id,
        "serviceId": issue.service_id,
        "serviceHost": service.host if service else None,
        "servicePort": service.port if service else None,
        "agentId": service.agent_id if service else None,
        "siteLabel": agent.site_label if agent else None,
        "sourceDocument": issue.source_document,
        "ruleId": issue.rule_id,
        "title": issue.title,
        "severity": issue.severity,
        "status": issue.status,
        "ownerUserId": issue.owner_user_id,
        "ownerTeamId": issue.owner_team_id,
        "effectiveOwnerUserId": eff_user,
        "effectiveOwnerTeamId": eff_team,
        "ownerName": _owner_name(db, eff_user, eff_team),
        "firstSeenAt": _as_utc(issue.first_seen_at).isoformat() if issue.first_seen_at else None,
        "lastSeenAt": _as_utc(issue.last_seen_at).isoformat() if issue.last_seen_at else None,
        "dueAt": _as_utc(issue.due_at).isoformat() if issue.due_at else None,
        "isOverdue": is_overdue(issue, now),
        "resolvedAt": _as_utc(issue.resolved_at).isoformat() if issue.resolved_at else None,
        "resolvedBy": issue.resolved_by,
        "verifiedAt": _as_utc(issue.verified_at).isoformat() if issue.verified_at else None,
        "cleanScansSinceResolved": issue.clean_scans_since_resolved or 0,
        "riskAcceptedBy": issue.risk_accepted_by,
        "riskAcceptanceReason": issue.risk_acceptance_reason,
        "riskAcceptedUntil": _as_utc(issue.risk_accepted_until).isoformat() if issue.risk_accepted_until else None,
        "reopenedCount": issue.reopened_count or 0,
        "lastCertificateFingerprint": issue.last_certificate_fingerprint,
    }
    if with_history:
        data["history"] = [
            {
                "id": h.id,
                "ts": _as_utc(h.ts).isoformat() if h.ts else None,
                "actorUserId": h.actor_user_id,
                "actorType": h.actor_type,
                "eventType": h.event_type,
                "fromValue": h.from_value,
                "toValue": h.to_value,
                "comment": h.comment,
                "scanId": h.scan_id,
            }
            for h in sorted(issue.history, key=lambda x: _as_utc(x.ts))
        ]
    return data


def _set_owner(db: Session, issue: Issue, user_id: str | None, team_id: str | None, actor_user_id: str | None) -> None:
    old_user, old_team = issue.owner_user_id, issue.owner_team_id
    issue.owner_user_id = user_id
    issue.owner_team_id = team_id
    if old_user != user_id or old_team != team_id:
        _history(
            db, issue.id, "owner_changed", actor_user_id=actor_user_id, actor_type="user",
            from_value=f"{old_user or ''}/{old_team or ''}",
            to_value=f"{user_id or ''}/{team_id or ''}",
        )
    if user_id or team_id:
        if issue.status == "open":
            issue.status = "assigned"
            _history(db, issue.id, "status_changed", actor_user_id=actor_user_id, actor_type="user", from_value="open", to_value="assigned")


def assign(db: Session, issue: Issue, *, owner_user_id: str | None, owner_team_id: str | None, actor_user_id: str | None) -> Issue:
    _set_owner(db, issue, owner_user_id, owner_team_id, actor_user_id)
    db.flush()
    return issue


def change_status(
    db: Session,
    issue: Issue,
    new_status: str,
    *,
    actor_user_id: str | None,
    comment: str | None = None,
    reason: str | None = None,
    risk_accepted_until: str | None = None,
) -> Issue:
    if new_status not in VALID_STATUSES:
        raise ValueError(f"Estado invalido: {new_status}")
    old = issue.status
    if old == new_status:
        return issue
    if old == "verified" and new_status != "reopened":
        raise ValueError("Un issue verificado solo puede reabrirse")
    if old == "false_positive":
        raise ValueError("Un issue marcado como falso positivo es terminal")
    now = _utcnow()

    if new_status == "resolved":
        issue.status = "resolved"
        issue.resolved_at = now
        issue.resolved_by = "user"
        issue.clean_scans_since_resolved = 0
    elif new_status == "verified":
        if old not in ("resolved", "verified"):
            raise ValueError("Solo un issue resuelto puede verificarse")
        issue.status = "verified"
        issue.verified_at = now
    elif new_status == RISK_ACCEPTED:
        issue.status = RISK_ACCEPTED
        issue.risk_accepted_by = actor_user_id
        issue.risk_acceptance_reason = reason
        if risk_accepted_until:
            from datetime import datetime as _dt

            try:
                issue.risk_accepted_until = _as_utc(_dt.fromisoformat(risk_accepted_until))
            except ValueError:
                issue.risk_accepted_until = None
    elif new_status == "false_positive":
        issue.status = "false_positive"
    elif new_status == "reopened":
        if old not in RESOLVED_LIKE:
            raise ValueError("Solo un issue resuelto/verificado puede reabrirse")
        issue.status = "assigned" if issue.owner_user_id or issue.owner_team_id else "open"
        issue.reopened_count = (issue.reopened_count or 0) + 1
        issue.clean_scans_since_resolved = 0
        issue.resolved_at = None
        issue.resolved_by = None
        issue.verified_at = None
        _history(
            db, issue.id, "reopened", actor_user_id=actor_user_id, actor_type="user",
            from_value=old, to_value=issue.status, comment=comment,
        )
        db.flush()
        return issue
    elif new_status in OPEN_STATUSES:
        issue.status = new_status
    else:
        raise ValueError(f"Transicion no soportada: {old} -> {new_status}")

    _history(
        db, issue.id, "status_changed", actor_user_id=actor_user_id, actor_type="user",
        from_value=old, to_value=new_status, comment=comment,
    )
    if new_status == RISK_ACCEPTED and reason:
        _history(db, issue.id, "risk_accepted", actor_user_id=actor_user_id, actor_type="user", comment=reason)
    db.flush()
    return issue


def add_comment(db: Session, issue: Issue, comment: str, *, actor_user_id: str | None) -> None:
    _history(db, issue.id, "comment", actor_user_id=actor_user_id, actor_type="user", comment=comment)
    db.flush()


# ---------------------------------------------------------------------------
# Alertas (dedup por related_issue_id)
# ---------------------------------------------------------------------------

def _upsert_issue_alert(
    db: Session,
    type_: str,
    severity: str,
    issue: Issue,
    title: str,
    description: str,
    *,
    action_href: str | None = None,
) -> None:
    existing = (
        db.query(Alert)
        .filter(
            Alert.type == type_,
            Alert.related_issue_id == issue.id,
            Alert.status.in_(["unread", "read"]),
        )
        .first()
    )
    if existing:
        existing.severity = severity
        existing.title = title
        existing.description = description
        return
    db.add(
        Alert(
            type=type_,
            severity=severity,
            title=title,
            description=description,
            status="unread",
            related_issue_id=issue.id,
            action_label="Ver issue",
            action_href=action_href or f"/issues/{issue.id}",
        )
    )


def raise_overdue_alerts(db: Session, issues: list[Issue] | None = None) -> int:
    """Crea/actualiza alertas issue_overdue para issues abiertos vencidos."""
    now = _utcnow()
    if issues is None:
        issues = db.query(Issue).filter(Issue.status.in_(list(OPEN_STATUSES))).all()
    created = 0
    for issue in issues:
        if not is_overdue(issue, now):
            continue
        before = (
            db.query(Alert)
            .filter(
                Alert.type == "issue_overdue",
                Alert.related_issue_id == issue.id,
                Alert.status.in_(["unread", "read"]),
            )
            .count()
        )
        _upsert_issue_alert(
            db,
            "issue_overdue",
            issue.severity if issue.severity in ("critical", "high", "medium") else "high",
            issue,
            f"Issue vencido: {issue.title}",
            f"El issue ({issue.severity}) del servicio {issue.service_id} supero su SLA "
            f"({_as_utc(issue.due_at).isoformat() if issue.due_at else 'n/d'}).",
        )
        if before == 0:
            created += 1
    db.flush()
    return created


def raise_owner_removed_alerts(db: Session, issues: list[Issue], *, actor_user_id: str | None = None) -> int:
    """Alerta issue_owner_removed por cada issue que quedo sin owner."""
    created = 0
    for issue in issues:
        before = (
            db.query(Alert)
            .filter(
                Alert.type == "issue_owner_removed",
                Alert.related_issue_id == issue.id,
                Alert.status.in_(["unread", "read"]),
            )
            .count()
        )
        _upsert_issue_alert(
            db,
            "issue_owner_removed",
            "medium",
            issue,
            f"Issue sin responsable: {issue.title}",
            f"El responsable del issue ({issue.severity}) fue eliminado. "
            "Asigna un nuevo owner.",
        )
        if before == 0:
            created += 1
    db.flush()
    return created
