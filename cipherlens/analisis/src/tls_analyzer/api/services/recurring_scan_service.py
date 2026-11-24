"""Logica de scans recurrentes: CRUD, tick scheduler, comparacion entre corridas y alertas.

Replica el patron de ``AlertScheduler`` de ``alerts_engine.py``: un solo proceso,
APScheduler in-process, sin infraestructura externa. ``run_scan()`` ya esta desacoplado
de HTTP, por lo que se invoca directamente desde el tick.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy.orm import Session

from ..config import settings
from ..db import SessionLocal
from ..models import AuditLog, Organization, RecurringScan, Scan
from ...cloud_network import (
    NonPublicTargetError,
    PinnedTarget,
    parse_scan_target,
    resolve_target_addresses,
)
from ..tenancy import (
    SYSTEM_TENANT_MODE,
    get_session_org_id,
    set_system_session,
    set_tenant_session,
)
from ... import serializers
from ..schemas import RecurringScanCreate, RecurringScanPatch
from ...alerts_engine import _alert  # reusa el constructor de alertas existente
from . import scan_service

logger = logging.getLogger(__name__)
_scheduled_scan_slots = threading.BoundedSemaphore(
    max(1, settings.max_concurrent_scans)
)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# --------------------------------------------------------------------------
# CRUD
# --------------------------------------------------------------------------

def create_recurring_scan(db: Session, payload: RecurringScanCreate) -> RecurringScan:
    profile = payload.profile or "citizen-facing"
    if profile not in ("citizen-facing", "government-only"):
        profile = "citizen-facing"
    agent_id = payload.agentId
    if agent_id:
        from ..models import Agent

        agent = db.get(Agent, agent_id)
        if agent is None or agent.status != "active":
            raise LookupError("Agent not found")
    row = RecurringScan(
        host=payload.host,
        port=payload.port,
        alternate_ports=payload.alternatePorts if payload.alternatePorts else None,
        profile=profile,
        interval_hours=payload.intervalHours if payload.intervalHours > 0 else 24.0,
        enabled=payload.enabled,
        agent_id=agent_id,
        next_run_at=_utcnow(),
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def list_recurring_scans(db: Session, enabled: Optional[bool] = None) -> list[RecurringScan]:
    q = db.query(RecurringScan)
    if enabled is not None:
        q = q.filter(RecurringScan.enabled == enabled)
    return q.order_by(RecurringScan.host).all()


def get_recurring_scan(db: Session, scan_id: int) -> Optional[RecurringScan]:
    return db.get(RecurringScan, scan_id)


def update_recurring_scan(db: Session, row: RecurringScan, payload: RecurringScanPatch) -> RecurringScan:
    data = payload.model_dump(exclude_unset=True)
    if "host" in data and data["host"]:
        row.host = data["host"]
    if "port" in data and data["port"]:
        row.port = data["port"]
    if "alternatePorts" in data:
        row.alternate_ports = data["alternatePorts"] or None
    if "profile" in data and data["profile"] in ("citizen-facing", "government-only"):
        row.profile = data["profile"]
    if "intervalHours" in data and data["intervalHours"] > 0:
        row.interval_hours = data["intervalHours"]
    if "enabled" in data:
        row.enabled = data["enabled"] is True
    if "agentId" in data:
        agent_id = data["agentId"]
        if agent_id:
            from ..models import Agent

            agent = db.get(Agent, agent_id)
            if agent is None or agent.status != "active":
                raise LookupError("Agent not found")
        row.agent_id = agent_id
    db.commit()
    db.refresh(row)
    return row


def delete_recurring_scan(db: Session, row: RecurringScan) -> None:
    # SET NULL manual (SQLite no valida ondelete en columnas existentes)
    db.query(Scan).filter(Scan.recurring_scan_id == row.id).update(
        {Scan.recurring_scan_id: None}
    )
    db.delete(row)
    db.commit()


def recent_scans(db: Session, recurring_scan_id: int, limit: int = 20) -> list[dict]:
    rows = (
        db.query(Scan)
        .filter(Scan.recurring_scan_id == recurring_scan_id)
        .order_by(Scan.started_at.desc())
        .limit(limit)
        .all()
    )
    return [serializers.history_entry_dto(r) for r in rows]


def list_recurring_scan_runs(
    db: Session, recurring_scan_id: int, page: int = 1, page_size: int = 20
) -> tuple[list[dict], int]:
    """Corridas de un schedule paginadas (todas, sin limite fijo). (rows, total)."""
    base = db.query(Scan).filter(Scan.recurring_scan_id == recurring_scan_id)
    total = base.count()
    rows = (
        base.order_by(Scan.started_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    return [serializers.history_entry_dto(r) for r in rows], total


def _utc_isoformat(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def to_dto(row: RecurringScan) -> dict:
    return {
        "id": row.id,
        "host": row.host,
        "port": row.port,
        "alternatePorts": row.alternate_ports or [],
        "profile": row.profile,
        "intervalHours": row.interval_hours,
        "enabled": row.enabled,
        "isRunning": row.is_running,
        "consecutiveFailures": row.consecutive_failures,
        "lastRunAt": _utc_isoformat(row.last_run_at) if row.last_run_at else None,
        "nextRunAt": _utc_isoformat(row.next_run_at) if row.next_run_at else "",
        "serviceId": row.service_id,
        "agentId": row.agent_id,
    }


# --------------------------------------------------------------------------
# Comparacion entre corridas
# --------------------------------------------------------------------------

@dataclass
class ScanComparison:
    score_delta: int = 0
    new_critical_or_high_rule_ids: list[str] = field(default_factory=list)
    resolved_rule_ids: list[str] = field(default_factory=list)
    certificate_expiry_crossed_threshold: bool = False
    has_previous: bool = False


def _rule_ids_by_severity(scan_row: Scan, severities: set[str]) -> set[str]:
    return {
        f.rule_id
        for f in scan_row.findings
        if f.severity in severities and f.evaluable
    }


def compute_scan_comparison(db: Session, scan_row: Scan) -> ScanComparison:
    cmp = ScanComparison()
    if scan_row.status != "completed" or scan_row.score is None:
        return cmp

    q = db.query(Scan).filter(Scan.id != scan_row.id, Scan.status == "completed")
    if scan_row.service_id:
        q = q.filter(Scan.service_id == scan_row.service_id)
    else:
        q = q.filter(Scan.host == scan_row.host, Scan.port == scan_row.port)
    prev = q.order_by(Scan.started_at.desc()).first()
    if prev is None:
        return cmp

    cmp.has_previous = True
    cmp.score_delta = (scan_row.score or 0) - (prev.score or 0)

    cur_crit_high = _rule_ids_by_severity(scan_row, {"critical", "high"})
    prev_crit_high = _rule_ids_by_severity(prev, {"critical", "high"})
    cmp.new_critical_or_high_rule_ids = sorted(cur_crit_high - prev_crit_high)
    cmp.resolved_rule_ids = sorted(prev_crit_high - cur_crit_high)

    # Certificate expiry threshold crossing
    cur_days = None
    prev_days = None
    if scan_row.raw_result:
        cur_days = (scan_row.raw_result.get("certificate") or {}).get("daysUntilExpiry")
    if prev.raw_result:
        prev_days = (prev.raw_result.get("certificate") or {}).get("daysUntilExpiry")
    if cur_days is not None and prev_days is not None:
        threshold = _get_critical_days(db)
        if cur_days <= threshold < prev_days:
            cmp.certificate_expiry_crossed_threshold = True

    return cmp


def _get_critical_days(db: Session) -> int:
    from ..models import AlertThreshold

    threshold = db.query(AlertThreshold).first()
    if threshold is None:
        return 7
    return threshold.critical_days or 7


# --------------------------------------------------------------------------
# Alertas post-corrida programada
# --------------------------------------------------------------------------

def handle_scheduled_scan_alerts(
    db: Session, schedule: RecurringScan, comparison: ScanComparison
) -> int:
    """Genera alertas de regresion/mejora/expiry segun la comparacion. Devuelve count."""
    created = 0
    target = f"{schedule.host}:{schedule.port}"

    latest_scan_id = (
        db.query(Scan.id)
        .filter(Scan.recurring_scan_id == schedule.id)
        .order_by(Scan.started_at.desc())
        .first()
    )
    action_href = f"/scanner/{latest_scan_id[0]}" if latest_scan_id else None

    if comparison.new_critical_or_high_rule_ids:
        severity = "critical" if _has_critical_rule(db, schedule) else "high"
        title = f"Security regression on {target}"
        desc = (
            f"Target {target} worsened since the last scheduled scan: new finding(s) "
            f"{', '.join(comparison.new_critical_or_high_rule_ids[:3])}"
        )
        db.add(_alert(
            "vulnerability_regression", severity, title, desc,
            related_target=target,
            action_label="View Analysis",
            action_href=action_href,
        ))
        created += 1

    elif comparison.resolved_rule_ids and comparison.score_delta > 0:
        title = f"Security improvement on {target}"
        desc = (
            f"Target {target} improved: resolved {', '.join(comparison.resolved_rule_ids[:5])}"
        )
        db.add(_alert(
            "vulnerability_improvement", "info", title, desc,
            related_target=target,
            action_label="View Analysis",
            action_href=action_href,
        ))
        created += 1

    if comparison.certificate_expiry_crossed_threshold:
        title = f"Certificate expiring soon on {target}"
        desc = f"Target {target}'s certificate crossed the critical expiry threshold."
        db.add(_alert(
            "certificate_expiry_crossed", "high", title, desc,
            related_target=target,
            action_label="View Certificate",
            action_href="/certificates",
        ))
        created += 1

    db.commit()
    return created


def _has_critical_rule(db: Session, schedule: RecurringScan) -> bool:
    """True si alguno de los findings del scan mas reciente del schedule es critical."""
    recent = (
        db.query(Scan)
        .filter(Scan.recurring_scan_id == schedule.id)
        .order_by(Scan.started_at.desc())
        .first()
    )
    if recent is None:
        return False
    return any(f.severity == "critical" and f.evaluable for f in recent.findings)


# --------------------------------------------------------------------------
# Tick (scheduler)
# --------------------------------------------------------------------------

def _execute_scheduled_scan(schedule_id: int, organization_id: int | None = None) -> None:
    """Execute within the process-wide scheduled-scan concurrency budget."""
    with _scheduled_scan_slots:
        _execute_scheduled_scan_with_slot(schedule_id, organization_id)


def _execute_scheduled_scan_with_slot(
    schedule_id: int, organization_id: int | None = None
) -> None:
    if organization_id is None:
        scope_db = SessionLocal()
        try:
            if scope_db.info.get("tenant_mode") == SYSTEM_TENANT_MODE:
                schedule_stub = scope_db.get(RecurringScan, schedule_id)
                if schedule_stub is None:
                    return
                organization_id = schedule_stub.organization_id
            else:
                organization_id = get_session_org_id(scope_db)
        finally:
            scope_db.close()
    db = SessionLocal()
    try:
        set_tenant_session(db, organization_id)
        schedule = db.get(RecurringScan, schedule_id)
        if schedule is None or not schedule.enabled or schedule.is_running:
            return
        if schedule.agent_id:
            from .agent_task_service import enqueue_recurring_task

            now = _utcnow()
            task = enqueue_recurring_task(db, schedule)
            if task is not None:
                schedule.is_running = task.status in {"queued", "claimed", "running"}
                schedule.last_run_at = now
                schedule.next_run_at = now + timedelta(
                    hours=schedule.interval_hours
                )
                db.commit()
            else:
                schedule.last_run_at = now
                schedule.next_run_at = now + timedelta(
                    hours=schedule.interval_hours
                )
                db.commit()
            return
        target = f"{schedule.host}:{schedule.port}"
        try:
            host, port = parse_scan_target(schedule.host, schedule.port)
            addresses = resolve_target_addresses(
                host,
                enforce_public=settings.cloud_scan_block_private,
            )
            pinned_target = PinnedTarget(
                addresses[0],
                enforce_public=settings.cloud_scan_block_private,
            )
        except (NonPublicTargetError, OSError) as exc:
            db.add(AuditLog(
                actor_type="system",
                action="cloud_scan.destination_blocked",
                entity_type="cloud_target",
                entity_id=target[:128],
                meta={
                    "operation": "recurring_scan.execute",
                    "recurring_scan_id": schedule.id,
                    "reason": str(exc),
                },
                organization_id=organization_id,
            ))
            schedule.consecutive_failures += 1
            schedule.last_run_at = _utcnow()
            schedule.next_run_at = schedule.last_run_at + timedelta(
                hours=schedule.interval_hours
            )
            if schedule.consecutive_failures >= settings.scheduled_scan_fail_threshold:
                _emit_failing_alert(db, schedule)
            db.commit()
            logger.warning("Scheduled scan destination rejected for %s: %s", target, exc)
            return

        quota = (
            db.query(AuditLog)
            .filter(
                AuditLog.action.in_(
                    (
                        "cloud_scan.started",
                        "cloud_discovery.started",
                        "cloud_scan.scheduled_started",
                    )
                ),
                AuditLog.ts >= _utcnow() - timedelta(hours=1),
            )
            .count()
        )
        organization = db.get(Organization, organization_id)
        quota_limit = int(
            (organization.max_cloud_scans_per_hour if organization else 0)
            or settings.default_max_cloud_scans_per_hour
        )
        if quota >= quota_limit:
            db.add(AuditLog(
                actor_type="system",
                action="cloud_scan.quota_rejected",
                entity_type="recurring_scan",
                entity_id=str(schedule.id),
                meta={
                    "operation": "recurring_scan.execute",
                    "target": target,
                    "reason": "organization hourly cloud scan quota exceeded",
                    "status": 429,
                },
                organization_id=organization_id,
            ))
            schedule.last_run_at = _utcnow()
            schedule.next_run_at = schedule.last_run_at + timedelta(hours=1)
            db.commit()
            logger.info("Scheduled scan deferred by hourly quota for %s", target)
            return

        db.add(AuditLog(
            actor_type="system",
            action="cloud_scan.scheduled_started",
            entity_type="cloud_target",
            entity_id=target[:128],
            meta={
                "operation": "recurring_scan.execute",
                "recurring_scan_id": schedule.id,
                "authorization_version": "2026-10-v1",
            },
            organization_id=organization_id,
        ))
        schedule.is_running = True
        db.commit()
        try:
            scan_service.run_scan(
                db,
                target=host,
                port=port,
                options={
                    "profile": schedule.profile,
                    "alternatePorts": schedule.alternate_ports or [],
                },
                origin="scheduled",
                recurring_scan_id=schedule.id,
                pinned_target=pinned_target,
            )
            schedule.consecutive_failures = 0
            schedule.service_id = resolve_service_id(db, schedule)
            scan_row = (
                db.query(Scan)
                .filter(Scan.recurring_scan_id == schedule.id)
                .order_by(Scan.started_at.desc())
                .first()
            )
            if scan_row is not None:
                comparison = compute_scan_comparison(db, scan_row)
                handle_scheduled_scan_alerts(db, schedule, comparison)
        except Exception as exc:  # pragma: no cover - fallback resiliente
            schedule.consecutive_failures += 1
            logger.warning("Scheduled scan failed for %s:%s: %s",
                           schedule.host, schedule.port, exc)
            if schedule.consecutive_failures >= settings.scheduled_scan_fail_threshold:
                _emit_failing_alert(db, schedule)
        finally:
            schedule.is_running = False
            schedule.last_run_at = _utcnow()
            schedule.next_run_at = schedule.last_run_at + timedelta(
                hours=schedule.interval_hours
            )
            db.commit()
    finally:
        db.close()


def resolve_service_id(db: Session, schedule: RecurringScan) -> Optional[str]:
    from ..models import Service

    service = (
        db.query(Service)
        .filter(Service.host == schedule.host, Service.port == schedule.port)
        .first()
    )
    return service.id if service else None


def _emit_failing_alert(db: Session, schedule: RecurringScan) -> None:
    target = f"{schedule.host}:{schedule.port}"
    title = f"Scheduled scan failing for {target}"
    desc = (
        f"Target {target} could not be scanned in the last "
        f"{schedule.consecutive_failures} runs. Verify availability."
    )
    db.add(_alert(
        "scheduled_scan_failing", "medium", title, desc,
        related_target=target,
    ))


def _round_robin_schedule_keys(
    organization_ids: list[int],
    due_by_organization: dict[int, list[tuple[int, int]]],
) -> list[tuple[int, int]]:
    """Interleave due schedules so early queue slots span all tenants."""
    keys: list[tuple[int, int]] = []
    positions = {organization_id: 0 for organization_id in organization_ids}
    while True:
        added = False
        for organization_id in organization_ids:
            position = positions[organization_id]
            rows = due_by_organization.get(organization_id, [])
            if position < len(rows):
                keys.append(rows[position])
                positions[organization_id] += 1
                added = True
        if not added:
            return keys


def run_scheduled_scans_tick() -> None:
    """Ronda periodica: ejecuta todos los scans programados due."""
    from .agent_task_service import reap_expired_tasks

    reap_expired_tasks()
    system_db = SessionLocal()
    try:
        set_system_session(system_db)
        organization_ids = [
            row[0]
            for row in system_db.query(Organization.id)
            .filter(Organization.status == "active")
            .order_by(Organization.id)
            .all()
        ]
    finally:
        system_db.close()

    due_by_organization: dict[int, list[tuple[int, int]]] = {}
    for organization_id in organization_ids:
        db = SessionLocal()
        try:
            set_tenant_session(db, organization_id)
            due_by_organization[organization_id] = [
                (organization_id, row.id)
                for row in db.query(RecurringScan)
                .filter(
                    RecurringScan.enabled.is_(True),
                    RecurringScan.is_running.is_(False),
                    RecurringScan.next_run_at <= _utcnow(),
                )
                .order_by(RecurringScan.next_run_at, RecurringScan.id)
                .all()
            ]
        finally:
            db.close()

    # Interleave tenants so one large tenant cannot fill the executor queue first.
    due_keys = _round_robin_schedule_keys(organization_ids, due_by_organization)

    if not due_keys:
        return

    from concurrent.futures import ThreadPoolExecutor

    limit = getattr(settings, "max_concurrent_scans", 5)
    with ThreadPoolExecutor(max_workers=limit) as pool:
        list(pool.map(lambda key: _execute_scheduled_scan(key[1], key[0]), due_keys))
