"""Lifecycle and tenant-scoped persistence for agent-pulled tasks."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import update
from sqlalchemy.orm import Session

from ..config import settings
from ..models import Agent, AgentTask, AuditLog, DiscoveryJob, RecurringScan, Scan
from ..tenancy import get_session_org_id

TASK_TYPES = {"scan", "discovery"}
TASK_STATUSES = {
    "queued", "claimed", "running", "done", "failed", "rejected", "expired",
    "cancelled",
}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(value: datetime | None) -> datetime | None:
    if value is None or value.tzinfo is not None:
        return value
    return value.replace(tzinfo=timezone.utc)


def _lease_seconds() -> int:
    return max(30, int(getattr(settings, "agent_task_lease_seconds", 600)))


def _max_attempts() -> int:
    return max(1, int(getattr(settings, "agent_task_max_attempts", 3)))


def _task_ttl_seconds() -> int:
    return max(60, int(getattr(settings, "agent_task_ttl_seconds", 3600)))


def _task_dto(task: AgentTask) -> dict:
    def iso(value):
        return value.isoformat() if value else None

    return {
        "id": task.id,
        "agentId": task.agent_id,
        "type": task.type,
        "status": task.status,
        "payload": task.payload or {},
        "createdAt": iso(task.created_at),
        "expiresAt": iso(task.expires_at),
        "claimedAt": iso(task.claimed_at),
        "leaseExpiresAt": iso(task.lease_expires_at),
        "finishedAt": iso(task.finished_at),
        "attempts": task.attempts,
        "error": task.error,
        "resultScanId": task.result_scan_id,
        "resultJobId": task.result_job_id,
        "recurringScanId": task.recurring_scan_id,
    }


def _record_recurring_failure(db: Session, task: AgentTask, now: datetime) -> None:
    if task.recurring_scan_id is None:
        return
    schedule = db.get(RecurringScan, task.recurring_scan_id)
    if schedule is None:
        return
    schedule.consecutive_failures += 1
    schedule.is_running = False
    schedule.last_run_at = now
    threshold = max(1, int(settings.scheduled_scan_fail_threshold))
    if schedule.consecutive_failures >= threshold:
        from .recurring_scan_service import _emit_failing_alert

        _emit_failing_alert(db, schedule)


def _record_task_event(
    db: Session,
    *,
    action: str,
    task: AgentTask,
    actor_type: str,
    actor_user_id: str | None = None,
    meta: dict | None = None,
) -> None:
    organization_id = task.organization_id or get_session_org_id(db)
    db.add(AuditLog(
        actor_type=actor_type,
        actor_user_id=actor_user_id,
        action=action,
        entity_type="agent_task",
        entity_id=task.id,
        meta=meta or {},
        organization_id=organization_id,
    ))


def create_task(
    db: Session,
    *,
    agent_id: str,
    task_type: str,
    payload: dict,
    requested_by_user_id: str | None,
    recurring_scan_id: int | None = None,
) -> AgentTask:
    if task_type not in TASK_TYPES:
        raise ValueError("Unsupported task type")
    agent = db.get(Agent, agent_id)
    if agent is None or agent.status != "active":
        raise LookupError("Agent not found")
    organization_id = get_session_org_id(db)
    if organization_id is None or agent.organization_id != organization_id:
        raise LookupError("Agent not found")
    now = _utcnow()
    task = AgentTask(
        id=str(uuid.uuid4()),
        organization_id=organization_id,
        agent_id=agent.id,
        type=task_type,
        payload=payload,
        status="queued",
        requested_by_user_id=requested_by_user_id,
        recurring_scan_id=recurring_scan_id,
        created_at=now,
        expires_at=now + timedelta(seconds=_task_ttl_seconds()),
        attempts=0,
    )
    db.add(task)
    db.flush()
    _record_task_event(
        db,
        action="agent_task.created",
        task=task,
        actor_type="user" if requested_by_user_id else "system",
        actor_user_id=requested_by_user_id,
        meta={"agent_id": agent.id, "type": task_type, "target": _task_target(payload)},
    )
    db.commit()
    db.refresh(task)
    return task


def _task_target(payload: dict) -> str:
    target = payload.get("target")
    if isinstance(target, dict):
        return str(target.get("host") or "")
    return str(payload.get("ipRange") or ", ".join(payload.get("domains") or []))


def _terminal_recurring_transition(
    db: Session, task: AgentTask, status: str, now: datetime
) -> None:
    task.status = status
    task.finished_at = now
    task.lease_expires_at = None
    if status in {"failed", "expired"}:
        _record_recurring_failure(db, task, now)
    elif status in {"done", "cancelled", "rejected"} and task.recurring_scan_id:
        schedule = db.get(RecurringScan, task.recurring_scan_id)
        if schedule is not None:
            schedule.is_running = False
            if status == "done":
                schedule.consecutive_failures = 0


def _reconcile_expired(db: Session, agent_id: str, now: datetime) -> None:
    max_attempts = _max_attempts()
    expired_queued = (
        db.query(AgentTask)
        .filter(
            AgentTask.agent_id == agent_id,
            AgentTask.status == "queued",
            AgentTask.expires_at <= now,
        )
        .all()
    )
    for task in expired_queued:
        changed = db.execute(
            update(AgentTask)
            .where(
                AgentTask.id == task.id,
                AgentTask.status == "queued",
                AgentTask.expires_at <= now,
            )
            .values(status="expired", finished_at=now, error="Task expired")
            .execution_options(synchronize_session=False)
        ).rowcount
        if changed:
            task.status = "expired"
            task.finished_at = now
            task.error = "Task expired"
            _record_recurring_failure(db, task, now)

    expired_leases = (
        db.query(AgentTask)
        .filter(
            AgentTask.agent_id == agent_id,
            AgentTask.status.in_(("claimed", "running")),
            AgentTask.lease_expires_at.is_not(None),
            AgentTask.lease_expires_at <= now,
        )
        .all()
    )
    for task in expired_leases:
        terminal = task.attempts >= max_attempts
        values = (
            {
                "status": "failed",
                "finished_at": now,
                "lease_expires_at": None,
                "error": "Lease expired after maximum attempts",
            }
            if terminal
            else {
                "status": "queued",
                "claimed_at": None,
                "lease_expires_at": None,
                "error": None,
            }
        )
        changed = db.execute(
            update(AgentTask)
            .where(
                AgentTask.id == task.id,
                AgentTask.status.in_(("claimed", "running")),
                AgentTask.lease_expires_at <= now,
            )
            .values(**values)
            .execution_options(synchronize_session=False)
        ).rowcount
        if changed:
            for key, value in values.items():
                setattr(task, key, value)
            if terminal:
                _record_recurring_failure(db, task, now)


def reap_expired_tasks() -> int:
    """Advance expired leases even when an agent remains offline."""
    from ..db import SessionLocal
    from ..models import Organization
    from ..tenancy import set_system_session, set_tenant_session

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

    changed = 0
    now = _utcnow()
    for organization_id in organization_ids:
        db = SessionLocal()
        try:
            set_tenant_session(db, organization_id)
            agent_ids = [
            row[0] for row in db.query(Agent.id).filter(Agent.status == "active")
            ]
            before = (
            db.query(AgentTask.id)
            .filter(AgentTask.status.in_(("queued", "claimed", "running")))
            .count()
            )
            for agent_id in agent_ids:
                _reconcile_expired(db, agent_id, now)
            db.commit()
            after = (
                db.query(AgentTask.id)
                .filter(AgentTask.status.in_(("queued", "claimed", "running")))
                .count()
            )
            changed += max(0, before - after)
        finally:
            db.close()
    return changed


def claim_tasks(
    db: Session, *, agent: Agent, max_tasks: int, agent_version: str | None = None
) -> list[dict]:
    now = _utcnow()
    _reconcile_expired(db, agent.id, now)
    organization_id = get_session_org_id(db)
    if organization_id is None or agent.organization_id != organization_id:
        return []

    claimed: list[AgentTask] = []
    candidates = (
        db.query(AgentTask)
        .filter(
            AgentTask.agent_id == agent.id,
            AgentTask.status == "queued",
            AgentTask.expires_at > now,
        )
        .order_by(AgentTask.created_at, AgentTask.id)
        .limit(max_tasks)
        .all()
    )
    lease_until = now + timedelta(seconds=_lease_seconds())
    for candidate in candidates:
        changed = db.execute(
            update(AgentTask)
            .where(
                AgentTask.id == candidate.id,
                AgentTask.agent_id == agent.id,
                AgentTask.organization_id == organization_id,
                AgentTask.status == "queued",
                AgentTask.expires_at > now,
            )
            .values(
                status="claimed",
                claimed_at=now,
                lease_expires_at=lease_until,
                attempts=AgentTask.attempts + 1,
                error=None,
            )
            .execution_options(synchronize_session=False)
        ).rowcount
        if changed == 1:
            candidate.status = "claimed"
            candidate.claimed_at = now
            candidate.lease_expires_at = lease_until
            candidate.attempts += 1
            candidate.error = None
            claimed.append(candidate)
    agent.last_seen_at = now
    if agent_version:
        agent.version = agent_version[:64]
    db.commit()
    return [
        {
            "taskId": task.id,
            "type": task.type,
            "payload": task.payload or {},
            "expiresAt": task.expires_at.isoformat(),
        }
        for task in claimed
    ]


def update_task_status(
    db: Session, *, agent: Agent, task_id: str, status: str, reason: str | None
) -> dict:
    task = (
        db.query(AgentTask)
        .filter(AgentTask.id == task_id, AgentTask.agent_id == agent.id)
        .first()
    )
    if task is None:
        raise LookupError("Task not found")
    now = _utcnow()
    if status == "running":
        if task.status not in {"claimed", "running"}:
            raise ValueError("Task is not claimable")
        lease = _as_utc(task.lease_expires_at)
        if lease is not None and lease <= now:
            _reconcile_expired(db, agent.id, now)
            db.commit()
            raise ValueError("Task lease expired")
        task.status = "running"
        task.lease_expires_at = now + timedelta(seconds=_lease_seconds())
    else:
        if task.status not in {"claimed", "running"}:
            if task.status == status:
                return _task_dto(task)
            raise ValueError("Task is not claimable")
        if status not in {"rejected", "failed"}:
            raise ValueError("Unsupported task status")
        _terminal_recurring_transition(db, task, status, now)
        task.error = (reason or status)[:255]
        _record_task_event(
            db,
            action=f"agent_task.{status}",
            task=task,
            actor_type="agent",
            meta={"agent_id": agent.id, "reason": task.error},
        )
    agent.last_seen_at = now
    db.commit()
    db.refresh(task)
    return _task_dto(task)


def authorize_task_result(
    db: Session, *, agent: Agent, task_id: str | None, task_type: str
) -> AgentTask | None:
    if not task_id:
        return None
    task = (
        db.query(AgentTask)
        .filter(AgentTask.id == task_id, AgentTask.agent_id == agent.id)
        .first()
    )
    if task is None:
        raise LookupError("Task not found")
    if task.type != task_type:
        raise ValueError("Task type does not match result")
    if task.status == "done":
        return task
    if task.status not in {"claimed", "running"}:
        raise ValueError("Task is not running")
    lease = _as_utc(task.lease_expires_at)
    if lease is not None and lease <= _utcnow():
        raise ValueError("Task lease expired")
    return task


def complete_task_result(
    db: Session,
    *,
    agent: Agent,
    task_id: str | None,
    task_type: str,
    scan: Scan | None = None,
    job: DiscoveryJob | None = None,
) -> None:
    if not task_id:
        return
    task = authorize_task_result(
        db, agent=agent, task_id=task_id, task_type=task_type
    )
    if task is None:
        return
    if task.status == "done":
        expected_id = task.result_scan_id if task_type == "scan" else task.result_job_id
        actual_id = scan.id if scan is not None else (job.id if job is not None else None)
        if expected_id != actual_id:
            raise ValueError("Task already completed with another result")
        return
    now = _utcnow()
    task.status = "done"
    task.finished_at = now
    task.lease_expires_at = None
    task.error = None
    if scan is not None:
        task.result_scan_id = scan.id
        if task.recurring_scan_id:
            schedule = db.get(RecurringScan, task.recurring_scan_id)
            if schedule is not None:
                schedule.service_id = scan.service_id
                if scan.status == "completed":
                    from .recurring_scan_service import (
                        compute_scan_comparison,
                        handle_scheduled_scan_alerts,
                    )

                    comparison = compute_scan_comparison(db, scan)
                    handle_scheduled_scan_alerts(db, schedule, comparison)
    if job is not None:
        task.result_job_id = job.id
    _terminal_recurring_transition(db, task, "done", now)
    db.commit()


def list_tasks(
    db: Session, *, status: str | None = None, agent_id: str | None = None,
    limit: int = 100,
) -> list[dict]:
    query = db.query(AgentTask)
    if status is not None:
        if status not in TASK_STATUSES:
            raise ValueError("Invalid task status")
        query = query.filter(AgentTask.status == status)
    if agent_id:
        query = query.filter(AgentTask.agent_id == agent_id)
    return [
        _task_dto(task)
        for task in query.order_by(AgentTask.created_at.desc(), AgentTask.id)
        .limit(min(max(limit, 1), 200))
        .all()
    ]


def get_task(db: Session, task_id: str) -> AgentTask | None:
    return db.get(AgentTask, task_id)


def cancel_task(
    db: Session, *, task: AgentTask, actor_user_id: str | None
) -> AgentTask | None:
    now = _utcnow()
    changed = db.execute(
        update(AgentTask)
        .where(AgentTask.id == task.id, AgentTask.status == "queued")
        .values(status="cancelled", finished_at=now, error="Cancelled by user")
        .execution_options(synchronize_session=False)
    ).rowcount
    if changed != 1:
        return None
    task.status = "cancelled"
    task.finished_at = now
    task.error = "Cancelled by user"
    task.lease_expires_at = None
    if task.recurring_scan_id:
        schedule = db.get(RecurringScan, task.recurring_scan_id)
        if schedule is not None:
            schedule.is_running = False
    _record_task_event(
        db,
        action="agent_task.cancelled",
        task=task,
        actor_type="user",
        actor_user_id=actor_user_id,
        meta={"agent_id": task.agent_id},
    )
    db.commit()
    db.refresh(task)
    return task


def enqueue_recurring_task(db: Session, schedule: RecurringScan) -> AgentTask | None:
    if not schedule.agent_id:
        return None
    existing = (
        db.query(AgentTask)
        .filter(
            AgentTask.recurring_scan_id == schedule.id,
            AgentTask.status.in_(("queued", "claimed", "running")),
        )
        .first()
    )
    if existing is not None:
        return existing
    agent = db.get(Agent, schedule.agent_id)
    if agent is None or agent.status != "active":
        schedule.consecutive_failures += 1
        schedule.is_running = False
        if schedule.consecutive_failures >= max(
            1, int(settings.scheduled_scan_fail_threshold)
        ):
            from .recurring_scan_service import _emit_failing_alert

            _emit_failing_alert(db, schedule)
        return None
    task = create_task(
        db,
        agent_id=agent.id,
        task_type="scan",
        payload={
            "target": {"host": schedule.host, "port": schedule.port},
            "options": {
                "profile": schedule.profile,
                "alternatePorts": schedule.alternate_ports or [],
            },
            "recurringScanId": schedule.id,
        },
        requested_by_user_id=None,
        recurring_scan_id=schedule.id,
    )
    return task
