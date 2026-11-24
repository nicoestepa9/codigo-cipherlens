"""Endpoints de ingesta del agente on-premise (rol ``agent``). Parte 5.4."""

from __future__ import annotations

import json
import logging
import threading
import time
from collections import deque
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.orm import Session

from ... import analysis
from ..config import settings
from ..db import get_db
from ..deps import AuthContext, require_agent
from ..finding_catalog import InvalidAgentFinding
from ..models import Agent
from ..schemas import (
    AgentDiscoveryIngest,
    AgentHeartbeatIn,
    AgentScanIngest,
    AgentTaskClaimIn,
    AgentTaskStatusIn,
)
from ..services import agent_service, agent_task_service

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/agent", tags=["agent-ingest"])

SUPPORTED_SCHEMA_VERSIONS = {analysis.SCHEMA_VERSION}
PLATFORM_RULES_VERSION = analysis.RULES_VERSION

_ingest_clock: dict[str, deque] = {}
_ingest_lock = threading.Lock()


def _check_schema_version(version: int) -> None:
    if version not in SUPPORTED_SCHEMA_VERSIONS:
        raise HTTPException(
            status_code=422,
            detail=(
                f"Unsupported schemaVersion {version}. Supported: "
                f"{sorted(SUPPORTED_SCHEMA_VERSIONS)} (platform rulesVersion "
                f"{PLATFORM_RULES_VERSION}). Update the agent."
            ),
        )


def _warn_rules_version(rules_version: str) -> None:
    if rules_version and rules_version != PLATFORM_RULES_VERSION:
        logger.warning(
            "Agent reports rulesVersion=%s but platform engine is %s; storing as-is",
            rules_version, PLATFORM_RULES_VERSION,
        )


def _rate_limit(agent_id: str) -> None:
    limit = settings.agent_ingest_rate_per_minute
    if limit <= 0:
        return
    now = time.monotonic()
    with _ingest_lock:
        dq = _ingest_clock.setdefault(agent_id, deque())
        while dq and now - dq[0] > 60.0:
            dq.popleft()
        if len(dq) >= limit:
            retry_after = max(1, int(60.0 - (now - dq[0])))
            raise HTTPException(
                status_code=429,
                detail="Rate limit exceeded",
                headers={"Retry-After": str(retry_after)},
            )
        dq.append(now)


def _load_agent(db: Session, ctx: AuthContext) -> Agent:
    agent = db.get(Agent, ctx.agent_id) if ctx.agent_id else None
    if agent is None or agent.status != "active":
        raise HTTPException(status_code=401, detail="Agent revoked or unknown")
    return agent


def _client_ip(request: Request) -> str | None:
    if request.client is None:
        return None
    return request.client.host


@router.post("/heartbeat", status_code=204)
def heartbeat(
    payload: AgentHeartbeatIn,
    request: Request,
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(require_agent),
):
    _check_schema_version(payload.schemaVersion)
    _rate_limit(ctx.agent_id or "")
    agent = _load_agent(db, ctx)
    agent_service.record_heartbeat(db, agent, payload, ip=_client_ip(request))
    return Response(status_code=204)


@router.post("/tasks/claim")
def claim_tasks(
    payload: AgentTaskClaimIn,
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(require_agent),
):
    agent = _load_agent(db, ctx)
    _rate_limit(agent.id)
    # A task-capable heartbeat is required before the platform will dispatch work.
    capabilities = agent.reported_capabilities or {}
    if capabilities.get("allowRemoteTasks") is not True:
        return []
    return agent_task_service.claim_tasks(
        db,
        agent=agent,
        max_tasks=payload.maxTasks,
        agent_version=payload.agentVersion,
    )


@router.post("/tasks/{task_id}/status")
def update_task_status(
    task_id: str,
    payload: AgentTaskStatusIn,
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(require_agent),
):
    agent = _load_agent(db, ctx)
    _rate_limit(agent.id)
    try:
        return agent_task_service.update_task_status(
            db,
            agent=agent,
            task_id=task_id,
            status=payload.status,
            reason=payload.reason,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail="Task not found") from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/ingest/scan")
def ingest_scan(
    payload: AgentScanIngest,
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(require_agent),
):
    _check_schema_version(payload.schemaVersion)
    _warn_rules_version(payload.rulesVersion)
    _rate_limit(ctx.agent_id or "")
    agent = _load_agent(db, ctx)
    try:
        task = agent_task_service.authorize_task_result(
            db, agent=agent, task_id=payload.taskId, task_type="scan"
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail="Task not found") from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    agent.last_seen_at = datetime.now(timezone.utc)
    db.commit()
    try:
        scan, created = agent_service.ingest_scan(
            db,
            agent,
            payload,
            task_id=payload.taskId,
            recurring_scan_id=task.recurring_scan_id if task else None,
        )
        agent_task_service.complete_task_result(
            db,
            agent=agent,
            task_id=payload.taskId,
            task_type="scan",
            scan=scan,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail="Task not found") from exc
    except InvalidAgentFinding as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return Response(
        content=_json({"scanId": scan.id, "created": created}),
        status_code=201 if created else 200,
        media_type="application/json",
    )


@router.post("/ingest/discovery")
def ingest_discovery(
    payload: AgentDiscoveryIngest,
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(require_agent),
):
    _check_schema_version(payload.schemaVersion)
    _warn_rules_version(payload.rulesVersion)
    _rate_limit(ctx.agent_id or "")
    agent = _load_agent(db, ctx)
    try:
        agent_task_service.authorize_task_result(
            db, agent=agent, task_id=payload.taskId, task_type="discovery"
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail="Task not found") from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    agent.last_seen_at = datetime.now(timezone.utc)
    db.commit()
    try:
        job, created = agent_service.ingest_discovery(
            db, agent, payload, task_id=payload.taskId
        )
        agent_task_service.complete_task_result(
            db,
            agent=agent,
            task_id=payload.taskId,
            task_type="discovery",
            job=job,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail="Task not found") from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return Response(
        content=_json({"jobId": job.id, "created": created}),
        status_code=201 if created else 200,
        media_type="application/json",
    )


def _json(data: dict) -> bytes:
    import json

    return json.dumps(data).encode("utf-8")
