"""Router de discovery: jobs, resultados y resumen."""

from __future__ import annotations

import threading

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from ..cloud_guardrails import (
    OrganizationQuotaExceeded,
    enforce_cloud_scan_quota,
    record_cloud_scan_start,
    require_cloud_authorization,
    resolve_cloud_discovery_targets,
)
from ..deps import AuthContext, require_api_key, require_auth
from ..schemas import (
    DiscoveryJobOut,
    DiscoveryRequest,
    DiscoveryResultOut,
    DiscoverySummaryOut,
    AgentTaskAcceptedOut,
)
from ..services import agent_task_service
from ..services import discovery_service
from ..db import get_db
from ..models import DiscoveryJob
from ..tenancy import get_session_org_id

router = APIRouter(prefix="/api", tags=["discovery"])


@router.post(
    "/discovery",
    response_model=DiscoveryJobOut,
    responses={202: {"model": AgentTaskAcceptedOut}},
)
def start_discovery(
    payload: DiscoveryRequest,
    request: Request,
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(require_auth),
):
    target_label = payload.ipRange or ", ".join(payload.domains)
    if payload.executor and payload.executor.type == "agent":
        if ctx.role not in {"lead", "admin"}:
            raise HTTPException(status_code=403, detail="Insufficient role")
        try:
            if discovery_service.estimate_target_count(
                payload.ipRange, payload.domains
            ) > discovery_service.MAX_TARGETS:
                raise HTTPException(
                    status_code=400,
                    detail="Discovery request exceeds the maximum target count",
                )
            task = agent_task_service.create_task(
                db,
                agent_id=payload.executor.agentId or "",
                task_type="discovery",
                payload={
                    "ipRange": payload.ipRange,
                    "domains": payload.domains,
                    "ports": payload.ports,
                    "scanInternal": True,
                },
                requested_by_user_id=ctx.user_id,
            )
        except LookupError as exc:
            raise HTTPException(status_code=404, detail="Agent not found") from exc
        except (TypeError, ValueError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return JSONResponse(
            {"taskId": task.id, "status": task.status}, status_code=202
        )

    require_cloud_authorization(
        db,
        request,
        ctx,
        accepted=payload.authorizationAccepted,
        version=payload.authorizationVersion,
        operation="discovery",
        target=target_label,
    )
    resolved_targets = resolve_cloud_discovery_targets(
        db,
        request,
        ctx,
        ip_range=payload.ipRange,
        domains=payload.domains,
        scan_internal=payload.scanInternal,
    )
    try:
        enforce_cloud_scan_quota(
            db,
            request,
            ctx,
            action="cloud_discovery.started",
            target=target_label,
        )
    except OrganizationQuotaExceeded as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc
    record_cloud_scan_start(
        db,
        request,
        ctx,
        action="cloud_discovery.started",
        target=target_label,
    )
    job_data = payload.model_dump()
    job_data["resolvedTargets"] = resolved_targets
    try:
        job = discovery_service.create_job(db, job_data)
    except discovery_service.DiscoveryTargetTooLarge as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    threading.Thread(
        target=discovery_service.run_job,
        args=(job.id, get_session_org_id(db)),
        daemon=True,
    ).start()
    return discovery_service.get_job(db, job.id)


@router.delete("/discovery/{job_id}", response_model=DiscoveryJobOut)
def cancel_discovery(
    job_id: str,
    db: Session = Depends(get_db),
    _: None = Depends(require_api_key),
):
    """Cancela un job en vuelo. El worker lo aborta en la proxima tanda de probes."""
    if not discovery_service.request_cancel(
        job_id, organization_id=get_session_org_id(db)
    ):
        job = db.get(DiscoveryJob, job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="Discovery job not found")
    return discovery_service.get_job(db, job_id)


@router.get("/discovery/results", response_model=list[DiscoveryResultOut])
def get_all_discovery_results(
    agentId: str | None = Query(None),
    siteLabel: str | None = Query(None),
    db: Session = Depends(get_db),
    _: None = Depends(require_api_key),
):
    return discovery_service.get_all_results(db, agent_id=agentId, site_label=siteLabel)


@router.get("/discovery/summary", response_model=DiscoverySummaryOut)
def get_discovery_summary(
    agentId: str | None = Query(None),
    siteLabel: str | None = Query(None),
    db: Session = Depends(get_db),
    _: None = Depends(require_api_key),
):
    return discovery_service.summary(db, agent_id=agentId, site_label=siteLabel)


@router.get("/discovery/{job_id}", response_model=DiscoveryJobOut)
def get_discovery_job(
    job_id: str,
    db: Session = Depends(get_db),
    _: None = Depends(require_api_key),
):
    job = discovery_service.get_job(db, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Discovery job not found")
    return job


@router.get("/discovery/{job_id}/results", response_model=list[DiscoveryResultOut])
def get_discovery_results(
    job_id: str,
    agentId: str | None = Query(None),
    siteLabel: str | None = Query(None),
    db: Session = Depends(get_db),
    _: None = Depends(require_api_key),
):
    return discovery_service.get_job_results(db, job_id, agent_id=agentId, site_label=siteLabel)
