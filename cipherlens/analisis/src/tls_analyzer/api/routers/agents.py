"""Router de gestion de agentes on-premise (solo admin). Parte 5.3."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import AuthContext, require_role
from ..cloud_guardrails import OrganizationQuotaExceeded, enforce_agent_quota
from ..schemas import AgentCreate, AgentCreated, AgentDetailOut, AgentOut, AgentUpdate
from ..services import agent_service

router = APIRouter(prefix="/api/agents", tags=["agents"])


@router.post("", response_model=AgentCreated, status_code=201)
def create_agent(
    payload: AgentCreate,
    request: Request,
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(require_role("admin")),
):
    try:
        enforce_agent_quota(db, request, ctx, name=payload.name)
    except OrganizationQuotaExceeded as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc
    dto, plain = agent_service.create_agent(
        db, payload.name, payload.siteLabel, actor_user_id=ctx.user_id
    )
    dto["apiKey"] = plain
    return dto


@router.get("", response_model=list[AgentOut])
def list_agents(
    db: Session = Depends(get_db),
    _: AuthContext = Depends(require_role("admin", "lead")),
):
    return agent_service.list_agents(db)


@router.get("/{agent_id}", response_model=AgentDetailOut)
def get_agent(
    agent_id: str,
    db: Session = Depends(get_db),
    _: AuthContext = Depends(require_role("admin", "lead")),
):
    dto = agent_service.get_agent(db, agent_id)
    if dto is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    return dto


@router.patch("/{agent_id}", response_model=AgentOut)
def update_agent(
    agent_id: str,
    payload: AgentUpdate,
    db: Session = Depends(get_db),
    _: AuthContext = Depends(require_role("admin")),
):
    dto = agent_service.update_agent(
        db, agent_id, name=payload.name, site_label=payload.siteLabel
    )
    if dto is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    return dto


@router.post("/{agent_id}/rotate-key", response_model=AgentCreated)
def rotate_key(
    agent_id: str,
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(require_role("admin")),
):
    result = agent_service.rotate_key(db, agent_id, actor_user_id=ctx.user_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Agent not found or revoked")
    dto, plain = result
    dto["apiKey"] = plain
    return dto


@router.delete("/{agent_id}", status_code=204)
def revoke_agent(
    agent_id: str,
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(require_role("admin")),
):
    if not agent_service.revoke_agent(db, agent_id, actor_user_id=ctx.user_id):
        raise HTTPException(status_code=404, detail="Agent not found")
    return Response(status_code=204)
