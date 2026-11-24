"""Router de equipos (Parte 2)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import AuthContext, led_team_ids, require_auth, require_role
from ..schemas import TeamCreate, TeamMemberAdd, TeamOut, TeamUpdate
from ..services import team_service
from .auth import ensure_default_organization

router = APIRouter(prefix="/api", tags=["teams"])


def _get_team(db: Session, team_id: str):
    team = team_service.get(db, team_id)
    if team is None:
        raise HTTPException(status_code=404, detail="Equipo no encontrado")
    return team


def _is_lead_of(db: Session, ctx: AuthContext, team) -> bool:
    return ctx.role == "lead" and ctx.user_id in team_service.lead_ids(db, team.id)


def _ensure_can_manage(db: Session, ctx: AuthContext, team) -> None:
    """Solo admin o el lead de ese equipo pueden gestionar su membresia."""
    if ctx.role == "admin" or _is_lead_of(db, ctx, team):
        return
    raise HTTPException(status_code=403, detail="No podes gestionar este equipo")


@router.get("/teams", response_model=list[TeamOut])
def list_teams(
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(require_auth),
):
    teams = team_service.list_teams(db, organization_id=ctx.organization_id)
    if ctx.role == "admin":
        visible = teams
    elif ctx.role == "lead":
        mine = set(led_team_ids(db, ctx.user_id))
        visible = [t for t in teams if t.id in mine]
    else:
        visible = []
    return [team_service.to_out(db, t) for t in visible]


@router.post("/teams", response_model=TeamOut, status_code=201)
def create_team(
    payload: TeamCreate,
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(require_role("admin")),
):
    org = ensure_default_organization(db, ctx.organization_id)
    try:
        team = team_service.create(
            db,
            name=payload.name,
            description=payload.description,
            member_ids_in=payload.memberIds,
            organization_id=org.id if org else None,
        )
    except team_service.TeamServiceError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail)
    db.commit()
    db.refresh(team)
    return team_service.to_out(db, team)


@router.get("/teams/{team_id}", response_model=TeamOut)
def get_team(
    team_id: str,
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(require_auth),
):
    team = _get_team(db, team_id)
    if ctx.role != "admin" and not _is_lead_of(db, ctx, team):
        raise HTTPException(status_code=403, detail="No podes ver este equipo")
    return team_service.to_out(db, team)


@router.patch("/teams/{team_id}", response_model=TeamOut)
def update_team(
    team_id: str,
    payload: TeamUpdate,
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(require_role("admin")),
):
    team = _get_team(db, team_id)
    try:
        team_service.update(db, team, name=payload.name, description=payload.description)
    except team_service.TeamServiceError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail)
    db.commit()
    db.refresh(team)
    return team_service.to_out(db, team)


@router.delete("/teams/{team_id}", status_code=204)
def delete_team(
    team_id: str,
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(require_role("admin")),
):
    team = _get_team(db, team_id)
    db.delete(team)
    db.commit()
    return None


@router.post("/teams/{team_id}/members", response_model=TeamOut)
def add_member(
    team_id: str,
    payload: TeamMemberAdd,
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(require_auth),
):
    team = _get_team(db, team_id)
    _ensure_can_manage(db, ctx, team)
    # Solo un admin puede designar lider de equipo.
    is_lead = bool(payload.isLead) and ctx.role == "admin"
    try:
        team_service.add_member(db, team, payload.userId, is_lead=is_lead)
    except team_service.TeamServiceError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail)
    db.commit()
    db.refresh(team)
    return team_service.to_out(db, team)


@router.delete("/teams/{team_id}/members/{user_id}", response_model=TeamOut)
def remove_member(
    team_id: str,
    user_id: str,
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(require_auth),
):
    team = _get_team(db, team_id)
    _ensure_can_manage(db, ctx, team)
    team_service.remove_member(db, team, user_id)
    db.commit()
    db.refresh(team)
    return team_service.to_out(db, team)
