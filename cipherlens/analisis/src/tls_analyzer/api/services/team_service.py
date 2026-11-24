"""Servicio de equipos (Parte 2)."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import func
from sqlalchemy.orm import Session

from ..models import Team, TeamMember, User


class TeamServiceError(Exception):
    def __init__(self, status_code: int, detail: str):
        self.status_code = status_code
        self.detail = detail
        super().__init__(detail)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def get(db: Session, team_id: str) -> Team | None:
    return db.get(Team, team_id)


def list_teams(db: Session, *, organization_id: int | None = None) -> list[Team]:
    q = db.query(Team)
    if organization_id is not None:
        q = q.filter(Team.organization_id == organization_id)
    return q.order_by(Team.name).all()


def member_ids(db: Session, team_id: str) -> list[str]:
    rows = db.query(TeamMember.user_id).filter(TeamMember.team_id == team_id).all()
    return [r[0] for r in rows]


def lead_ids(db: Session, team_id: str) -> list[str]:
    rows = (
        db.query(TeamMember.user_id)
        .filter(TeamMember.team_id == team_id, TeamMember.is_lead.is_(True))
        .all()
    )
    return [r[0] for r in rows]


def to_out(db: Session, team: Team) -> dict:
    ids = member_ids(db, team.id)
    return {
        "id": team.id,
        "name": team.name,
        "description": team.description,
        "createdAt": team.created_at.isoformat() if team.created_at else None,
        "memberIds": ids,
        "leadIds": lead_ids(db, team.id),
        "memberCount": len(ids),
    }


def create(db: Session, *, name: str, description: str | None, member_ids_in: list[str] | None, organization_id: int | None = None) -> Team:
    name = (name or "").strip()
    if not name:
        raise TeamServiceError(400, "El nombre es obligatorio")
    existing = db.query(Team).filter(Team.name == name).first()
    if existing is not None:
        raise TeamServiceError(409, "Ya existe un equipo con ese nombre")
    team = Team(name=name, description=description or "", organization_id=organization_id)
    db.add(team)
    db.flush()
    for uid in member_ids_in or []:
        _add_member(db, team, uid)
    db.flush()
    return team


def update(db: Session, team: Team, *, name: str | None, description: str | None) -> Team:
    if name is not None:
        name = name.strip()
        if not name:
            raise TeamServiceError(400, "El nombre no puede ser vacio")
        clash = db.query(Team).filter(Team.name == name, Team.id != team.id).first()
        if clash is not None:
            raise TeamServiceError(409, "Ya existe un equipo con ese nombre")
        team.name = name
    if description is not None:
        team.description = description
    db.flush()
    return team


def _add_member(db: Session, team: Team, user_id: str, is_lead: bool = False) -> None:
    if db.get(User, user_id) is None:
        raise TeamServiceError(404, "Usuario no encontrado")
    exists = (
        db.query(TeamMember)
        .filter(TeamMember.team_id == team.id, TeamMember.user_id == user_id)
        .first()
    )
    if exists is None:
        db.add(TeamMember(team_id=team.id, user_id=user_id, is_lead=is_lead))
    elif is_lead:
        exists.is_lead = True


def add_member(db: Session, team: Team, user_id: str, is_lead: bool = False) -> None:
    _add_member(db, team, user_id, is_lead=is_lead)
    db.flush()


def remove_member(db: Session, team: Team, user_id: str) -> None:
    db.query(TeamMember).filter(
        TeamMember.team_id == team.id, TeamMember.user_id == user_id
    ).delete(synchronize_session=False)
    db.flush()
