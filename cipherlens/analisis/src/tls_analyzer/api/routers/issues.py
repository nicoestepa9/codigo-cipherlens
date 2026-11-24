"""Router de issues (Parte 2)."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import or_
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import (
    AuthContext,
    led_team_ids,
    led_team_member_ids,
    member_team_ids,
    require_auth,
)
from ..models import Agent, Issue, Service, Team, User
from ..schemas import IssueAssign, IssueOut, IssueUpdate, Paged
from ..services import issue_service

router = APIRouter(prefix="/api", tags=["issues"])

ASSIGN_ROLES = ("admin", "lead")


def _naive_utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _get_issue(db: Session, issue_id: str) -> Issue:
    issue = db.get(Issue, issue_id)
    if issue is None:
        raise HTTPException(status_code=404, detail="Issue no encontrado")
    return issue


def _can_view(db: Session, ctx: AuthContext, issue: Issue) -> bool:
    """Visibilidad: admin todo; user/lead lo propio y lo de sus equipos;
    lead ademas lo asignado a miembros de los equipos que lidera."""
    if ctx.role == "admin":
        return True
    if ctx.user_id and issue.owner_user_id == ctx.user_id:
        return True
    if (
        ctx.user_id
        and issue.owner_team_id
        and issue.owner_team_id in member_team_ids(db, ctx.user_id)
    ):
        return True
    if ctx.role == "lead":
        if issue.owner_user_id and issue.owner_user_id in led_team_member_ids(
            db, ctx.user_id
        ):
            return True
        if issue.owner_team_id and issue.owner_team_id in led_team_ids(db, ctx.user_id):
            return True
    return False


def _can_work(db: Session, ctx: AuthContext, issue: Issue) -> bool:
    """Comentar / cambiar estado: admin todo; el resto sobre lo que pueden ver."""
    return _can_view(db, ctx, issue)


def _validate_assign(
    db: Session,
    ctx: AuthContext,
    owner_user_id: str | None,
    owner_team_id: str | None,
) -> None:
    """admin asigna a cualquiera; lead solo a miembros de un equipo que lidera."""
    if owner_user_id is not None:
        owner = db.get(User, owner_user_id)
        if owner is None or not owner.is_active or owner.deleted_at is not None:
            raise HTTPException(status_code=422, detail="Owner no valido")
        if (
            ctx.organization_id is not None
            and owner.organization_id != ctx.organization_id
        ):
            raise HTTPException(status_code=422, detail="Owner no valido")
    if owner_team_id is not None:
        team = db.get(Team, owner_team_id)
        if team is None:
            raise HTTPException(status_code=422, detail="Owner no valido")
        if (
            ctx.organization_id is not None
            and team.organization_id != ctx.organization_id
        ):
            raise HTTPException(status_code=422, detail="Owner no valido")
    if ctx.role == "admin":
        return
    if ctx.role != "lead":
        raise HTTPException(status_code=403, detail="No podes asignar issues")
    if owner_team_id is not None:
        raise HTTPException(
            status_code=403,
            detail="Un lead solo puede asignar a miembros de su equipo",
        )
    if owner_user_id is not None and owner_user_id not in led_team_member_ids(
        db, ctx.user_id
    ):
        raise HTTPException(
            status_code=403,
            detail="Solo podes asignar issues a miembros de tu equipo",
        )


@router.get("/issues", response_model=Paged[IssueOut])
def list_issues(
    status: str | None = Query(None),
    severity: str | None = Query(None),
    serviceId: str | None = Query(None),
    ownerUserId: str | None = Query(None),
    ownerTeamId: str | None = Query(None),
    sourceDocument: str | None = Query(None),
    overdue: bool | None = Query(None),
    agentId: str | None = Query(None),
    siteLabel: str | None = Query(None),
    mine: bool = Query(False),
    page: int = Query(1, ge=1),
    pageSize: int = Query(25, ge=1, le=100),
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(require_auth),
):
    org_id = ctx.organization_id
    q = db.query(Issue)
    if org_id is not None:
        q = q.filter(Issue.organization_id == org_id)
    if status:
        q = q.filter(Issue.status == status)
    if severity:
        q = q.filter(Issue.severity == severity)
    if serviceId:
        q = q.filter(Issue.service_id == serviceId)
    if ownerUserId:
        q = q.filter(Issue.owner_user_id == ownerUserId)
    if ownerTeamId:
        q = q.filter(Issue.owner_team_id == ownerTeamId)
    if sourceDocument:
        q = q.filter(Issue.source_document == sourceDocument)
    if agentId or siteLabel:
        q = q.join(Service, Service.id == Issue.service_id)
    if agentId:
        q = q.filter(Service.agent_id == agentId)
    if siteLabel:
        q = (
            q.join(Agent, Agent.id == Service.agent_id)
            .filter(Agent.site_label.ilike(f"%{siteLabel.strip()}%"))
        )
    if overdue is True:
        q = q.filter(
            Issue.status.in_(list(issue_service.OPEN_STATUSES)),
            Issue.due_at.isnot(None),
            Issue.due_at < _naive_utcnow(),
        )
    elif overdue is False:
        q = q.filter(
            Issue.status.in_(list(issue_service.OPEN_STATUSES)),
            (Issue.due_at.is_(None)) | (Issue.due_at >= _naive_utcnow()),
        )

    # Mis issues: propios + los asignados a cualquiera de mis equipos.
    if mine:
        mine_conditions = []
        if ctx.user_id:
            mine_conditions.append(Issue.owner_user_id == ctx.user_id)
            team_ids = member_team_ids(db, ctx.user_id)
            if team_ids:
                mine_conditions.append(Issue.owner_team_id.in_(team_ids))
        if not mine_conditions:
            return {"items": [], "total": 0, "page": page, "pageSize": pageSize}
        q = q.filter(or_(*mine_conditions))

    # Alcance por rol: admin todo; user/lead lo propio y lo de sus equipos;
    # lead ademas lo asignado a miembros de los equipos que lidera.
    if ctx.role != "admin":
        conditions = []
        if ctx.user_id:
            conditions.append(Issue.owner_user_id == ctx.user_id)
            team_ids = member_team_ids(db, ctx.user_id)
            if team_ids:
                conditions.append(Issue.owner_team_id.in_(team_ids))
        if ctx.role == "lead":
            member_ids = led_team_member_ids(db, ctx.user_id)
            if member_ids:
                conditions.append(Issue.owner_user_id.in_(member_ids))
            team_ids = led_team_ids(db, ctx.user_id)
            if team_ids:
                conditions.append(Issue.owner_team_id.in_(team_ids))
        if not conditions:
            return {"items": [], "total": 0, "page": page, "pageSize": pageSize}
        q = q.filter(or_(*conditions))

    total = q.count()
    rows = (
        q.order_by(Issue.updated_at.desc())
        .offset((page - 1) * pageSize)
        .limit(pageSize)
        .all()
    )
    return {
        "items": [issue_service.to_out(db, i) for i in rows],
        "total": total,
        "page": page,
        "pageSize": pageSize,
    }


@router.get("/issues/{issue_id}", response_model=IssueOut)
def get_issue(
    issue_id: str,
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(require_auth),
):
    issue = _get_issue(db, issue_id)
    if not _can_view(db, ctx, issue):
        raise HTTPException(status_code=403, detail="Sin acceso a este issue")
    return issue_service.to_out(db, issue, with_history=True)


@router.patch("/issues/{issue_id}", response_model=IssueOut)
def update_issue(
    issue_id: str,
    payload: IssueUpdate,
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(require_auth),
):
    issue = _get_issue(db, issue_id)
    fields = payload.model_fields_set
    is_assign = "ownerUserId" in fields or "ownerTeamId" in fields
    is_work = bool(payload.status) or bool(payload.comment)

    if is_assign:
        if ctx.role not in ASSIGN_ROLES:
            raise HTTPException(status_code=403, detail="No podes asignar issues")
        if not _can_view(db, ctx, issue):
            raise HTTPException(status_code=403, detail="No podes modificar este issue")
        _validate_assign(db, ctx, payload.ownerUserId, payload.ownerTeamId)
        issue_service.assign(
            db, issue,
            owner_user_id=payload.ownerUserId,
            owner_team_id=payload.ownerTeamId,
            actor_user_id=ctx.user_id,
        )

    if is_work:
        if not _can_work(db, ctx, issue):
            raise HTTPException(
                status_code=403,
                detail="Solo podes trabajar sobre issues asignados a vos o a tu equipo",
            )

    if payload.status:
        try:
            issue_service.change_status(
                db, issue, payload.status,
                actor_user_id=ctx.user_id,
                comment=payload.comment,
                reason=payload.reason,
                risk_accepted_until=payload.riskAcceptedUntil,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
    elif payload.comment:
        issue_service.add_comment(db, issue, payload.comment, actor_user_id=ctx.user_id)

    db.commit()
    db.refresh(issue)
    return issue_service.to_out(db, issue, with_history=True)


@router.post("/issues/assign")
def bulk_assign(
    payload: IssueAssign,
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(require_auth),
):
    if ctx.role not in ASSIGN_ROLES:
        raise HTTPException(status_code=403, detail="No podes asignar issues")
    _validate_assign(db, ctx, payload.ownerUserId, payload.ownerTeamId)
    updated = 0
    for issue_id in payload.issueIds:
        issue = db.get(Issue, issue_id)
        if issue is None:
            continue
        if not _can_view(db, ctx, issue):
            continue
        issue_service.assign(
            db, issue,
            owner_user_id=payload.ownerUserId,
            owner_team_id=payload.ownerTeamId,
            actor_user_id=ctx.user_id,
        )
        updated += 1
    db.commit()
    return {"updated": updated}


@router.post("/issues/{issue_id}/comment")
def add_comment(
    issue_id: str,
    payload: IssueUpdate,
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(require_auth),
):
    issue = _get_issue(db, issue_id)
    if not payload.comment:
        raise HTTPException(status_code=400, detail="Comentario vacio")
    if not _can_work(db, ctx, issue):
        raise HTTPException(
            status_code=403,
            detail="Solo podes comentar issues asignados a vos",
        )
    issue_service.add_comment(db, issue, payload.comment, actor_user_id=ctx.user_id)
    db.commit()
    return {"status": "ok"}
