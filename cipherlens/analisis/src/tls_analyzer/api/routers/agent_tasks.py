"""User-facing queue visibility and cancellation for remote agent tasks."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import AuthContext, require_role
from ..models import AgentTask
from ..schemas import AgentTaskOut
from ..services import agent_task_service

router = APIRouter(prefix="/api/agent-tasks", tags=["agent-tasks"])
_task_reader = require_role("lead", "admin")


@router.get("", response_model=list[AgentTaskOut])
def list_agent_tasks(
    status: str | None = Query(default=None),
    agentId: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=200),
    db: Session = Depends(get_db),
    _: AuthContext = Depends(_task_reader),
):
    try:
        return agent_task_service.list_tasks(
            db, status=status, agent_id=agentId, limit=limit
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/{task_id}", response_model=AgentTaskOut)
def get_agent_task(
    task_id: str,
    db: Session = Depends(get_db),
    _: AuthContext = Depends(_task_reader),
):
    task = agent_task_service.get_task(db, task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="Agent task not found")
    return agent_task_service._task_dto(task)


@router.delete("/{task_id}", response_model=AgentTaskOut)
def cancel_agent_task(
    task_id: str,
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(_task_reader),
):
    task = agent_task_service.get_task(db, task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="Agent task not found")
    cancelled = agent_task_service.cancel_task(
        db, task=task, actor_user_id=ctx.user_id
    )
    if cancelled is None:
        raise HTTPException(
            status_code=409, detail="Only queued tasks can be cancelled"
        )
    return agent_task_service._task_dto(cancelled)
