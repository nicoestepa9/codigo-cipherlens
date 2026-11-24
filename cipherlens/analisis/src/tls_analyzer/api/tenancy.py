"""Infraestructura multi-tenant: filtro ORM, modo sesion, before_flush."""
from __future__ import annotations

from typing import Optional

from sqlalchemy import event, inspect
from sqlalchemy.sql.elements import TextClause
from sqlalchemy.orm import Session

SYSTEM_TENANT_MODE = "system"
TENANT_MODE = "tenant"


def get_session_org_id(db: Session) -> Optional[int]:
    info = getattr(db, "info", None) or {}
    mode = info.get("tenant_mode")
    if mode == SYSTEM_TENANT_MODE:
        return None
    if mode != TENANT_MODE:
        raise RuntimeError("Tenant session without organization_id or explicit system mode")
    org_id = info.get("organization_id")
    if org_id is None:
        raise RuntimeError("Tenant session without organization_id")
    return org_id


def set_tenant_session(db: Session, organization_id: int) -> None:
    db.info = getattr(db, "info", None) or {}
    db.info["tenant_mode"] = TENANT_MODE
    db.info["organization_id"] = int(organization_id)


def set_system_session(db: Session) -> None:
    db.info = getattr(db, "info", None) or {}
    db.info["tenant_mode"] = SYSTEM_TENANT_MODE
    db.info.pop("organization_id", None)


def install_tenancy(db_session_cls) -> None:
    # SQLAlchemy ORM session events belong to the Session class used by a
    # sessionmaker, not the sessionmaker instance itself.
    target = getattr(db_session_cls, "class_", db_session_cls)

    @event.listens_for(target, "do_orm_execute")
    def _do_orm_execute(orm_execute_state):
        statement = orm_execute_state.statement
        if isinstance(statement, TextClause):
            mode = orm_execute_state.session.info.get("tenant_mode")
            if mode == TENANT_MODE:
                raise RuntimeError("Text SQL is prohibited in tenant sessions")
            if mode != SYSTEM_TENANT_MODE:
                raise RuntimeError(
                    "Tenant session without organization_id or explicit system mode"
                )
            return
        if (
            orm_execute_state.is_column_load
            or orm_execute_state.is_relationship_load
            or not (
                orm_execute_state.is_select
                or orm_execute_state.is_update
                or orm_execute_state.is_delete
            )
        ):
            return
        stmt = statement
        info = orm_execute_state.session.info
        mode = info.get("tenant_mode")
        if mode == SYSTEM_TENANT_MODE:
            return
        if mode != TENANT_MODE:
            raise RuntimeError("Tenant session without organization_id or explicit system mode")
        org_id = info.get("organization_id")
        if org_id is None:
            raise RuntimeError("Tenant session without organization_id")

        from sqlalchemy.orm import with_loader_criteria
        from .db import Base
        from .models import TenantMixin

        org_val = int(org_id)
        tenant_table_names = {
            mapper.local_table.name
            for mapper in Base.registry.mappers
            if issubclass(mapper.class_, TenantMixin)
        }

        def referenced_table_names(from_clause) -> set[str]:
            names = set()
            name = getattr(from_clause, "name", None)
            if name:
                names.add(name)
            for attribute in ("left", "right", "element"):
                nested = getattr(from_clause, attribute, None)
                if nested is not None and nested is not from_clause:
                    names.update(referenced_table_names(nested))
            return names

        # ORM events cannot safely inject tenant predicates into textual/Core
        # SQL. Reject those statements when they address tenant-owned tables.
        if orm_execute_state.is_select and not orm_execute_state.is_orm_statement:
            referenced_names = set()
            for from_clause in stmt.get_final_froms():
                referenced_names.update(referenced_table_names(from_clause))
            if referenced_names & tenant_table_names:
                raise RuntimeError("Core queries on tenant tables are prohibited")
            return
        if orm_execute_state.is_update or orm_execute_state.is_delete:
            mapper = orm_execute_state.bind_mapper
            if mapper is None or not issubclass(mapper.class_, TenantMixin):
                table = getattr(stmt, "table", None)
                if (
                    table is not None
                    and getattr(table, "name", None) in tenant_table_names
                ):
                    raise RuntimeError(
                        "Core DML on tenant tables is prohibited in tenant sessions"
                    )
                return
            if orm_execute_state.is_update:
                assigned_columns = getattr(stmt, "_values", None) or {}
                if any(
                    getattr(column, "key", column) == "organization_id"
                    for column in assigned_columns
                ):
                    raise ValueError("Cannot change organization_id")
            orm_execute_state.statement = stmt.options(
                with_loader_criteria(
                    mapper.class_,
                    lambda entity: entity.organization_id == org_val,
                    include_aliases=True,
                )
            )
            return
        # Apply criteria for every tenant model. Query.count() wraps the ORM
        # entity in a subquery whose outer column description has no entity;
        # entity-only detection therefore silently skipped its inner query.
        for mapper in Base.registry.mappers:
            cls = mapper.class_
            if issubclass(cls, TenantMixin):
                orm_execute_state.statement = orm_execute_state.statement.options(
                    with_loader_criteria(
                        cls,
                        lambda entity: entity.organization_id == org_val,
                        include_aliases=True,
                    )
                )

    @event.listens_for(target, "before_flush")
    def _before_flush(session, flush_context, instances):
        from .models import TenantMixin

        info = getattr(session, "info", None) or {}
        mode = info.get("tenant_mode")
        if mode == SYSTEM_TENANT_MODE:
            org_id = None
        elif mode == TENANT_MODE:
            org_id = info.get("organization_id")
            if org_id is None:
                raise RuntimeError("Tenant session without organization_id")
        else:
            raise RuntimeError("Tenant session without organization_id or explicit system mode")
        if org_id is None:
            # System work may write tenant-owned rows, but every row still has
            # to declare its owner explicitly (migrations use SQL backfills).
            missing = [
                obj for obj in session.new
                if isinstance(obj, TenantMixin)
                and getattr(obj, "organization_id", None) is None
            ]
            if missing:
                raise ValueError(
                    "System session inserts require an explicit organization_id"
                )
            return
        for obj in session.new:
            if isinstance(obj, TenantMixin):
                if getattr(obj, "organization_id", None) is None:
                    obj.organization_id = int(org_id)
                elif int(obj.organization_id) != int(org_id):
                    raise ValueError("Cannot set organization_id on new tenant object")
        for obj in session.dirty:
            if isinstance(obj, TenantMixin):
                insp = inspect(obj)
                if insp.has_identity:
                    hist = insp.attrs.organization_id.history
                    if hist.has_changes():
                        raise ValueError("Cannot change organization_id")
