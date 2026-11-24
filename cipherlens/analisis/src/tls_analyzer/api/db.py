"""Base de datos: engine SQLAlchemy y sesion FastAPI."""

from __future__ import annotations

from collections.abc import Iterator

from fastapi import Request
from sqlalchemy import create_engine, inspect, select
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.pool import StaticPool

from .config import settings


class Base(DeclarativeBase):
    """Base declarativa para los modelos ORM."""


class TenantSession(Session):
    """Session subclass that also scopes primary-key lookups by organization."""

    def _tenant_org_for(self, instance):
        from .models import TenantMixin
        from .tenancy import SYSTEM_TENANT_MODE, TENANT_MODE

        if not isinstance(instance, TenantMixin):
            return None
        mode = self.info.get("tenant_mode")
        if mode == SYSTEM_TENANT_MODE:
            return None
        if mode != TENANT_MODE:
            raise RuntimeError(
                "Tenant session without organization_id or explicit system mode"
            )
        organization_id = self.info.get("organization_id")
        if organization_id is None:
            raise RuntimeError("Tenant session without organization_id")
        return int(organization_id)

    def refresh(self, instance, attribute_names=None, with_for_update=None, **kwargs):
        org_id = self._tenant_org_for(instance)
        if org_id is not None:
            if getattr(instance, "organization_id", None) is None:
                raise ValueError("Cannot refresh tenant object without organization_id")
            if int(instance.organization_id) != org_id:
                raise ValueError("Cannot refresh tenant object from another organization")
        return super().refresh(
            instance,
            attribute_names=attribute_names,
            with_for_update=with_for_update,
            **kwargs,
        )

    def merge(self, instance, *, load=True, options=None):
        org_id = self._tenant_org_for(instance)
        if org_id is not None:
            owner = getattr(instance, "organization_id", None)
            if owner is not None and int(owner) != org_id:
                raise ValueError("Cannot merge tenant object from another organization")
        return super().merge(instance, load=load, options=options)

    def get(self, entity, ident, **kwargs):
        from .models import TenantMixin
        from .tenancy import SYSTEM_TENANT_MODE, TENANT_MODE

        if not isinstance(entity, type) or not issubclass(entity, TenantMixin):
            return super().get(entity, ident, **kwargs)

        mode = self.info.get("tenant_mode")
        if mode == SYSTEM_TENANT_MODE:
            return super().get(entity, ident, **kwargs)
        if mode != TENANT_MODE:
            raise RuntimeError("Tenant session without organization_id or explicit system mode")
        organization_id = self.info.get("organization_id")
        if organization_id is None:
            raise RuntimeError("Tenant session without organization_id")

        mapper = inspect(entity)
        if isinstance(ident, dict):
            values = tuple(
                ident.get(column.key, ident.get(column.name))
                for column in mapper.primary_key
            )
        elif isinstance(ident, (tuple, list)):
            values = tuple(ident)
        else:
            values = (ident,)
        if len(values) != len(mapper.primary_key):
            raise ValueError("Incorrect number of primary-key values")

        statement = select(entity).where(
            *(column == value for column, value in zip(mapper.primary_key, values)),
            entity.organization_id == int(organization_id),
        )
        for option in kwargs.get("options") or ():
            statement = statement.options(option)
        if kwargs.get("with_for_update"):
            statement = statement.with_for_update(**kwargs["with_for_update"])
        execution_options = dict(kwargs.get("execution_options") or {})
        if kwargs.get("populate_existing"):
            execution_options["populate_existing"] = True
        result = self.scalars(statement, execution_options=execution_options).first()
        return result


def _connect_args(url: str) -> dict:
    if url.startswith("sqlite"):
        return {"check_same_thread": False}
    return {}


def _engine_options(url: str) -> dict:
    options = {"connect_args": _connect_args(url)}
    if url in ("sqlite://", "sqlite:///:memory:"):
        # SQLite en memoria comparte una sola conexion (necesario en tests)
        options["poolclass"] = StaticPool
    elif not url.startswith("sqlite"):
        # PostgreSQL/MySQL: pool acotado para un unico proceso backend. Los
        # schedulers y rate limits en memoria impiden escalar a varios workers.
        options.update(
            pool_pre_ping=True,
            pool_size=settings.db_pool_size,
            max_overflow=settings.db_max_overflow,
            pool_timeout=settings.db_pool_timeout,
            pool_recycle=settings.db_pool_recycle,
        )
    return options


engine = create_engine(
    settings.database_url,
    **_engine_options(settings.database_url),
)

SessionLocal = sessionmaker(
    bind=engine,
    class_=TenantSession,
    autoflush=False,
    expire_on_commit=False,
    # No implicit scope: every caller must opt into tenant or system mode before
    # issuing ORM statements. This keeps new call sites fail-closed.
    info={},
)

# Instalar filtros multi-tenant. No ocultar fallos de instalación: sin los
# listeners, las sesiones de tenant quedarían sin aislamiento.
from .tenancy import install_tenancy

install_tenancy(SessionLocal)


def scoped_get(db: Session, model, ident):
    """get() con filtro por organizacion cuando la sesion es tenant."""
    from .tenancy import get_session_org_id, SYSTEM_TENANT_MODE, TENANT_MODE

    info = getattr(db, "info", None) or {}
    if info.get("tenant_mode") == SYSTEM_TENANT_MODE:
        return db.get(model, ident)
    if info.get("tenant_mode") != TENANT_MODE:
        raise RuntimeError("Tenant session without organization_id or explicit system mode")
    org_id = get_session_org_id(db)
    from .models import TenantMixin

    if isinstance(model, type) and issubclass(model, TenantMixin):
        obj = db.get(model, ident)
        if obj is None or getattr(obj, "organization_id") != int(org_id):
            return None
        return obj
    return db.get(model, ident)


def get_db(request: Request) -> Iterator[Session]:
    """Cede una sesión tenant para requests autenticadas."""
    from . import tenancy

    db = SessionLocal()
    try:
        auth_context = getattr(request.state, "auth_context", None)
        if request.url.path.startswith("/api/auth/"):
            tenancy.set_system_session(db)
        elif auth_context is not None and auth_context.organization_id is not None:
            tenancy.set_tenant_session(db, auth_context.organization_id)
        elif auth_context is not None and getattr(auth_context, "role", None) == "operator":
            tenancy.set_system_session(db)
        else:
            raise RuntimeError("Authenticated request without tenant context")
        yield db
    finally:
        db.close()
