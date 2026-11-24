"""Configuracion global de pytest: isola la DB de la API y desactiva red/alertas."""

import os

import pytest
from sqlalchemy import text

os.environ["DATABASE_URL"] = "sqlite://"
os.environ.setdefault("ENV", "dev")
os.environ.setdefault("ALERTS_ENABLED", "false")
os.environ.setdefault("DISABLE_API_AUTH", "true")
os.environ.setdefault("AI_PROVIDER", "template")

from tls_analyzer.api import models  # noqa: E402,F401
from tls_analyzer.api.db import Base, SessionLocal, engine  # noqa: E402
from tls_analyzer.api.tenancy import set_system_session  # noqa: E402

def _reset_fk_create_rules() -> None:
    """Deshace la marca que ``AddConstraint`` deja en FKs cíclicas compartidas.

    Cuando ``create_all`` corre sobre un dialecto con soporte de ALTER
    (PostgreSQL), las FKs de tablas que forman un ciclo
    (``services`` <-> ``certificates``) se emiten por separado con
    ``AddConstraint``. Ese constructor asigna ``_create_rule=False`` al
    ``ForeignKeyConstraint`` compartido de ``Base.metadata`` y no lo restaura.
    Un ``create_all`` posterior sobre SQLite con el mismo metadata omite
    entonces *todas* las FKs de esas tablas. Resetear el atributo interno deja
    el metadata en un estado determinista, independiente del orden de tests.
    """

    for table in Base.metadata.tables.values():
        for constraint in table.foreign_key_constraints:
            if constraint._create_rule is not None:
                constraint._create_rule = None


Base.metadata.create_all(engine)
_reset_fk_create_rules()

organization_id = None


def _ensure_default_organization() -> None:
    """Keep legacy single-tenant tests scoped to the default organization."""
    global organization_id
    db = SessionLocal()
    try:
        set_system_session(db)
        org = db.query(models.Organization).order_by(models.Organization.id).first()
        if org is None:
            org = models.Organization(name="Default Org", slug="default", status="active")
            db.add(org)
            db.commit()
            db.refresh(org)
        organization_id = org.id
    finally:
        db.close()
    SessionLocal.configure(
        info={"tenant_mode": "tenant", "organization_id": organization_id}
    )


def reset_database() -> None:
    """Empty the shared test database without relying on FK-aware DROP order."""
    if engine.dialect.name == "sqlite":
        Base.metadata.drop_all(engine)
        Base.metadata.create_all(engine)
    else:
        tables = ", ".join(f'"{name}"' for name in Base.metadata.tables)
        with engine.begin() as conn:
            conn.execute(text(f"TRUNCATE TABLE {tables} RESTART IDENTITY CASCADE"))
    _ensure_default_organization()


_ensure_default_organization()


@pytest.fixture(autouse=True)
def _isolate_postgres_tests():
    """Start every test from a deterministic database and metadata state."""
    _reset_fk_create_rules()
    if engine.dialect.name != "postgresql":
        yield
        return
    reset_database()
    yield


@pytest.fixture
def clean_db_after():
    yield
    reset_database()
