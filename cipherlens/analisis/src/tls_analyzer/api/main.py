"""Aplicacion FastAPI de la plataforma CryptoGuard."""

from __future__ import annotations

import logging
import os
import re
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import inspect, text

from ..alerts_engine import scheduler
from .access_control import authorize_write, operator_path_allowed
from .config import settings
from .db import Base, SessionLocal, engine
from .deps import get_auth_context
from .routers import (
    alerts,
    assets,
    certificates,
    cves,
    dashboard,
    discovery,
    history,
    integrations,
    issues,
    organizations,
    recurring_scans,
    reports,
    scans,
    services,
    settings as settings_router,
    teams,
    vulnerabilities,
)
from .seed import seed
from .services.discovery_service import reap_orphaned_jobs
from .routers import auth, users
from .routers import agent_ingest, agent_tasks, agents
from .routers import crypto_ml

def _add_columns(*columns: tuple[str, str, str]) -> None:
    """Add missing compatibility columns without masking unrelated DDL errors."""
    with engine.connect() as conn:
        inspector = inspect(conn)
        tables = set(inspector.get_table_names())
        is_postgres = conn.dialect.name == "postgresql"
        for table, col, type_ in columns:
            if table not in tables:
                continue
            existing = {item["name"] for item in inspector.get_columns(table)}
            if col in existing:
                continue
            if is_postgres:
                type_ = (
                    type_.replace("DATETIME", "TIMESTAMP")
                    .replace("BOOLEAN DEFAULT 0", "BOOLEAN DEFAULT FALSE")
                    .replace("BOOLEAN DEFAULT 1", "BOOLEAN DEFAULT TRUE")
                )
            conn.exec_driver_sql(f'ALTER TABLE "{table}" ADD COLUMN "{col}" {type_}')
            conn.commit()
            inspector = inspect(conn)


def _remap_roles() -> None:
    """Rol legacy -> canonico. Analyst->lead.

    Nota Parte 6: ``viewer`` paso a ser un rol canonico (menor privilegio,
    de solo lectura), por lo que ya NO se remapea a ``user``.
    """
    with engine.connect() as conn:
        for table in ("users", "api_keys"):
            try:
                conn.exec_driver_sql(
                    f"UPDATE {table} SET role='lead' WHERE role='analyst'"
                )
                conn.commit()
            except Exception:
                pass  # tabla inexistente o role ya migrado


def _migrate_asset_identity_indexes() -> None:
    """Recrea los indices de identidad de assets para incluir el puerto.

    La identidad de un Asset es (organization/agent, ip, hostname, port), asi
    que un mismo host con distintos puertos son activos distintos. Los indices
    viejos no incluian ``port``; ``CREATE INDEX IF NOT EXISTS`` no los
    actualiza, por eso se eliminan para que el CREATE posterior los recree.
    """
    logger = logging.getLogger(__name__)
    with engine.connect() as conn:
        inspector = inspect(conn)
        if "assets" not in inspector.get_table_names():
            return
        index_columns = {
            index["name"]: index.get("column_names") or []
            for index in inspector.get_indexes("assets")
        }
        for name in ("uq_assets_agent_identity", "uq_assets_platform_identity"):
            columns = index_columns.get(name)
            if columns is None or "port" in columns:
                continue
            try:
                conn.exec_driver_sql(f'DROP INDEX IF EXISTS "{name}"')
                conn.commit()
                logger.info("Migrated %s to include port", name)
            except Exception as exc:
                logger.warning("No se pudo migrar indice %s: %s", name, exc)


def _ensure_indexes() -> None:
    """Crea los indices unicos (idempotente)."""
    _migrate_asset_identity_indexes()
    statements = [
        "CREATE INDEX IF NOT EXISTS ix_assets_agent_id ON assets (agent_id)",
        "CREATE INDEX IF NOT EXISTS ix_services_agent_id ON services (agent_id)",
        "CREATE INDEX IF NOT EXISTS ix_scans_agent_id ON scans (agent_id)",
        "CREATE INDEX IF NOT EXISTS ix_discovery_jobs_agent_id ON discovery_jobs (agent_id)",
        "CREATE INDEX IF NOT EXISTS ix_scans_task_id ON scans (task_id)",
        "CREATE INDEX IF NOT EXISTS ix_discovery_jobs_task_id ON discovery_jobs (task_id)",
        "CREATE INDEX IF NOT EXISTS ix_recurring_scans_agent_id ON recurring_scans (agent_id)",
        ("CREATE UNIQUE INDEX IF NOT EXISTS uq_scans_task_id "
         "ON scans (task_id) WHERE task_id IS NOT NULL"),
        ("CREATE UNIQUE INDEX IF NOT EXISTS uq_discovery_jobs_task_id "
         "ON discovery_jobs (task_id) WHERE task_id IS NOT NULL"),
        ("CREATE UNIQUE INDEX IF NOT EXISTS uq_services_agent_host_port "
         "ON services (agent_id, host, port) WHERE agent_id IS NOT NULL"),
        ("CREATE UNIQUE INDEX IF NOT EXISTS uq_services_platform_host_port "
         "ON services (organization_id, host, port) WHERE agent_id IS NULL"),
        ("CREATE UNIQUE INDEX IF NOT EXISTS uq_assets_agent_identity "
         "ON assets (agent_id, ip_address, hostname, port) WHERE agent_id IS NOT NULL"),
        ("CREATE UNIQUE INDEX IF NOT EXISTS uq_assets_platform_identity "
         "ON assets (organization_id, ip_address, hostname, port) WHERE agent_id IS NULL"),
        ("CREATE UNIQUE INDEX IF NOT EXISTS uq_scans_agent_client "
         "ON scans (agent_id, client_scan_id)"),
        ("CREATE UNIQUE INDEX IF NOT EXISTS uq_discovery_jobs_agent_client "
         "ON discovery_jobs (agent_id, client_job_id)"),
        "CREATE INDEX IF NOT EXISTS ix_users_organization_id ON users (organization_id)",
        "CREATE INDEX IF NOT EXISTS ix_agents_organization_id ON agents (organization_id)",
        "CREATE INDEX IF NOT EXISTS ix_services_organization_id ON services (organization_id)",
        "CREATE INDEX IF NOT EXISTS ix_assets_organization_id ON assets (organization_id)",
        "CREATE INDEX IF NOT EXISTS ix_certificates_organization_id ON certificates (organization_id)",
        "CREATE INDEX IF NOT EXISTS ix_scans_organization_id ON scans (organization_id)",
        "CREATE INDEX IF NOT EXISTS ix_discovery_jobs_organization_id ON discovery_jobs (organization_id)",
        "CREATE INDEX IF NOT EXISTS ix_issues_organization_id ON issues (organization_id)",
        "CREATE INDEX IF NOT EXISTS ix_teams_organization_id ON teams (organization_id)",
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_teams_org_name ON teams (organization_id, name)",
        "CREATE INDEX IF NOT EXISTS ix_findings_organization_id ON findings (organization_id)",
        "CREATE INDEX IF NOT EXISTS ix_team_members_organization_id ON team_members (organization_id)",
        "CREATE INDEX IF NOT EXISTS ix_issue_history_organization_id ON issue_history (organization_id)",
        "CREATE INDEX IF NOT EXISTS ix_discovery_results_organization_id ON discovery_results (organization_id)",
        "CREATE INDEX IF NOT EXISTS ix_api_keys_organization_id ON api_keys (organization_id)",
        "CREATE INDEX IF NOT EXISTS ix_integrations_organization_id ON integrations (organization_id)",
        "CREATE INDEX IF NOT EXISTS ix_scan_cve_matches_organization_id ON scan_cve_matches (organization_id)",
        ("CREATE INDEX IF NOT EXISTS ix_agent_tasks_agent_status "
         "ON agent_tasks (agent_id, status, created_at)"),
        ("CREATE INDEX IF NOT EXISTS ix_agent_tasks_org_status "
         "ON agent_tasks (organization_id, status, created_at)"),
    ]
    with engine.connect() as conn:
        for stmt in statements:
            try:
                conn.exec_driver_sql(stmt)
                conn.commit()
            except Exception as exc:
                logging.getLogger(__name__).warning(
                    "No se pudo crear indice: %s (%s)", stmt, exc
                )


def _backfill_tenant_data(db, default_org_id: int) -> None:
    """Fill organization ownership from agent/parent links, then the legacy org."""
    from .models import Organization

    organizations = db.query(Organization).order_by(Organization.id).all()
    used_slugs: set[str] = set()
    for organization in organizations:
        base_slug = re.sub(r"[^a-z0-9]+", "-", organization.name.lower()).strip("-")
        base_slug = (base_slug or f"org-{organization.id}")[:54]
        slug = organization.slug or base_slug
        if slug in used_slugs:
            slug = f"{base_slug[:54]}-{organization.id}"
        used_slugs.add(slug)
        organization.slug = slug
        organization.status = organization.status or "active"
        organization.ai_mode = organization.ai_mode or "template"
        organization.max_agents = (
            organization.max_agents or settings.default_max_agents
        )
        organization.max_cloud_scans_per_hour = (
            organization.max_cloud_scans_per_hour
            or settings.default_max_cloud_scans_per_hour
        )
        organization.max_recurring_scans = (
            organization.max_recurring_scans
            or settings.default_max_recurring_scans
        )
    db.flush()

    # Agent data belongs to the organization that owns the agent. Parent-owned
    # rows inherit from their root; a legacy orphan falls back to the default.
    statements = (
        "UPDATE assets SET organization_id=(SELECT organization_id FROM agents WHERE agents.id=assets.agent_id) WHERE organization_id IS NULL AND agent_id IS NOT NULL",
        "UPDATE services SET organization_id=(SELECT organization_id FROM agents WHERE agents.id=services.agent_id) WHERE organization_id IS NULL AND agent_id IS NOT NULL",
        "UPDATE scans SET organization_id=(SELECT organization_id FROM agents WHERE agents.id=scans.agent_id) WHERE organization_id IS NULL AND agent_id IS NOT NULL",
        "UPDATE discovery_jobs SET organization_id=(SELECT organization_id FROM agents WHERE agents.id=discovery_jobs.agent_id) WHERE organization_id IS NULL AND agent_id IS NOT NULL",
        "UPDATE api_keys SET organization_id=(SELECT organization_id FROM users WHERE users.id=api_keys.user_id) WHERE organization_id IS NULL AND user_id IS NOT NULL",
        "UPDATE api_keys SET organization_id=(SELECT organization_id FROM agents WHERE agents.api_key_id=api_keys.id) WHERE organization_id IS NULL AND EXISTS (SELECT 1 FROM agents WHERE agents.api_key_id=api_keys.id)",
        "UPDATE findings SET organization_id=(SELECT organization_id FROM scans WHERE scans.id=findings.scan_id) WHERE organization_id IS NULL",
        "UPDATE team_members SET organization_id=(SELECT organization_id FROM teams WHERE teams.id=team_members.team_id) WHERE organization_id IS NULL",
        "UPDATE issue_history SET organization_id=(SELECT organization_id FROM issues WHERE issues.id=issue_history.issue_id) WHERE organization_id IS NULL",
        "UPDATE discovery_results SET organization_id=(SELECT organization_id FROM discovery_jobs WHERE discovery_jobs.id=discovery_results.discovery_job_id) WHERE organization_id IS NULL",
        "UPDATE scan_cve_matches SET organization_id=(SELECT organization_id FROM scans WHERE scans.id=scan_cve_matches.scan_id) WHERE organization_id IS NULL",
    )
    tables = set(inspect(db.connection()).get_table_names())
    for statement in statements:
        match = re.match(r"UPDATE\s+([a-z_]+)", statement, re.IGNORECASE)
        if match and match.group(1) in tables:
            db.execute(text(statement))
    tenant_tables = (
        "users", "teams", "issues", "agents", "services", "assets",
        "certificates", "scans", "findings", "team_members",
        "issue_history", "discovery_jobs", "discovery_results",
        "recurring_scans", "alerts", "alert_thresholds",
        "compliance_windows", "api_keys", "integrations",
        "audit_logs", "refresh_tokens", "scan_cve_matches",
        "agent_tasks",
    )
    for table in tenant_tables:
        if table in tables:
            db.execute(
                text(
                    f'UPDATE "{table}" SET organization_id=:org_id '
                    "WHERE organization_id IS NULL"
                ),
                {"org_id": default_org_id},
            )


def _assert_tenant_parent_consistency() -> None:
    """Fail startup if a tenant row points at a parent owned by another org.

    The ORM filter protects reads and the flush hook protects writes, but legacy
    data can still contain parent/child pairs with different owners. Checking
    every tenant-to-tenant foreign key after backfill keeps those rows from
    becoming a hidden cross-tenant reference.
    """
    from .models import TenantMixin
    from .db import Base

    tenant_tables = {
        mapper.local_table.name
        for mapper in Base.registry.mappers
        if issubclass(mapper.class_, TenantMixin)
    }
    violations: list[str] = []
    with engine.connect() as conn:
        present = set(inspect(conn).get_table_names())
        for table_name in sorted(tenant_tables & present):
            table = Base.metadata.tables.get(table_name)
            if table is None or "organization_id" not in table.columns:
                continue
            null_count = conn.execute(
                text(f'SELECT COUNT(*) FROM "{table_name}" '
                     "WHERE organization_id IS NULL")
            ).scalar_one()
            if null_count:
                violations.append(f"{table_name}: {null_count} rows without owner")
            for constraint in table.foreign_key_constraints:
                if len(constraint.elements) != 1:
                    continue
                element = next(iter(constraint.elements))
                parent_table = element.column.table.name
                if parent_table not in tenant_tables or parent_table not in present:
                    continue
                child_column = element.parent.name
                parent_column = element.column.name
                count = conn.execute(
                    text(
                        f'SELECT COUNT(*) FROM "{table_name}" child '
                        f'JOIN "{parent_table}" parent '
                        f'ON child."{child_column}" = parent."{parent_column}" '
                        "WHERE child.organization_id <> parent.organization_id"
                    )
                ).scalar_one()
                if count:
                    violations.append(
                        f"{table_name}.{child_column} -> "
                        f"{parent_table}.{parent_column}: {count} cross-org rows"
                    )
    if violations:
        raise RuntimeError(
            "Tenant parent-child coherence check failed: " + "; ".join(violations)
        )


def _enforce_tenant_ownership() -> None:
    """Enforce ownership on legacy schemas upgraded by startup compatibility DDL.

    Alembic adds native NOT NULL/FK constraints. SQLite cannot alter those
    constraints in place, so the create_all + _add_columns path installs
    equivalent insert/update/delete guards after backfill.
    """
    tenant_tables = (
        "users", "teams", "issues", "agents", "services", "assets",
        "certificates", "scans", "findings", "team_members", "issue_history",
        "discovery_jobs", "discovery_results", "recurring_scans", "alerts",
        "alert_thresholds", "compliance_windows", "api_keys", "integrations",
        "audit_logs", "refresh_tokens", "scan_cve_matches",
        "agent_tasks",
    )
    with engine.begin() as conn:
        inspector = inspect(conn)
        present_tables = set(inspector.get_table_names())
        applicable = [
            table for table in tenant_tables
            if table in present_tables
            and "organization_id" in {
                column["name"] for column in inspector.get_columns(table)
            }
        ]
        if conn.dialect.name == "sqlite":
            for table in applicable:
                for action in ("INSERT", "UPDATE"):
                    trigger = f"trg_{table}_organization_guard_{action.lower()}"
                    conn.execute(text(
                        f'CREATE TRIGGER IF NOT EXISTS "{trigger}" '
                        f'BEFORE {action} ON "{table}" '
                        "WHEN NEW.organization_id IS NULL OR NOT EXISTS "
                        "(SELECT 1 FROM organizations "
                        "WHERE id=NEW.organization_id) "
                        "BEGIN SELECT RAISE(ABORT, "
                        "'tenant organization_id is required and must exist'); END"
                    ))
            existence_checks = " OR ".join(
                f'EXISTS (SELECT 1 FROM "{table}" '
                "WHERE organization_id=OLD.id)"
                for table in applicable
            )
            conn.execute(text(
                "CREATE TRIGGER IF NOT EXISTS trg_organizations_tenant_guard_delete "
                "BEFORE DELETE ON organizations "
                f"WHEN {existence_checks} "
                "BEGIN SELECT RAISE(ABORT, "
                "'organization still owns tenant data'); END"
            ))
            return

        if conn.dialect.name == "postgresql":
            for table in applicable:
                column = next(
                    column for column in inspect(conn).get_columns(table)
                    if column["name"] == "organization_id"
                )
                if column["nullable"]:
                    conn.execute(text(
                        f'ALTER TABLE "{table}" ALTER COLUMN organization_id '
                        "SET NOT NULL"
                    ))
                has_fk = any(
                    fk.get("constrained_columns") == ["organization_id"]
                    and fk.get("referred_table") == "organizations"
                    for fk in inspect(conn).get_foreign_keys(table)
                )
                if not has_fk:
                    constraint = f"fk_{table}_organization_id"
                    conn.execute(text(
                        f'ALTER TABLE "{table}" ADD CONSTRAINT "{constraint}" '
                        "FOREIGN KEY (organization_id) REFERENCES organizations(id)"
                    ))
            return

        raise RuntimeError(
            "Tenant compatibility enforcement supports SQLite and PostgreSQL; "
            f"got {conn.dialect.name}"
        )


def _deduplicate_legacy_assets() -> None:
    """Merge duplicate legacy inventory identities before unique indexes exist."""
    with engine.begin() as conn:
        inspector = inspect(conn)
        if "assets" not in inspector.get_table_names():
            return
        rows = conn.execute(text(
            "SELECT id, organization_id, agent_id, ip_address, hostname, port, source, "
            "is_internal, first_seen, last_seen FROM assets ORDER BY id"
        )).mappings().all()
        grouped = {}
        for row in rows:
            if row["agent_id"] is None:
                identity = (
                    "organization", row["organization_id"],
                    row["ip_address"], row["hostname"], row["port"],
                )
            else:
                identity = (
                    "agent", row["agent_id"], row["ip_address"], row["hostname"],
                    row["port"],
                )
            grouped.setdefault(identity, []).append(row)

        references = []
        for table in inspector.get_table_names():
            if table == "assets":
                continue
            for foreign_key in inspector.get_foreign_keys(table):
                if foreign_key.get("referred_table") != "assets":
                    continue
                for local_column, remote_column in zip(
                    foreign_key.get("constrained_columns") or (),
                    foreign_key.get("referred_columns") or (),
                ):
                    if remote_column == "id":
                        references.append((table, local_column))
        if "discovery_results" in inspector.get_table_names() and (
            "matched_asset_id" in {
                column["name"] for column in inspector.get_columns("discovery_results")
            }
        ):
            references.append(("discovery_results", "matched_asset_id"))

        for duplicates in grouped.values():
            if len(duplicates) < 2:
                continue
            canonical = duplicates[0]
            duplicate_ids = [row["id"] for row in duplicates[1:]]
            first_seen = [row["first_seen"] for row in duplicates if row["first_seen"]]
            last_seen = [row["last_seen"] for row in duplicates if row["last_seen"]]
            conn.execute(
                text(
                    "UPDATE assets SET source=:source, is_internal=:is_internal, "
                    "first_seen=:first_seen, last_seen=:last_seen WHERE id=:id"
                ),
                {
                    "source": (
                        "manual"
                        if any(row["source"] == "manual" for row in duplicates)
                        else canonical["source"]
                    ),
                    "is_internal": any(row["is_internal"] for row in duplicates),
                    "first_seen": min(first_seen) if first_seen else None,
                    "last_seen": max(last_seen) if last_seen else None,
                    "id": canonical["id"],
                },
            )
            parameters = {
                "canonical_id": canonical["id"],
                **{
                    f"duplicate_{index}": duplicate_id
                    for index, duplicate_id in enumerate(duplicate_ids)
                },
            }
            placeholders = ", ".join(
                ":duplicate_" + str(index)
                for index in range(len(duplicate_ids))
            )
            for table, local_column in references:
                conn.execute(
                    text(
                        f'UPDATE "{table}" SET "{local_column}"=:canonical_id '
                        f'WHERE "{local_column}" IN ({placeholders})'
                    ),
                    parameters,
                )
            conn.execute(
                text(
                    "DELETE FROM assets WHERE id IN ("
                    + placeholders
                    + ")"
                ),
                {
                    f"duplicate_{index}": duplicate_id
                    for index, duplicate_id in enumerate(duplicate_ids)
                },
            )


_COMPATIBILITY_COLUMNS = (
    ("scan_cve_matches", "keyword", "VARCHAR(200)"),
    ("scans", "origin", "VARCHAR(20)"),
    ("scans", "recurring_scan_id", "INTEGER"),
    ("scans", "task_id", "VARCHAR(36)"),
    # Parte 2: ownership / issues
    ("alerts", "related_issue_id", "VARCHAR(36)"),
    ("certificates", "owner_user_id", "VARCHAR(36)"),
    ("certificates", "owner_team_id", "VARCHAR(36)"),
    ("findings", "issue_id", "VARCHAR(36)"),
    ("services", "default_owner_user_id", "VARCHAR(36)"),
    ("services", "default_owner_team_id", "VARCHAR(36)"),
    # Roles: marca de lider de equipo
    ("team_members", "is_lead", "BOOLEAN DEFAULT 0"),
    # API keys: owner + rol + expiracion (refactor de roles)
    ("api_keys", "user_id", "VARCHAR(36)"),
    ("api_keys", "role", "VARCHAR(20) DEFAULT 'lead'"),
    ("api_keys", "expires_at", "DATETIME"),
    # Parte 5: agentes on-premise
    ("assets", "agent_id", "VARCHAR(36)"),
    # Inventario de assets: identidad ip + hostname + puerto
    ("assets", "port", "INTEGER DEFAULT 443"),
    ("assets", "service", "VARCHAR(128) DEFAULT ''"),
    ("assets", "tls_version", "VARCHAR(32)"),
    ("assets", "scope", "VARCHAR(20) DEFAULT 'external'"),
    ("assets", "inventory_status", "VARCHAR(20) DEFAULT 'shadow_it'"),
    ("services", "agent_id", "VARCHAR(36)"),
    ("scans", "agent_id", "VARCHAR(36)"),
    ("scans", "client_scan_id", "VARCHAR(64)"),
    ("scans", "upload_level", "VARCHAR(20)"),
    ("scans", "rules_version", "VARCHAR(32)"),
    ("discovery_jobs", "agent_id", "VARCHAR(36)"),
    ("discovery_jobs", "client_job_id", "VARCHAR(64)"),
    ("discovery_jobs", "resolved_targets", "JSON"),
    ("discovery_jobs", "task_id", "VARCHAR(36)"),
    ("recurring_scans", "agent_id", "VARCHAR(36)"),
    # M1: multi-tenant
    ("organizations", "slug", "VARCHAR(64)"),
    ("organizations", "status", "VARCHAR(16) DEFAULT 'active'"),
    ("organizations", "ai_mode", "VARCHAR(16) DEFAULT 'template'"),
    ("organizations", "max_agents", "INTEGER DEFAULT 0"),
    ("organizations", "max_cloud_scans_per_hour", "INTEGER DEFAULT 0"),
    ("organizations", "max_recurring_scans", "INTEGER DEFAULT 0"),
    ("organizations", "sla_days_critical", "INTEGER"),
    ("organizations", "sla_days_high", "INTEGER"),
    ("organizations", "sla_days_medium", "INTEGER"),
    ("users", "must_change_password", "BOOLEAN DEFAULT 0"),
    ("users", "organization_id", "INTEGER"),
    ("teams", "organization_id", "INTEGER"),
    ("team_members", "organization_id", "INTEGER"),
    ("issues", "organization_id", "INTEGER"),
    ("issue_history", "organization_id", "INTEGER"),
    ("agents", "organization_id", "INTEGER"),
    ("agents", "reported_capabilities", "TEXT"),
    ("services", "organization_id", "INTEGER"),
    ("assets", "organization_id", "INTEGER"),
    ("certificates", "organization_id", "INTEGER"),
    ("scans", "organization_id", "INTEGER"),
    ("findings", "organization_id", "INTEGER"),
    ("discovery_jobs", "organization_id", "INTEGER"),
    ("discovery_results", "organization_id", "INTEGER"),
    ("recurring_scans", "organization_id", "INTEGER"),
    ("alerts", "organization_id", "INTEGER"),
    ("alert_thresholds", "organization_id", "INTEGER"),
    ("compliance_windows", "organization_id", "INTEGER"),
    ("api_keys", "organization_id", "INTEGER"),
    ("integrations", "organization_id", "INTEGER"),
    ("scan_cve_matches", "organization_id", "INTEGER"),
    ("audit_logs", "organization_id", "INTEGER"),
    ("refresh_tokens", "organization_id", "INTEGER"),
)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    logging.basicConfig(
        level=getattr(logging, os.getenv("LOG_LEVEL", "INFO").upper(), logging.INFO),
        format="%(asctime)s %(levelname)-8s %(name)s  %(message)s",
        datefmt="%H:%M:%S",
    )
    # Permitir enfocar el DEBUG solo en el modulo de AI sin inundar todo.
    ai_level = getattr(logging, os.getenv("AI_LOG_LEVEL", "").upper(), None)
    if ai_level is not None:
        logging.getLogger("tls_analyzer.ai_recommendations").setLevel(ai_level)
    Base.metadata.create_all(engine)

    # Auto-migration: add missing columns to existing tables
    _add_columns(*_COMPATIBILITY_COLUMNS)
    _remap_roles()

    db = SessionLocal()
    try:
        from . import tenancy
        # Backfill organization si falta
        from . import models

        tenancy.set_system_session(db)
        # Crear org default si no existe
        org = db.query(models.Organization).order_by(models.Organization.id).first()
        if org is None:
            org = models.Organization(name="Default Org", slug="default", status="active")
            db.add(org)
            db.commit()
            db.refresh(org)
        _backfill_tenant_data(db, org.id)
        db.commit()
        _deduplicate_legacy_assets()
        _assert_tenant_parent_consistency()
        _enforce_tenant_ownership()
        _ensure_indexes()
        # Seed/default admin writes are explicitly scoped to the legacy org.
        tenancy.set_tenant_session(db, org.id)
        # Integridad básica

        seed(db)
        from .routers.auth import ensure_bootstrap_admin

        ensure_bootstrap_admin(db)
        db.commit()
    finally:
        db.close()
    # Un proceso anterior pudo morir a mitad de un scan: esos jobs quedaron en
    # 'running' sin hilo que los termine. Se cierran antes de aceptar trabajo nuevo.
    reap_orphaned_jobs()
    scheduler.start()
    yield
    scheduler.shutdown()


def create_app() -> FastAPI:
    app = FastAPI(
        title="CryptoGuard TLS Analysis API",
        version="1.0.0",
        lifespan=lifespan,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=settings.cors_allow_credentials,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.middleware("http")
    async def _security_headers(request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        if settings.cookie_secure:
            response.headers.setdefault(
                "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
            )
        return response

    # Auth global por defecto (default-deny). Solo se salvan rutas publicas.
    public_paths = {"/", "/health"}
    if settings.expose_docs:
        public_paths.update({"/docs", "/redoc", "/openapi.json"})

    @app.middleware("http")
    async def _limit_agent_body(request, call_next):
        # Limite de tamano del cuerpo para la ingesta del agente (Parte 5.4).
        if request.url.path.startswith("/api/agent/ingest"):
            cl = request.headers.get("content-length")
            if cl and cl.isdigit() and int(cl) > settings.agent_ingest_max_bytes:
                return JSONResponse(
                    {"detail": "Payload too large"}, status_code=413
                )
        return await call_next(request)

    @app.middleware("http")
    async def _global_auth(request, call_next):
        if request.method == "OPTIONS":
            response = await call_next(request)
            return response
        path = request.url.path
        if settings.disable_api_auth:
            try:
                request.state.auth_context = get_auth_context(
                    x_api_key=request.headers.get("X-API-Key"),
                    authorization=request.headers.get("Authorization"),
                )
                if (
                    request.state.auth_context.role == "operator"
                    and not operator_path_allowed(path)
                ):
                    return JSONResponse(
                        {
                            "detail": (
                                "Operator credentials are restricted to "
                                "/api/organizations"
                            )
                        },
                        status_code=403,
                    )
                authorize_write(
                    request.state.auth_context.role, request.method, path
                )
            except HTTPException as exc:
                return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)
            return await call_next(request)
        if path.startswith("/api/auth/"):
            return await call_next(request)
        if path in public_paths:
            return await call_next(request)
        try:
            ctx = get_auth_context(
                x_api_key=request.headers.get("X-API-Key"),
                authorization=request.headers.get("Authorization"),
            )
        except HTTPException as exc:
            return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)
        request.state.auth_context = ctx
        # Una key de agente solo puede acceder a los endpoints de ingesta.
        if ctx.role == "agent" and not path.startswith("/api/agent/"):
            return JSONResponse(
                {"detail": "Agent credentials are restricted to /api/agent/*"},
                status_code=403,
            )
        if ctx.role == "operator" and not operator_path_allowed(path):
            return JSONResponse(
                {
                    "detail": (
                        "Operator credentials are restricted to /api/organizations"
                    )
                },
                status_code=403,
            )
        try:
            authorize_write(ctx.role, request.method, path)
        except HTTPException as exc:
            return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)
        return await call_next(request)

    app.include_router(scans.router)
    app.include_router(crypto_ml.router)
    app.include_router(history.router)
    app.include_router(certificates.router)
    app.include_router(assets.router)
    app.include_router(services.router)
    app.include_router(dashboard.router)
    app.include_router(vulnerabilities.router)
    app.include_router(alerts.router)
    app.include_router(discovery.router)
    app.include_router(integrations.router)
    app.include_router(settings_router.router)
    app.include_router(cves.router)
    app.include_router(recurring_scans.router)
    app.include_router(auth.router)
    app.include_router(users.router)
    app.include_router(issues.router)
    app.include_router(teams.router)
    app.include_router(agents.router)
    app.include_router(agent_ingest.router)
    app.include_router(agent_tasks.router)
    app.include_router(reports.router)
    app.include_router(organizations.router)

    @app.get("/", include_in_schema=False)
    def root() -> dict:
        return {
            "service": "CryptoGuard TLS Analysis API",
            "docs": "/docs",
            "health": "/health",
            "api": "/api",
        }

    @app.get("/health", tags=["system"])
    def health() -> dict:
        return {"status": "ok", "service": "cryptoguard-api"}

    return app


app = create_app()
