"""Paridad del grafo tenant entre Alembic y create_all."""

from __future__ import annotations

from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import DBAPIError

from tls_analyzer.api import main, models
from tls_analyzer.api.db import Base, SessionLocal
from tls_analyzer.api.tenancy import set_system_session, set_tenant_session


ROOT = Path(__file__).resolve().parents[1]
LEGACY_REVISION = "a3f1c9d27b64"

ORG_A = "legacy-org-a"
ORG_B = "legacy-org-b"
KEY_B = "legacy-key-b"
AGENT_B = "legacy-agent-b"
ASSET_A = "legacy-asset-a"
ASSET_B = "legacy-asset-b"
SERVICE_A = "legacy-service-a"
SERVICE_B = "legacy-service-b"
SCAN_A = "legacy-scan-a"
SCAN_B = "legacy-scan-b"
FINDING_A = "legacy-finding-a"
FINDING_B = "legacy-finding-b"
ISSUE_A = "legacy-issue-a"
ISSUE_B = "legacy-issue-b"
HISTORY_A = "legacy-history-a"
HISTORY_B = "legacy-history-b"


def _upgrade(url: str, revision: str = "head") -> None:
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, revision)


def _tenant_tables() -> set[str]:
    return {
        mapper.local_table.name
        for mapper in Base.registry.mappers
        if issubclass(mapper.class_, models.TenantMixin)
    }


def _snapshot(engine) -> dict[str, tuple[bool, set[tuple[str, str, str]]]]:
    inspector = inspect(engine)
    present = set(inspector.get_table_names())
    tenant = _tenant_tables() & present
    snapshot = {}
    for table in sorted(tenant):
        columns = {column["name"]: column for column in inspector.get_columns(table)}
        organization = columns.get("organization_id")
        assert organization is not None, f"{table} has no organization_id"
        foreign_keys = {
            (
                foreign_key["constrained_columns"][0],
                foreign_key["referred_table"],
                foreign_key["referred_columns"][0],
            )
            for foreign_key in inspector.get_foreign_keys(table)
            if foreign_key["referred_table"] in tenant
        }
        snapshot[table] = (bool(organization["nullable"]), foreign_keys)
    return snapshot


def test_alembic_and_create_all_tenant_schema_parity(tmp_path):
    alembic_url = f"sqlite:///{(tmp_path / 'alembic.db').as_posix()}"
    create_all_url = f"sqlite:///{(tmp_path / 'create_all.db').as_posix()}"

    _upgrade(alembic_url)
    create_all_engine = create_engine(create_all_url)
    try:
        Base.metadata.create_all(create_all_engine)
        alembic_engine = create_engine(alembic_url)
        try:
            assert _snapshot(alembic_engine) == _snapshot(create_all_engine)
        finally:
            alembic_engine.dispose()
    finally:
        create_all_engine.dispose()


def test_alembic_organization_sla_columns_match_models(tmp_path):
    alembic_url = f"sqlite:///{(tmp_path / 'sla.db').as_posix()}"
    _upgrade(alembic_url)
    engine = create_engine(alembic_url)
    try:
        columns = {
            column["name"]: column
            for column in inspect(engine).get_columns("organizations")
        }
        for name in (
            "sla_days_critical",
            "sla_days_high",
            "sla_days_medium",
        ):
            assert name in columns
            assert columns[name]["nullable"] is True
            assert models.Organization.__table__.columns[name].nullable is True
    finally:
        engine.dispose()


def _new_session(engine):
    return SessionLocal.class_(
        bind=engine,
        autoflush=False,
        expire_on_commit=False,
        info={},
    )


def _insert(conn, table: str, **values) -> None:
    """Insert a legacy-compatible row, filling required columns generically."""
    columns = {column["name"]: column for column in inspect(conn).get_columns(table)}
    row = {
        name: value for name, value in values.items() if name in columns
    }
    for name, column in columns.items():
        if name in row or name == "id":
            continue
        if column["nullable"] or column.get("default") is not None:
            continue
        type_name = type(column["type"]).__name__.upper()
        if "INT" in type_name:
            row[name] = 0
        elif "BOOL" in type_name:
            row[name] = False
        elif "DATETIME" in type_name or "DATE" in type_name:
            row[name] = "2024-01-01 00:00:00"
        elif "JSON" in type_name:
            row[name] = "{}"
        else:
            row[name] = ""
    names = ", ".join(f'"{name}"' for name in row)
    params = ", ".join(f":{name}" for name in row)
    conn.execute(text(f'INSERT INTO "{table}" ({names}) VALUES ({params})'), row)


def _create_organization(conn, name: str, slug: str, full_schema: bool) -> int:
    values = {"name": name}
    if full_schema:
        values.update(
            slug=slug,
            status="active",
            ai_mode="template",
            max_agents=0,
            max_cloud_scans_per_hour=0,
            max_recurring_scans=0,
        )
    _insert(conn, "organizations", **values)
    return conn.execute(
        text("SELECT id FROM organizations WHERE name=:name"), {"name": name}
    ).scalar_one()


def _seed_rows(conn, org_a: int, org_b: int, include_org: bool) -> None:
    def owner(organization_id: int) -> dict:
        return {"organization_id": organization_id} if include_org else {}

    _insert(
        conn,
        "api_keys",
        id=KEY_B,
        name="Legacy agent key",
        key_hash="legacy-key-hash-b",
        prefix="legacyb",
        role="agent",
        revoked=False,
        **owner(org_b),
    )
    _insert(
        conn,
        "agents",
        id=AGENT_B,
        name="Legacy agent B",
        site_label="Site B",
        status="active",
        api_key_id=KEY_B,
        **owner(org_b),
    )
    _insert(
        conn,
        "assets",
        id=ASSET_A,
        ip_address="10.10.0.1",
        hostname="a.example.test",
        source="manual",
        is_internal=True,
        agent_id=None,
        **owner(org_a),
    )
    _insert(
        conn,
        "assets",
        id=ASSET_B,
        ip_address="10.20.0.1",
        hostname="b.example.test",
        source="agent",
        is_internal=True,
        agent_id=AGENT_B,
        **owner(org_b),
    )
    _insert(
        conn,
        "services",
        id=SERVICE_A,
        asset_id=ASSET_A,
        host="a.example.test",
        ip_address="10.10.0.1",
        port=443,
        scope="external",
        **owner(org_a),
    )
    _insert(
        conn,
        "services",
        id=SERVICE_B,
        asset_id=ASSET_B,
        host="b.example.test",
        ip_address="10.20.0.1",
        port=443,
        scope="internal",
        agent_id=AGENT_B,
        **owner(org_b),
    )
    _insert(
        conn,
        "scans",
        id=SCAN_A,
        service_id=SERVICE_A,
        origin="manual",
        host="a.example.test",
        port=443,
        status="completed",
        target="a.example.test:443",
        **owner(org_a),
    )
    _insert(
        conn,
        "scans",
        id=SCAN_B,
        service_id=SERVICE_B,
        origin="agent",
        host="b.example.test",
        port=443,
        status="completed",
        target="b.example.test:443",
        agent_id=AGENT_B,
        client_scan_id="legacy-client-scan-b",
        **owner(org_b),
    )
    _insert(
        conn,
        "findings",
        id=FINDING_A,
        scan_id=SCAN_A,
        rule_id="LEGACY-A",
        title="Legacy finding A",
        severity="medium",
        **owner(org_a),
    )
    _insert(
        conn,
        "findings",
        id=FINDING_B,
        scan_id=SCAN_B,
        rule_id="LEGACY-B",
        title="Legacy finding B",
        severity="high",
        **owner(org_b),
    )
    _insert(
        conn,
        "issues",
        id=ISSUE_A,
        service_id=SERVICE_A,
        source_document="80052",
        rule_id="LEGACY-A",
        title="Legacy issue A",
        severity="medium",
        **owner(org_a),
    )
    _insert(
        conn,
        "issues",
        id=ISSUE_B,
        service_id=SERVICE_B,
        source_document="80052",
        rule_id="LEGACY-B",
        title="Legacy issue B",
        severity="high",
        **owner(org_b),
    )
    _insert(
        conn,
        "issue_history",
        id=HISTORY_A,
        issue_id=ISSUE_A,
        actor_type="system",
        event_type="created",
        **owner(org_a),
    )
    _insert(
        conn,
        "issue_history",
        id=HISTORY_B,
        issue_id=ISSUE_B,
        actor_type="system",
        event_type="created",
        **owner(org_b),
    )


def _seed_legacy(engine) -> tuple[int, int]:
    with engine.begin() as conn:
        org_a = _create_organization(conn, "Org A", "org-a", full_schema=False)
        org_b = _create_organization(conn, "Org B", "org-b", full_schema=False)
        _seed_rows(conn, org_a, org_b, include_org=False)
    return org_a, org_b


def _seed_fresh(engine) -> tuple[int, int]:
    with engine.begin() as conn:
        org_a = _create_organization(conn, "Org A", "org-a", full_schema=True)
        org_b = _create_organization(conn, "Org B", "org-b", full_schema=True)
        _seed_rows(conn, org_a, org_b, include_org=True)
    return org_a, org_b


def _backfill(engine, default_org_id: int) -> None:
    db = _new_session(engine)
    try:
        set_system_session(db)
        main._backfill_tenant_data(db, default_org_id)
        db.commit()
    finally:
        db.close()


def _run_startup(engine, default_org_id: int) -> None:
    main._add_columns(*main._COMPATIBILITY_COLUMNS)
    main._remap_roles()
    _backfill(engine, default_org_id)
    main._deduplicate_legacy_assets()
    main._assert_tenant_parent_consistency()
    main._enforce_tenant_ownership()
    main._ensure_indexes()


def _exercise(engine, org_a: int, org_b: int) -> dict[str, bool]:
    result: dict[str, bool] = {}
    db = _new_session(engine)
    try:
        set_tenant_session(db, org_a)
        result["tenant_a_reads_own_asset"] = db.get(models.Asset, ASSET_A) is not None
        result["tenant_a_reads_own_issue"] = db.get(models.Issue, ISSUE_A) is not None
        result["tenant_a_cannot_read_b_asset"] = db.get(models.Asset, ASSET_B) is None
        result["tenant_a_cannot_read_b_issue"] = db.get(models.Issue, ISSUE_B) is None
        result["tenant_a_query_scope"] = {
            asset.id for asset in db.query(models.Asset).all()
        } == {ASSET_A}
    finally:
        db.close()

    db = _new_session(engine)
    try:
        set_tenant_session(db, org_b)
        result["tenant_b_reads_own_asset"] = db.get(models.Asset, ASSET_B) is not None
        result["tenant_b_reads_own_issue"] = db.get(models.Issue, ISSUE_B) is not None
        result["tenant_b_cannot_read_a_asset"] = db.get(models.Asset, ASSET_A) is None
        result["tenant_b_cannot_read_a_issue"] = db.get(models.Issue, ISSUE_A) is None
        result["tenant_b_query_scope"] = {
            asset.id for asset in db.query(models.Asset).all()
        } == {ASSET_B}
    finally:
        db.close()

    db = _new_session(engine)
    try:
        set_system_session(db)
        ownership = (
            (models.ApiKey, KEY_B, org_b),
            (models.Agent, AGENT_B, org_b),
            (models.Asset, ASSET_A, org_a),
            (models.Asset, ASSET_B, org_b),
            (models.Service, SERVICE_A, org_a),
            (models.Service, SERVICE_B, org_b),
            (models.Scan, SCAN_A, org_a),
            (models.Scan, SCAN_B, org_b),
            (models.Finding, FINDING_A, org_a),
            (models.Finding, FINDING_B, org_b),
            (models.Issue, ISSUE_A, org_a),
            (models.Issue, ISSUE_B, org_b),
            (models.IssueHistory, HISTORY_A, org_a),
            (models.IssueHistory, HISTORY_B, org_b),
        )
        for model, row_id, expected in ownership:
            row = db.get(model, row_id)
            result[f"{model.__tablename__}_{row_id}_owner"] = (
                row is not None and row.organization_id == expected
            )
    finally:
        db.close()

    db = _new_session(engine)
    try:
        set_tenant_session(db, org_b)
        db.add(
            models.Service(
                organization_id=org_a,
                host="foreign-write.example.test",
                port=8443,
            )
        )
        try:
            db.flush()
        except ValueError:
            result["tenant_b_rejects_foreign_write"] = True
        else:
            result["tenant_b_rejects_foreign_write"] = False
    finally:
        db.rollback()
        db.close()

    for label, organization_id in (("null", None), ("unknown", 999999)):
        try:
            with engine.begin() as conn:
                _insert(
                    conn,
                    "assets",
                    id=f"probe-{label}-org",
                    organization_id=organization_id,
                )
        except (DBAPIError, ValueError):
            result[f"rejects_{label}_organization"] = True
        else:
            result[f"rejects_{label}_organization"] = False

    with engine.begin() as conn:
        _insert(
            conn,
            "findings",
            id="probe-cross-parent",
            organization_id=org_a,
            scan_id=SCAN_B,
        )
    try:
        main._assert_tenant_parent_consistency()
    except RuntimeError:
        result["detects_cross_org_parent"] = True
    else:
        result["detects_cross_org_parent"] = False
    return result


def test_legacy_and_fresh_alembic_tenant_behavior_parity(tmp_path, monkeypatch):
    legacy_url = f"sqlite:///{(tmp_path / 'legacy.db').as_posix()}"
    fresh_url = f"sqlite:///{(tmp_path / 'fresh.db').as_posix()}"

    legacy_engine = create_engine(legacy_url)
    fresh_engine = create_engine(fresh_url)
    try:
        _upgrade(legacy_url, LEGACY_REVISION)
        legacy_a, legacy_b = _seed_legacy(legacy_engine)
        Base.metadata.create_all(legacy_engine)
        monkeypatch.setattr(main, "engine", legacy_engine)
        with legacy_engine.begin() as conn:
            conn.execute(
                text("UPDATE agents SET organization_id=:org WHERE id=:id"),
                {"org": legacy_b, "id": AGENT_B},
            )
            conn.execute(
                text("UPDATE issues SET organization_id=:org WHERE id=:id"),
                {"org": legacy_b, "id": ISSUE_B},
            )
        _run_startup(legacy_engine, legacy_a)
        legacy_result = _exercise(legacy_engine, legacy_a, legacy_b)

        _upgrade(fresh_url)
        fresh_a, fresh_b = _seed_fresh(fresh_engine)
        monkeypatch.setattr(main, "engine", fresh_engine)
        _run_startup(fresh_engine, fresh_a)
        fresh_result = _exercise(fresh_engine, fresh_a, fresh_b)
    finally:
        legacy_engine.dispose()
        fresh_engine.dispose()

    assert legacy_result == fresh_result
    assert all(legacy_result.values()), {
        name: value for name, value in legacy_result.items() if not value
    }
