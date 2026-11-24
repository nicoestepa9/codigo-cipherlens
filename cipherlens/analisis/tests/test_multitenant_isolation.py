import os
import ast
import re
from datetime import datetime, timedelta, timezone
from uuid import uuid4
from pathlib import Path

import pytest
from sqlalchemy.exc import IntegrityError

os.environ.setdefault("ENV", "dev")
os.environ.setdefault("JWT_SECRET", "dev-local-secret")

from fastapi.testclient import TestClient

from tls_analyzer.api import models
from tls_analyzer.api.db import SessionLocal
from tls_analyzer.api.main import app
from tls_analyzer.api.tenancy import set_system_session


def _authorization(token: str) -> str:
    return "".join(("Bear", "er ", token))


def test_cross_org_isolation_scans():
    suffix = uuid4().hex[:8]
    db = SessionLocal()
    set_system_session(db)
    try:
        org1 = models.Organization(name=f"Org1-{suffix}", slug=f"org1-{suffix}", status="active")
        org2 = models.Organization(name=f"Org2-{suffix}", slug=f"org2-{suffix}", status="active")
        db.add_all([org1, org2])
        db.commit()
        db.refresh(org1)
        db.refresh(org2)

        u1 = models.User(
            email=f"u1-{suffix}@o1.com", name="u1", password_hash="x",
            role="user", organization_id=org1.id,
        )
        u2 = models.User(
            email=f"u2-{suffix}@o2.com", name="u2", password_hash="x",
            role="user", organization_id=org2.id,
        )
        db.add_all([u1, u2])
        db.commit()
        db.refresh(u1)
        db.refresh(u2)

        s1 = models.Service(
            id=f"s1-{suffix}", host=f"h1-{suffix}", port=443,
            organization_id=org1.id,
        )
        s2 = models.Service(
            id=f"s2-{suffix}", host=f"h2-{suffix}", port=443,
            organization_id=org2.id,
        )
        db.add_all([s1, s2])
        db.commit()

        sc1 = models.Scan(
            id=f"sc1-{suffix}", service_id=s1.id, host=s1.host, port=443,
            organization_id=org1.id,
        )
        sc2 = models.Scan(
            id=f"sc2-{suffix}", service_id=s2.id, host=s2.host, port=443,
            organization_id=org2.id,
        )
        db.add_all([sc1, sc2])
        db.commit()
        org_ids = [org1.id, org2.id]
        user_ids = [u1.id, u2.id]
        scan_ids = [sc1.id, sc2.id]
    finally:
        db.close()

    from tls_analyzer.api.services import auth_service

    t1 = auth_service.create_access_token(str(user_ids[0]), "user")
    t2 = auth_service.create_access_token(str(user_ids[1]), "user")
    try:
        with TestClient(app) as tc:
            r1 = tc.get("/api/scans", headers={"Authorization": _authorization(t1)})
            assert r1.status_code == 200
            ids1 = {item["id"] for item in r1.json().get("items", [])}
            assert scan_ids[0] in ids1
            assert scan_ids[1] not in ids1
            assert r1.json()["total"] == 1
            hidden_scan = tc.get(
                f"/api/scans/{scan_ids[1]}",
                headers={"Authorization": _authorization(t1)},
            )
            assert hidden_scan.status_code == 404

            r2 = tc.get("/api/scans", headers={"Authorization": _authorization(t2)})
            assert r2.status_code == 200
            ids2 = {item["id"] for item in r2.json().get("items", [])}
            assert scan_ids[1] in ids2
            assert scan_ids[0] not in ids2
            assert r2.json()["total"] == 1

            services1 = tc.get("/api/services", headers={"Authorization": _authorization(t1)})
            assert services1.status_code == 200
            service_ids1 = {item["id"] for item in services1.json()["items"]}
            assert s1.id in service_ids1
            assert s2.id not in service_ids1

            services2 = tc.get("/api/services", headers={"Authorization": _authorization(t2)})
            assert services2.status_code == 200
            service_ids2 = {item["id"] for item in services2.json()["items"]}
            assert s2.id in service_ids2
            assert s1.id not in service_ids2

            hidden_service = tc.get(
                f"/api/services/{s2.id}",
                headers={"Authorization": _authorization(t1)},
            )
            assert hidden_service.status_code == 404
    finally:
        cleanup_db = SessionLocal()
        set_system_session(cleanup_db)
        try:
            cleanup_db.query(models.Scan).filter(
                models.Scan.id.in_(scan_ids)
            ).delete(synchronize_session=False)
            cleanup_db.query(models.Service).filter(
                models.Service.id.in_([f"s1-{suffix}", f"s2-{suffix}"])
            ).delete(synchronize_session=False)
            cleanup_db.query(models.User).filter(
                models.User.id.in_(user_ids)
            ).delete(synchronize_session=False)
            cleanup_db.query(models.Organization).filter(
                models.Organization.id.in_(org_ids)
            ).delete(synchronize_session=False)
            cleanup_db.commit()
        finally:
            cleanup_db.close()


def test_unconfigured_orm_session_fails_closed():
    db = SessionLocal()
    db.info.clear()
    try:
        with pytest.raises(RuntimeError, match="without organization_id"):
            db.query(models.Scan).all()
    finally:
        db.close()


def test_bulk_update_and_delete_are_tenant_scoped():
    suffix = uuid4().hex[:8]
    db = SessionLocal()
    set_system_session(db)
    try:
        org_a = models.Organization(
            name=f"Bulk-A-{suffix}", slug=f"bulk-a-{suffix}", status="active"
        )
        org_b = models.Organization(
            name=f"Bulk-B-{suffix}", slug=f"bulk-b-{suffix}", status="active"
        )
        db.add_all([org_a, org_b])
        db.flush()
        service_a = models.Service(
            id=f"bulk-a-{suffix}", host=f"a-{suffix}", port=443,
            organization_id=org_a.id,
        )
        service_b = models.Service(
            id=f"bulk-b-{suffix}", host=f"b-{suffix}", port=443,
            organization_id=org_b.id,
        )
        db.add_all([service_a, service_b])
        db.commit()
        org_a_id = org_a.id
        org_b_id = org_b.id
        service_a_id = service_a.id
        service_b_id = service_b.id
    finally:
        db.close()

    tenant_db = SessionLocal()
    try:
        from tls_analyzer.api.tenancy import set_tenant_session

        set_tenant_session(tenant_db, org_a_id)
        tenant_db.query(models.Service).update(
            {models.Service.security_status: "isolated"},
            synchronize_session=False,
        )
        tenant_db.query(models.Service).filter(
            models.Service.id == service_a_id
        ).delete(synchronize_session=False)
        tenant_db.commit()
    finally:
        tenant_db.close()

    verify_db = SessionLocal()
    set_system_session(verify_db)
    try:
        assert verify_db.get(models.Service, service_a_id) is None
        service_b = verify_db.get(models.Service, service_b_id)
        assert service_b is not None
        assert service_b.security_status != "isolated"
    finally:
        verify_db.query(models.Service).filter(
            models.Service.id == service_b_id
        ).delete(synchronize_session=False)
        verify_db.query(models.Organization).filter(
            models.Organization.id.in_([org_a_id, org_b_id])
        ).delete(synchronize_session=False)
        verify_db.commit()
        verify_db.close()


def test_tenant_filter_covers_joins_subqueries_relationships_and_scoped_get():
    from sqlalchemy import func

    from tls_analyzer.api.db import scoped_get
    from tls_analyzer.api.tenancy import set_tenant_session

    suffix = uuid4().hex[:8]
    db = SessionLocal()
    set_system_session(db)
    try:
        org_a = models.Organization(
            name=f"Query-A-{suffix}", slug=f"query-a-{suffix}", status="active"
        )
        org_b = models.Organization(
            name=f"Query-B-{suffix}", slug=f"query-b-{suffix}", status="active"
        )
        db.add_all([org_a, org_b])
        db.flush()
        asset_a = models.Asset(
            id=f"asset-a-{suffix}", hostname=f"a-{suffix}", organization_id=org_a.id
        )
        asset_b = models.Asset(
            id=f"asset-b-{suffix}", hostname=f"b-{suffix}", organization_id=org_b.id
        )
        db.add_all([asset_a, asset_b])
        db.flush()
        service_a = models.Service(
            id=f"query-a-{suffix}", host=f"a-{suffix}", port=443,
            asset_id=asset_a.id, organization_id=org_a.id,
        )
        service_b = models.Service(
            id=f"query-b-{suffix}", host=f"b-{suffix}", port=443,
            asset_id=asset_b.id, organization_id=org_b.id,
        )
        db.add_all([service_a, service_b])
        db.commit()
        org_a_id, org_b_id = org_a.id, org_b.id
        asset_ids = [asset_a.id, asset_b.id]
        service_ids = [service_a.id, service_b.id]
    finally:
        db.close()

    tenant_db = SessionLocal()
    try:
        set_tenant_session(tenant_db, org_a_id)
        joined_services = (
            tenant_db.query(models.Service)
            .join(models.Asset, models.Service.asset_id == models.Asset.id)
            .all()
        )
        assert [service.id for service in joined_services] == [service_ids[0]]
        assert joined_services[0].asset.hostname == f"a-{suffix}"

        service_ids_subquery = tenant_db.query(models.Service.id).subquery()
        assert tenant_db.query(func.count()).select_from(service_ids_subquery).scalar() == 1

        assert scoped_get(tenant_db, models.Service, service_ids[0]) is not None
        assert scoped_get(tenant_db, models.Service, service_ids[1]) is None
        assert scoped_get(tenant_db, models.Asset, asset_ids[1]) is None
    finally:
        tenant_db.close()

    cleanup_db = SessionLocal()
    set_system_session(cleanup_db)
    try:
        cleanup_db.query(models.Service).filter(
            models.Service.id.in_(service_ids)
        ).delete(synchronize_session=False)
        cleanup_db.query(models.Asset).filter(
            models.Asset.id.in_(asset_ids)
        ).delete(synchronize_session=False)
        cleanup_db.query(models.Organization).filter(
            models.Organization.id.in_([org_a_id, org_b_id])
        ).delete(synchronize_session=False)
        cleanup_db.commit()
    finally:
        cleanup_db.close()


def test_api_keys_cannot_override_user_or_agent_organization():
    from fastapi import HTTPException

    from tls_analyzer.api.deps import _authenticate_api_key, hash_api_key

    suffix = uuid4().hex[:8]
    key_user = f"user-key-{suffix}"
    key_agent = f"agent-key-{suffix}"
    db = SessionLocal()
    set_system_session(db)
    try:
        org_a = models.Organization(
            name=f"Key-A-{suffix}", slug=f"key-a-{suffix}", status="active"
        )
        org_b = models.Organization(
            name=f"Key-B-{suffix}", slug=f"key-b-{suffix}", status="active"
        )
        db.add_all([org_a, org_b])
        db.flush()
        user = models.User(
            email=f"key-user-{suffix}@example.com",
            name="Key user",
            password_hash="x",
            role="user",
            organization_id=org_a.id,
        )
        db.add(user)
        db.flush()
        user_key = models.ApiKey(
            name="mismatched user key",
            key_hash=hash_api_key(key_user),
            role="user",
            user_id=user.id,
            organization_id=org_b.id,
        )
        agent_key = models.ApiKey(
            name="mismatched agent key",
            key_hash=hash_api_key(key_agent),
            role="agent",
            organization_id=org_b.id,
        )
        db.add_all([user_key, agent_key])
        db.flush()
        agent = models.Agent(
            name="Key agent",
            site_label="test",
            api_key_id=agent_key.id,
            organization_id=org_a.id,
        )
        db.add(agent)
        db.commit()
        key_ids = [user_key.id, agent_key.id]
        user_id = user.id
        agent_id = agent.id
        organization_ids = [org_a.id, org_b.id]
    finally:
        db.close()

    auth_db = SessionLocal()
    set_system_session(auth_db)
    try:
        with pytest.raises(HTTPException) as user_error:
            _authenticate_api_key(auth_db, key_user)
        assert user_error.value.status_code == 401

        with pytest.raises(HTTPException) as agent_error:
            _authenticate_api_key(auth_db, key_agent)
        assert agent_error.value.status_code == 401
    finally:
        auth_db.close()

    cleanup_db = SessionLocal()
    set_system_session(cleanup_db)
    try:
        cleanup_db.query(models.Agent).filter(models.Agent.id == agent_id).delete()
        cleanup_db.query(models.ApiKey).filter(
            models.ApiKey.id.in_(key_ids)
        ).delete(synchronize_session=False)
        cleanup_db.query(models.User).filter(models.User.id == user_id).delete()
        cleanup_db.query(models.Organization).filter(
            models.Organization.id.in_(organization_ids)
        ).delete(synchronize_session=False)
        cleanup_db.commit()
    finally:
        cleanup_db.close()


def test_primary_key_and_child_entity_lookups_are_tenant_scoped():
    from tls_analyzer.api.tenancy import set_tenant_session

    suffix = uuid4().hex[:8]
    setup = SessionLocal()
    set_system_session(setup)
    try:
        org_a = models.Organization(
            name=f"PK-A-{suffix}", slug=f"pk-a-{suffix}", status="active"
        )
        org_b = models.Organization(
            name=f"PK-B-{suffix}", slug=f"pk-b-{suffix}", status="active"
        )
        setup.add_all([org_a, org_b])
        setup.flush()
        scan_a = models.Scan(
            id=f"pk-scan-a-{suffix}", organization_id=org_a.id, host="a.test"
        )
        scan_b = models.Scan(
            id=f"pk-scan-b-{suffix}", organization_id=org_b.id, host="b.test"
        )
        setup.add_all([scan_a, scan_b])
        setup.flush()
        finding_a = models.Finding(
            scan_id=scan_a.id, organization_id=org_a.id
        )
        finding_b = models.Finding(
            scan_id=scan_b.id, organization_id=org_b.id
        )
        setup.add_all([finding_a, finding_b])
        setup.commit()
        org_a_id, org_b_id = org_a.id, org_b.id
        scan_ids = [scan_a.id, scan_b.id]
        finding_ids = [finding_a.id, finding_b.id]
    finally:
        setup.close()

    tenant = SessionLocal()
    try:
        set_tenant_session(tenant, org_a_id)
        assert tenant.get(models.Scan, scan_ids[0]) is not None
        assert tenant.get(models.Scan, scan_ids[1]) is None
        assert tenant.get(models.Finding, finding_ids[1]) is None
        assert {row.id for row in tenant.query(models.Finding).all()} == {
            finding_ids[0]
        }
        assert tenant.get(models.Organization, org_b_id) is not None
    finally:
        tenant.close()

    cleanup = SessionLocal()
    set_system_session(cleanup)
    try:
        cleanup.query(models.Finding).filter(
            models.Finding.id.in_(finding_ids)
        ).delete(synchronize_session=False)
        cleanup.query(models.Scan).filter(
            models.Scan.id.in_(scan_ids)
        ).delete(synchronize_session=False)
        cleanup.query(models.Organization).filter(
            models.Organization.id.in_([org_a_id, org_b_id])
        ).delete(synchronize_session=False)
        cleanup.commit()
    finally:
        cleanup.close()


def test_customer_models_have_required_organization_columns():
    tenant_models = (
        models.Team, models.TeamMember, models.Issue,
        models.IssueHistory, models.Asset, models.Service, models.Certificate,
        models.Scan, models.Finding, models.ScanCveMatch, models.DiscoveryJob,
        models.DiscoveryResult, models.RecurringScan, models.Alert,
        models.AlertThreshold, models.ComplianceWindow, models.ApiKey,
        models.Integration, models.Agent, models.AuditLog, models.RefreshToken,
    )
    for model in tenant_models:
        column = model.__table__.c.organization_id
        assert column.nullable is False, model.__tablename__
        assert any(
            fk.target_fullname == "organizations.id"
            for fk in column.foreign_keys
        ), model.__tablename__

    # Platform operators are identities outside any tenant, so their nullable
    # organization is intentional while tenant-owned customer models are not.
    user_organization = models.User.__table__.c.organization_id
    assert user_organization.nullable is True
    assert any(
        fk.target_fullname == "organizations.id"
        for fk in user_organization.foreign_keys
    )

    assert "organization_id" not in models.Cve.__table__.c
    assert "organization_id" not in models.CveQueryCache.__table__.c


def test_system_session_requires_explicit_tenant_on_inserts():
    db = SessionLocal()
    set_system_session(db)
    try:
        db.add(models.Asset(hostname="unowned.example"))
        with pytest.raises(ValueError, match="explicit organization_id"):
            db.flush()
        db.rollback()
    finally:
        db.close()


def test_tenant_cannot_reassign_existing_rows_through_orm_or_bulk_update():
    from sqlalchemy import update

    from tls_analyzer.api.tenancy import set_tenant_session

    suffix = uuid4().hex[:8]
    setup = SessionLocal()
    set_system_session(setup)
    try:
        org_a = models.Organization(
            name=f"Move-A-{suffix}", slug=f"move-a-{suffix}", status="active"
        )
        org_b = models.Organization(
            name=f"Move-B-{suffix}", slug=f"move-b-{suffix}", status="active"
        )
        setup.add_all([org_a, org_b])
        setup.flush()
        service = models.Service(
            id=f"move-service-{suffix}",
            host=f"move-{suffix}.example",
            organization_id=org_a.id,
        )
        setup.add(service)
        setup.commit()
        org_a_id, org_b_id, service_id = org_a.id, org_b.id, service.id
    finally:
        setup.close()

    tenant = SessionLocal()
    set_tenant_session(tenant, org_a_id)
    try:
        service = tenant.get(models.Service, service_id)
        service.organization_id = org_b_id
        with pytest.raises(ValueError, match="Cannot change organization_id"):
            tenant.flush()
        tenant.rollback()
        with pytest.raises(ValueError, match="Cannot change organization_id"):
            tenant.execute(
                update(models.Service)
                .where(models.Service.id == service_id)
                .values(organization_id=org_b_id)
            )
        tenant.rollback()
    finally:
        tenant.close()

    verify = SessionLocal()
    set_system_session(verify)
    try:
        assert verify.get(models.Service, service_id).organization_id == org_a_id
    finally:
        verify.query(models.Service).filter_by(id=service_id).delete()
        verify.query(models.Organization).filter(
            models.Organization.id.in_([org_a_id, org_b_id])
        ).delete(synchronize_session=False)
        verify.commit()
        verify.close()


def test_tenant_api_has_no_unapproved_raw_sql_or_core_table_access():
    api_root = Path(__file__).parents[1] / "src" / "tls_analyzer" / "api"
    violations = []

    class RawSqlVisitor(ast.NodeVisitor):
        def __init__(self, path):
            self.path = path
            self.function_stack = []

        def visit_FunctionDef(self, node):
            self.function_stack.append(node.name)
            self.generic_visit(node)
            self.function_stack.pop()

        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_Call(self, node):
            name = node.func.id if isinstance(node.func, ast.Name) else None
            if name in {"text", "Table"}:
                approved_schema_ddl = (
                    self.path.name == "main.py"
                    and bool(
                        set(self.function_stack)
                        & {
                            "_add_columns",
                            "_backfill_tenant_data",
                            "_deduplicate_legacy_assets",
                            "_assert_tenant_parent_consistency",
                            "_enforce_tenant_ownership",
                        }
                    )
                )
                approved_model_metadata = (
                    self.path.name == "models.py" and name == "text"
                )
                if not approved_schema_ddl and not approved_model_metadata:
                    violations.append(
                        f"{self.path.relative_to(api_root)}:{node.lineno}: {name}(...)"
                    )
            self.generic_visit(node)

        def visit_Attribute(self, node):
            if node.attr == "__table__":
                violations.append(
                    f"{self.path.relative_to(api_root)}:{node.lineno}: __table__"
                )
            self.generic_visit(node)

    for source_path in sorted(api_root.rglob("*.py")):
        tree = ast.parse(source_path.read_text(encoding="utf-8-sig"))
        RawSqlVisitor(source_path).visit(tree)
    assert not violations, (
        "Raw SQL/Core table access in tenant API requires explicit review and "
        f"allowlisting: {violations}"
    )


def test_startup_compatibility_schema_rejects_missing_or_unknown_organizations():
    from sqlalchemy import text

    from tls_analyzer.api.db import engine
    from tls_analyzer.api.main import _enforce_tenant_ownership

    _enforce_tenant_ownership()
    for organization_id in (None, 987654321):
        with engine.connect() as connection:
            transaction = connection.begin()
            try:
                with pytest.raises(IntegrityError):
                    connection.execute(
                        text(
                            "INSERT INTO integrations (id, organization_id) "
                            "VALUES (:id, :organization_id)"
                        ),
                        {
                            "id": f"startup-guard-{uuid4().hex[:8]}",
                            "organization_id": organization_id,
                        },
                    )
            finally:
                transaction.rollback()


def test_tenant_session_rejects_core_and_text_queries_to_tenant_tables():
    from sqlalchemy import select, text, update

    from tls_analyzer.api.tenancy import set_tenant_session

    db = SessionLocal()
    try:
        set_tenant_session(db, 1)
        with pytest.raises(RuntimeError, match="Core queries"):
            db.execute(select(models.Service.__table__)).all()
        with pytest.raises(RuntimeError, match="Core DML"):
            db.execute(
                update(models.Service.__table__).values(name="unscoped")
            )
        with pytest.raises(RuntimeError, match="Text SQL"):
            db.execute(text("SELECT * FROM services")).all()
    finally:
        db.close()


@pytest.fixture
def complete_two_tenant_data():
    from tls_analyzer.api.services.auth_service import create_access_token

    suffix = uuid4().hex[:8]
    db = SessionLocal()
    set_system_session(db)
    orgs = {}
    records = {}
    try:
        for label in ("a", "b"):
            org = models.Organization(
                name=f"Complete-{label}-{suffix}",
                slug=f"complete-{label}-{suffix}",
                status="active",
            )
            db.add(org)
            db.flush()
            user = models.User(
                email=f"complete-{label}-{suffix}@example.com",
                name=f"Complete user {label}",
                password_hash="unused",
                role="admin",
                organization_id=org.id,
            )
            db.add(user)
            db.flush()
            team = models.Team(
                name=f"Complete team {label}-{suffix}",
                organization_id=org.id,
            )
            db.add(team)
            db.flush()
            db.add(models.TeamMember(
                team_id=team.id,
                user_id=user.id,
                organization_id=org.id,
                is_lead=True,
            ))
            role_users = {}
            for role in ("lead", "user"):
                member = models.User(
                    email=f"complete-{role}-{label}-{suffix}@example.com",
                    name=f"Complete {role} {label}",
                    password_hash="unused",
                    role=role,
                    organization_id=org.id,
                )
                db.add(member)
                db.flush()
                role_users[role] = member.id
                db.add(models.TeamMember(
                    team_id=team.id,
                    user_id=member.id,
                    organization_id=org.id,
                    is_lead=(role == "lead"),
                ))
            agent_key = models.ApiKey(
                name=f"agent key {label}",
                key_hash=f"unused-{label}-{suffix}",
                role="agent",
                organization_id=org.id,
            )
            db.add(agent_key)
            db.flush()
            agent = models.Agent(
                name=f"Complete agent {label}-{suffix}",
                organization_id=org.id,
                api_key_id=agent_key.id,
            )
            db.add(agent)
            asset = models.Asset(
                id=f"complete-asset-{label}-{suffix}",
                ip_address=f"192.0.2.{10 if label == 'a' else 20}",
                hostname=f"complete-asset-{label}-{suffix}.example",
                port=443,
                organization_id=org.id,
            )
            db.add(asset)
            db.flush()
            service = models.Service(
                id=f"complete-service-{label}-{suffix}",
                host=f"shared-{suffix}.example",
                port=443,
                name=f"Complete service {label}",
                organization_id=org.id,
            )
            db.add(service)
            db.flush()
            certificate = models.Certificate(
                id=f"complete-cert-{label}-{suffix}",
                service_id=service.id,
                domain=f"shared-{suffix}.example",
                fingerprint_sha256=f"shared-fingerprint-{suffix}",
                organization_id=org.id,
            )
            db.add(certificate)
            scan = models.Scan(
                id=f"complete-scan-{label}-{suffix}",
                service_id=service.id,
                host=service.host,
                port=443,
                organization_id=org.id,
            )
            db.add(scan)
            db.flush()
            finding = models.Finding(
                scan_id=scan.id,
                rule_id=f"COMPLETE-{label}-{suffix}",
                organization_id=org.id,
            )
            issue = models.Issue(
                service_id=service.id,
                source_document="test",
                rule_id=f"COMPLETE-{label}-{suffix}",
                title=f"Complete issue {label}",
                organization_id=org.id,
            )
            db.add_all([finding, issue])
            db.flush()
            history = models.IssueHistory(
                issue_id=issue.id,
                event_type="created",
                organization_id=org.id,
            )
            alert = models.Alert(
                title=f"Complete alert {label}",
                organization_id=org.id,
            )
            recurring = models.RecurringScan(
                host=service.host,
                service_id=service.id,
                organization_id=org.id,
            )
            discovery = models.DiscoveryJob(
                cidr_or_targets=["192.0.2.1"],
                organization_id=org.id,
            )
            db.add_all([history, alert, recurring, discovery])
            db.flush()
            discovery_result = models.DiscoveryResult(
                discovery_job_id=discovery.id,
                ip_address=f"192.0.2.{1 if label == 'a' else 2}",
                port=443,
                organization_id=org.id,
            )
            user_key = models.ApiKey(
                name=f"user key {label}",
                key_hash=f"user-key-{label}-{suffix}",
                role="user",
                user_id=user.id,
                organization_id=org.id,
            )
            db.add_all([discovery_result, user_key])
            db.flush()
            agent_task = models.AgentTask(
                agent_id=agent.id,
                type="scan",
                payload={"target": {"host": "192.0.2.10", "port": 443}},
                status="queued",
                expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
                organization_id=org.id,
            )
            db.add(agent_task)
            db.flush()
            records[label] = {
                "org_id": org.id,
                "user_id": user.id,
                "role_user_ids": role_users,
                "team_id": team.id,
                "agent_id": agent.id,
                "agent_key_id": agent_key.id,
                "asset_id": asset.id,
                "service_id": service.id,
                "certificate_id": certificate.id,
                "scan_id": scan.id,
                "finding_id": finding.id,
                "issue_id": issue.id,
                "alert_id": alert.id,
                "recurring_id": recurring.id,
                "discovery_id": discovery.id,
                "discovery_result_id": discovery_result.id,
                "api_key_id": user_key.id,
                "agent_task_id": agent_task.id,
                "token": create_access_token(user.id, "admin"),
                "marker": f"Complete {label}",
            }
        db.commit()
    finally:
        db.close()

    try:
        yield records
    finally:
        cleanup = SessionLocal()
        set_system_session(cleanup)
        try:
            from tls_analyzer.cli import _purge_organization

            for org_id in [records["a"]["org_id"], records["b"]["org_id"]]:
                _purge_organization(cleanup, org_id)
            cleanup.commit()
        finally:
            cleanup.close()


def test_two_complete_tenants_cover_required_detail_and_listing_isolation(
    complete_two_tenant_data, monkeypatch,
):
    from tls_analyzer.api import cloud_guardrails

    monkeypatch.setattr(
        cloud_guardrails,
        "resolve_target_addresses",
        lambda host, enforce_public=True: ("8.8.8.8",),
    )
    tenant_a = complete_two_tenant_data["a"]
    tenant_b = complete_two_tenant_data["b"]
    headers = {"Authorization": _authorization(tenant_a["token"])}
    system = SessionLocal()
    set_system_session(system)
    try:
        assert tenant_a["service_id"] != tenant_b["service_id"]
        assert tenant_a["scan_id"] != tenant_b["scan_id"]
        certificates = system.query(models.Certificate).filter(
            models.Certificate.fingerprint_sha256
            == f"shared-fingerprint-{tenant_a['service_id'].split('-')[-1]}"
        ).all()
        assert {certificate.organization_id for certificate in certificates} == {
            tenant_a["org_id"],
            tenant_b["org_id"],
        }
    finally:
        system.close()

    foreign_detail_paths = (
        f"/api/scans/{tenant_b['scan_id']}",
        f"/api/services/{tenant_b['service_id']}",
        f"/api/certificates/{tenant_b['certificate_id']}",
        f"/api/issues/{tenant_b['issue_id']}",
        f"/api/agents/{tenant_b['agent_id']}",
        f"/api/users/{tenant_b['user_id']}",
        f"/api/teams/{tenant_b['team_id']}",
        f"/api/recurring-scans/{tenant_b['recurring_id']}",
        f"/api/discovery/{tenant_b['discovery_id']}",
    )
    list_paths = (
        "/api/scans",
        "/api/history",
        "/api/services",
        "/api/certificates",
        "/api/assets",
        "/api/issues",
        "/api/agents",
        "/api/users",
        "/api/teams",
        "/api/alerts",
        "/api/recurring-scans",
        "/api/discovery/results",
        "/api/vulnerabilities",
    )
    foreign_mutations = (
        ("patch", f"/api/services/{tenant_b['service_id']}/owner",
         {"ownerUserId": None, "ownerTeamId": None}),
        ("put", f"/api/alerts/{tenant_b['alert_id']}/status", {"status": "read"}),
        ("delete", f"/api/assets/{tenant_b['asset_id']}", None),
        ("patch", f"/api/issues/{tenant_b['issue_id']}", {"status": "resolved"}),
        ("post", f"/api/issues/{tenant_b['issue_id']}/comment", {"comment": "hidden"}),
        ("patch", f"/api/agents/{tenant_b['agent_id']}", {"name": "changed"}),
        ("post", f"/api/agents/{tenant_b['agent_id']}/rotate-key", None),
        ("delete", f"/api/agents/{tenant_b['agent_id']}", None),
        ("patch", f"/api/users/{tenant_b['user_id']}", {"name": "changed"}),
        ("delete", f"/api/users/{tenant_b['user_id']}", None),
        ("patch", f"/api/teams/{tenant_b['team_id']}",
         {"name": "changed", "description": ""}),
        ("post", f"/api/teams/{tenant_b['team_id']}/members",
         {"userId": tenant_a["user_id"]}),
        ("delete", f"/api/teams/{tenant_b['team_id']}/members/{tenant_a['user_id']}",
         None),
        ("patch", f"/api/recurring-scans/{tenant_b['recurring_id']}",
         {"enabled": False}),
        ("delete", f"/api/recurring-scans/{tenant_b['recurring_id']}", None),
        ("delete", f"/api/discovery/{tenant_b['discovery_id']}", None),
        ("delete", f"/api/api-keys/{tenant_b['api_key_id']}", None),
    )
    with TestClient(app) as client:
        for path in foreign_detail_paths:
            response = client.get(path, headers=headers)
            assert response.status_code == 404, (path, response.text)

        for path in list_paths:
            response = client.get(path, headers=headers)
            assert response.status_code == 200, (path, response.text)
            assert tenant_b["marker"] not in response.text, path
            assert tenant_b["scan_id"] not in response.text, path
            assert tenant_b["service_id"] not in response.text, path
            assert tenant_b["issue_id"] not in response.text
            filtered = client.get(
                path,
                headers=headers,
                params={
                    "page": 1,
                    "pageSize": 1,
                    "search": tenant_b["marker"],
                    "agentId": tenant_b["agent_id"],
                    "siteLabel": tenant_b["marker"],
                },
            )
            assert filtered.status_code == 200, (path, filtered.text)
            assert tenant_b["marker"] not in filtered.text, path
            assert tenant_b["scan_id"] not in filtered.text, path
            assert tenant_b["service_id"] not in filtered.text, path
            assert tenant_b["issue_id"] not in filtered.text, path

        dashboard = client.get("/api/dashboard", headers=headers)
        assert dashboard.status_code == 200
        dashboard_data = dashboard.json()
        assert dashboard_data["totalServices"] == 1
        assert dashboard_data["totalCertificates"] == 1
        assert dashboard_data["unreadAlerts"] == 1
        vulnerability_stats = client.get(
            "/api/vulnerabilities/stats", headers=headers
        )
        assert vulnerability_stats.status_code == 200
        assert vulnerability_stats.json()["bySeverity"]["info"] == 1, path

        created_user = client.post(
            "/api/users",
            headers=headers,
            json={
                "email": f"created-in-a-{uuid4().hex[:8]}@example.com",
                "name": "Tenant A new user",
                "password": "Strong!Test123",
                "role": "user",
            },
        )
        assert created_user.status_code == 201, created_user.text
        created_team = client.post(
            "/api/teams",
            headers=headers,
            json={"name": f"Tenant A created team {uuid4().hex[:8]}"},
        )
        assert created_team.status_code == 201, created_team.text
        created_agent = client.post(
            "/api/agents",
            headers=headers,
            json={"name": "Tenant A created agent", "siteLabel": "A"},
        )
        assert created_agent.status_code == 201, created_agent.text
        created_api_key = client.post(
            "/api/api-keys",
            headers=headers,
            json={"name": "Tenant A created key", "role": "user"},
        )
        assert created_api_key.status_code == 201, created_api_key.text
        created_schedule = client.post(
            "/api/recurring-scans",
            headers=headers,
            json={
                "host": f"tenant-a-{uuid4().hex[:8]}.example",
                "authorizationAccepted": True,
                "authorizationVersion": "2026-10-v1",
            },
        )
        assert created_schedule.status_code == 201, created_schedule.text

        writes = SessionLocal()
        set_system_session(writes)
        try:
            assert writes.get(
                models.User, created_user.json()["id"]
            ).organization_id == tenant_a["org_id"]
            assert writes.get(
                models.Team, created_team.json()["id"]
            ).organization_id == tenant_a["org_id"]
            assert writes.get(
                models.Agent, created_agent.json()["id"]
            ).organization_id == tenant_a["org_id"]
            assert writes.query(models.ApiKey).filter_by(
                name="Tenant A created key"
            ).one().organization_id == tenant_a["org_id"]
            created_schedule_id = created_schedule.json()["id"]
            assert writes.get(
                models.RecurringScan, created_schedule_id
            ).organization_id == tenant_a["org_id"]
        finally:
            writes.close(), path

        for method, path, body in foreign_mutations:
            response = client.request(
                method.upper(), path, headers=headers, json=body
            )
            assert response.status_code == 404, (
                method.upper(), path, response.status_code, response.text
            )

        # Enumerate the live OpenAPI GET surface so newly added tenant read
        # routes cannot silently escape this isolation suite. CVE detail is
        # explicitly global public-data access and is probed separately.
        path_values = {
            "scan_id": tenant_b["scan_id"],
            "service_id": tenant_b["service_id"],
            "cert_id": tenant_b["certificate_id"],
            "asset_id": tenant_b["asset_id"],
            "issue_id": tenant_b["issue_id"],
            "alert_id": tenant_b["alert_id"],
            "agent_id": tenant_b["agent_id"],
            "user_id": tenant_b["user_id"],
            "team_id": tenant_b["team_id"],
            "job_id": tenant_b["discovery_id"],
            "key_id": tenant_b["api_key_id"],
            "task_id": tenant_b["agent_task_id"],
        }
        for route_path, operations in app.openapi()["paths"].items():
            if route_path == "/api/cves/{cve_id}":
                continue  # CVE/NVD records are global public data (T8).
            if route_path.startswith("/api/organizations"):
                continue  # Platform-operator scope, not tenant data.
            if not route_path.startswith("/api/"):
                continue
            get_operation = operations.get("get")
            if get_operation is None:
                continue
            path_params = re.findall(r"\{([^}]+)\}", route_path)
            path = route_path
            for name in path_params:
                if name == "scan_id" and "recurring-scans" in path:
                    value = tenant_b["recurring_id"]
                else:
                    value = path_values.get(name)
                assert value is not None, (route_path, name)
                path = path.replace(f"{{{name}}}", str(value))
            response = client.get(path, headers=headers)
            expected_status = (
                200
                if route_path == "/api/discovery/{job_id}/results"
                else 404 if path_params else 200
            )
            assert response.status_code == expected_status, (
                route_path, response.status_code, response.text
            )
            assert tenant_b["discovery_result_id"] not in response.text, route_path
            if not path_params:
                for foreign_value in (
                    tenant_b["marker"],
                    tenant_b["scan_id"],
                    tenant_b["service_id"],
                    tenant_b["issue_id"],
                ):
                    assert foreign_value not in response.text, route_path

        mutation_payloads = {
            "set_service_owner_api_services__service_id__owner_patch": {
                "ownerUserId": None,
                "ownerTeamId": None,
            },
            "delete_asset_api_assets__asset_id__delete": None,
            "update_alert_status_api_alerts__alert_id__status_put": {
                "status": "read",
            },
            "update_issue_api_issues__issue_id__patch": {"status": "resolved"},
            "add_comment_api_issues__issue_id__comment_post": {
                "comment": "hidden",
            },
            "update_agent_api_agents__agent_id__patch": {"name": "changed"},
            "rotate_key_api_agents__agent_id__rotate_key_post": None,
            "revoke_agent_api_agents__agent_id__delete": None,
            "update_user_api_users__user_id__patch": {"name": "changed"},
            "delete_user_api_users__user_id__delete": None,
            "update_team_api_teams__team_id__patch": {
                "name": "changed",
                "description": "",
            },
            "delete_team_api_teams__team_id__delete": None,
            "add_member_api_teams__team_id__members_post": {
                "userId": tenant_a["user_id"],
            },
            "remove_member_api_teams__team_id__members__user_id__delete": None,
            "update_recurring_scan_api_recurring_scans__scan_id__patch": {
                "enabled": False,
            },
            "delete_recurring_scan_api_recurring_scans__scan_id__delete": None,
            "run_now_api_recurring_scans__scan_id__run_now_post": None,
            "cancel_discovery_api_discovery__job_id__delete": None,
            "revoke_api_key_api_api_keys__key_id__delete": None,
            "update_task_status_api_agent_tasks__task_id__status_post": {
                "status": "running",
            },
            "cancel_agent_task_api_agent_tasks__task_id__delete": None,
        }
        exercised_mutations = set()
        for route_path, operations in app.openapi()["paths"].items():
            if route_path.startswith("/api/organizations"):
                continue  # Platform-operator scope, not tenant data.
            path_params = re.findall(r"\{([^}]+)\}", route_path)
            if not path_params:
                continue
            mutating_operations = {
                method: operation
                for method, operation in operations.items()
                if method in {"post", "put", "patch", "delete"}
            }
            if not mutating_operations:
                continue
            path = route_path
            for name in path_params:
                if name == "scan_id" and "recurring-scans" in path:
                    value = tenant_b["recurring_id"]
                else:
                    value = path_values.get(name)
                assert value is not None, (route_path, name)
                path = path.replace(f"{{{name}}}", str(value))
            for method, operation in mutating_operations.items():
                operation_id = operation["operationId"]
                assert operation_id in mutation_payloads, (
                    "New path-parameter mutation requires an isolation probe",
                    method.upper(),
                    route_path,
                    operation_id,
                )
                response = client.request(
                    method.upper(),
                    path,
                    headers=headers,
                    json=mutation_payloads[operation_id],
                )
                expected = (
                    403
                    if operation_id
                    == "update_task_status_api_agent_tasks__task_id__status_post"
                    else 404
                )
                assert response.status_code == expected, (
                    method.upper(), route_path, response.status_code, response.text
                )
                exercised_mutations.add(operation_id)
        assert exercised_mutations == set(mutation_payloads)


def test_collection_mutation_routes_are_classified_and_tenant_scoped(
    complete_two_tenant_data, monkeypatch
):
    """Keep collection-level writes covered even when they have no foreign ID."""
    from types import SimpleNamespace

    from tls_analyzer.api.routers import discovery as discovery_router
    from tls_analyzer.api.routers import scans as scans_router
    from tls_analyzer.api.tenancy import get_session_org_id

    tenant_a = complete_two_tenant_data["a"]
    tenant_b = complete_two_tenant_data["b"]
    headers = {"Authorization": _authorization(tenant_a["token"])}

    # Tenant data mutations have direct two-organization probes. Auth lifecycle
    # routes use system-scoped refresh-token/bootstrap operations, while CVE
    # refresh is global public-data maintenance (T8).
    tenant_route_evidence = {
        "run_scan_api_scans_post": "this test: authenticated scan request scope",
        "start_discovery_api_discovery_post": "this test: persisted job ownership",
        "create_api_key_api_api_keys_post": (
            "test_two_complete_tenants_cover_required_detail_and_listing_isolation"
        ),
        "update_thresholds_api_settings_thresholds_put": (
            "this test: organization-specific thresholds"
        ),
            "update_ai_mode_api_settings_ai_mode_put": (
                "this test: organization-scoped AI egress policy and audit"
            ),
            "update_sla_settings_api_settings_sla_put": (
                "this test: organization-scoped SLA targets"
            ),
        "replace_compliance_windows_api_settings_compliance_windows_put": (
            "this test: organization-scoped compliance window replacement"
        ),
        "create_recurring_scan_api_recurring_scans_post": (
            "test_two_complete_tenants_cover_required_detail_and_listing_isolation"
        ),
        "create_user_api_users_post": (
            "test_two_complete_tenants_cover_required_detail_and_listing_isolation"
        ),
        "update_me_api_users_me_patch": "test_auth.py: self-profile is identity-scoped",
        "delete_me_api_users_me_delete": "test_delete_me_anonymizes",
        "change_my_password_api_users_me_password_post": (
            "test_password_change_requires_current"
        ),
        "bulk_assign_api_issues_assign_post": "this test: foreign issue is ignored",
        "create_team_api_teams_post": (
            "test_two_complete_tenants_cover_required_detail_and_listing_isolation"
        ),
        "create_agent_api_agents_post": (
            "test_two_complete_tenants_cover_required_detail_and_listing_isolation"
        ),
        "create_asset_api_assets_post": (
            "this test: organization-scoped asset creation"
        ),
        "heartbeat_api_agent_heartbeat_post": (
            "test_disabled_organization_blocks_password_login_refresh_and_api_key; "
            "test_heartbeat_and_offline_alert"
        ),
        "ingest_scan_api_agent_ingest_scan_post": (
            "test_agent_ingest_ownership_is_derived_from_key_across_organizations"
        ),
        "ingest_discovery_api_agent_ingest_discovery_post": (
            "test_agent_ingest_ownership_is_derived_from_key_across_organizations"
        ),
        "claim_tasks_api_agent_tasks_claim_post": (
            "test_agent_must_opt_in_before_claim_and_task_status_renews_lease"
        ),
    }
    explicitly_global_or_auth = {
        "refresh_cves_api_cves_refresh_post": "global CVE/NVD cache maintenance (T8)",
        "analyze_api_crypto_ml_analyze_post": "stateless Java analysis of the request body without tenant data access",
        "login_api_auth_login_post": "test_disabled_organization_blocks_password_login_refresh_and_api_key",
        "refresh_api_auth_refresh_post": "test_disabled_organization_blocks_password_login_refresh_and_api_key",
        "logout_api_auth_logout_post": (
            "system-scoped revocation by presented refresh-token hash; no tenant data response"
        ),
        "bootstrap_api_auth_bootstrap_post": (
            "system-scoped one-time initial-admin operation before tenant users exist"
        ),
        "create_organization_api_organizations_post": (
            "operator-only platform organization creation (system session)"
        ),
    }
    collection_mutations = {
        operation["operationId"]
        for route_path, operations in app.openapi()["paths"].items()
        if route_path.startswith("/api/")
        and not re.search(r"\{[^}]+\}", route_path)
        for method, operation in operations.items()
        if method in {"post", "put", "patch", "delete"}
    }
    assert set(tenant_route_evidence) | set(explicitly_global_or_auth) == (
        collection_mutations
    ), "Every collection mutation must be tenant-probed or explicitly exempted"

    seen_scan_organizations = []

    def fake_run_scan(db, target, port=None, options=None, pinned_target=None):
        seen_scan_organizations.append(get_session_org_id(db))
        assert pinned_target.address == "8.8.8.8"
        return {
            "id": f"tenant-scope-probe-{uuid4().hex[:8]}",
            "target": target,
            "host": target,
            "port": port or 443,
            "scanStartedAt": "2026-10-23T00:00:00+00:00",
        }

    monkeypatch.setattr(scans_router.scan_service, "run_scan", fake_run_scan)

    class NoopThread:
        def __init__(self, *args, **kwargs):
            pass

        def start(self):
            pass

    # Replace only the router module's threading binding, not the shared module.
    monkeypatch.setitem(
        discovery_router.start_discovery.__globals__,
        "threading",
        SimpleNamespace(Thread=NoopThread),
    )

    with TestClient(app) as client:
        scan_response = client.post(
            "/api/scans",
            headers=headers,
            json={
                "target": "8.8.8.8",
                "port": 443,
                "authorizationAccepted": True,
                "authorizationVersion": "2026-10-v1",
            },
        )
        assert scan_response.status_code == 200, scan_response.text
        assert seen_scan_organizations == [tenant_a["org_id"]]

        discovery_response = client.post(
            "/api/discovery",
            headers=headers,
            json={
                "ipRange": "8.8.8.8",
                "ports": [443],
                "authorizationAccepted": True,
                "authorizationVersion": "2026-10-v1",
            },
        )
        assert discovery_response.status_code == 200, discovery_response.text
        discovery_id = discovery_response.json()["id"]

        threshold_response = client.put(
            "/api/settings/thresholds",
            headers=headers,
            json={
                "criticalDays": 3,
                "warningDays": 12,
                "daysBeforeExpiry": [12, 3],
                "notifyOnCriticalFinding": True,
                "notifyOnCompliance": True,
            },
        )
        assert threshold_response.status_code == 200, threshold_response.text
        assert threshold_response.json()["criticalDays"] == 3

        ai_mode_response = client.put(
            "/api/settings/ai-mode",
            headers=headers,
            json={"mode": "external"},
        )
        assert ai_mode_response.status_code == 200, ai_mode_response.text
        assert ai_mode_response.json()["mode"] == "external"

        sla_response = client.put(
            "/api/settings/sla",
            headers=headers,
            json={"criticalDays": 3, "highDays": 9, "mediumDays": 21},
        )
        assert sla_response.status_code == 200, sla_response.text
        assert sla_response.json()["slaDaysCritical"] == 3
        tenant_b_sla = client.get(
            "/api/settings/organization",
            headers={"Authorization": _authorization(tenant_b["token"])},
        )
        assert tenant_b_sla.status_code == 200, tenant_b_sla.text
        assert tenant_b_sla.json()["slaDaysCritical"] != 3

        system = SessionLocal()
        set_system_session(system)
        try:
            assert system.get(models.Organization, tenant_a["org_id"]).ai_mode == "external"
            assert system.get(models.Organization, tenant_b["org_id"]).ai_mode == "template"
            audit = system.query(models.AuditLog).filter(
                models.AuditLog.organization_id == tenant_a["org_id"],
                models.AuditLog.action == "organization.ai_mode_changed",
            ).one()
            assert audit.meta["new_mode"] == "external"
        finally:
            system.close()

        compliance_response = client.put(
            "/api/settings/compliance-windows",
            headers=headers,
            json=[
                {
                    "name": "Tenant A PCI audit",
                    "framework": "PCI-DSS",
                    "auditDate": "2026-12-31",
                    "scopeFilter": ["payments.example.com"],
                }
            ],
        )
        assert compliance_response.status_code == 200, compliance_response.text
        assert len(compliance_response.json()) == 1
        tenant_b_windows = client.get(
            "/api/settings/compliance-windows",
            headers={"Authorization": _authorization(tenant_b["token"])},
        )
        assert tenant_b_windows.status_code == 200, tenant_b_windows.text
        assert tenant_b_windows.json() == []

        organization_response = client.get(
            "/api/settings/organization", headers=headers
        )
        assert organization_response.status_code == 200, organization_response.text
        assert organization_response.json()["id"] == tenant_a["org_id"]

        assignment_response = client.post(
            "/api/issues/assign",
            headers=headers,
            json={
                "issueIds": [tenant_b["issue_id"]],
                "ownerTeamId": tenant_a["team_id"],
            },
        )
        assert assignment_response.status_code == 200, assignment_response.text
        assert assignment_response.json()["updated"] == 0

        tenant_b_thresholds = client.get(
            "/api/settings/thresholds",
            headers={
                "Authorization": _authorization(tenant_b["token"]),
            },
        )
        assert tenant_b_thresholds.status_code == 200, tenant_b_thresholds.text
        assert tenant_b_thresholds.json()["criticalDays"] == 7

    verify = SessionLocal()
    set_system_session(verify)
    try:
        job = verify.get(models.DiscoveryJob, discovery_id)
        assert job is not None
        assert job.organization_id == tenant_a["org_id"]
        foreign_issue = verify.get(models.Issue, tenant_b["issue_id"])
        assert foreign_issue is not None
        assert foreign_issue.owner_team_id is None
        assert foreign_issue.organization_id == tenant_b["org_id"]
    finally:
        verify.close()


def test_agent_ingest_ownership_is_derived_from_key_across_organizations(
    complete_two_tenant_data,
):
    from tls_analyzer import analysis
    from tls_analyzer.api.deps import hash_api_key

    db = SessionLocal()
    set_system_session(db)
    keys = {
        "a": f"ingest-a-{uuid4().hex[:8]}",
        "b": f"ingest-b-{uuid4().hex[:8]}",
    }
    try:
        for label in ("a", "b"):
            record = complete_two_tenant_data[label]
            key = db.get(models.ApiKey, record["agent_key_id"])
            key.key_hash = hash_api_key(keys[label])
        db.commit()
    finally:
        db.close()

    with TestClient(app) as client:
        # Tenant/agent identity cannot be supplied by the message body.
        rejected = client.post(
            "/api/agent/ingest/scan",
            headers={"X-API-Key": keys["a"]},
            json={
                "schemaVersion": analysis.SCHEMA_VERSION,
                "rulesVersion": analysis.RULES_VERSION,
                "clientScanId": f"bad-{uuid4().hex[:8]}",
                "target": {"host": "same-agent-host.example", "port": 443},
                "organizationId": complete_two_tenant_data["b"]["org_id"],
            },
        )
        assert rejected.status_code == 422

        scan_ids = {}
        for label in ("a", "b"):
            response = client.post(
                "/api/agent/ingest/scan",
                headers={"X-API-Key": keys[label]},
                json={
                    "schemaVersion": analysis.SCHEMA_VERSION,
                    "rulesVersion": analysis.RULES_VERSION,
                    "clientScanId": f"valid-{label}-{uuid4().hex[:8]}",
                    "target": {"host": "same-agent-host.example", "port": 443},
                },
            )
            assert response.status_code == 201, response.text
            scan_ids[label] = response.json()["scanId"]

    verify = SessionLocal()
    set_system_session(verify)
    try:
        scans = {
            row.id: row
            for row in verify.query(models.Scan)
            .filter(models.Scan.id.in_(scan_ids.values()))
            .all()
        }
        assert {
            scans[scan_ids[label]].organization_id
            for label in ("a", "b")
        } == {
            complete_two_tenant_data["a"]["org_id"],
            complete_two_tenant_data["b"]["org_id"],
        }
        assert scans[scan_ids["a"]].agent_id == complete_two_tenant_data["a"]["agent_id"]
        assert scans[scan_ids["b"]].agent_id == complete_two_tenant_data["b"]["agent_id"]
        service_ids = {
            scans[scan_id].service_id for scan_id in scan_ids.values()
        }
        services = verify.query(models.Service).filter(
            models.Service.id.in_(service_ids)
        ).all()
        assert len(services) == 2
        assert {service.organization_id for service in services} == {
            complete_two_tenant_data["a"]["org_id"],
            complete_two_tenant_data["b"]["org_id"],
        }
    finally:
        verify.close()


def test_user_api_keys_are_scoped_to_the_owning_organization(
    complete_two_tenant_data,
):
    from tls_analyzer.api.deps import hash_api_key

    plaintext = {
        "a": f"user-a-{uuid4().hex[:8]}",
        "b": f"user-b-{uuid4().hex[:8]}",
    }
    setup = SessionLocal()
    set_system_session(setup)
    try:
        for label in ("a", "b"):
            key = setup.get(
                models.ApiKey, complete_two_tenant_data[label]["api_key_id"]
            )
            key.key_hash = hash_api_key(plaintext[label])
        setup.commit()
    finally:
        setup.close()

    with TestClient(app) as client:
        headers = {"X-API-Key": plaintext["a"]}
        listing = client.get("/api/services", headers=headers)
        assert listing.status_code == 200
        returned_ids = {row["id"] for row in listing.json()["items"]}
        assert complete_two_tenant_data["a"]["service_id"] in returned_ids
        assert complete_two_tenant_data["b"]["service_id"] not in returned_ids
        hidden = client.get(
            f"/api/services/{complete_two_tenant_data['b']['service_id']}",
            headers=headers,
        )
        assert hidden.status_code == 404


def test_alert_scheduler_uses_one_active_tenant_session_per_organization(monkeypatch):
    from tls_analyzer import alerts_engine

    suffix = uuid4().hex[:8]
    setup = SessionLocal()
    set_system_session(setup)
    try:
        active_orgs = [
            models.Organization(
                name=f"Alert active {label}-{suffix}",
                slug=f"alert-active-{label}-{suffix}",
                status="active",
            )
            for label in ("a", "b")
        ]
        disabled_org = models.Organization(
            name=f"Alert disabled-{suffix}",
            slug=f"alert-disabled-{suffix}",
            status="disabled",
        )
        setup.add_all([*active_orgs, disabled_org])
        setup.commit()
        active_ids = {org.id for org in active_orgs}
        disabled_id = disabled_org.id
    finally:
        setup.close()

    visited = []

    def record_scope(db):
        visited.append((db.info.get("tenant_mode"), db.info.get("organization_id")))
        return 0

    monkeypatch.setattr(alerts_engine, "generate_expiration_alerts", record_scope)
    monkeypatch.setattr(alerts_engine, "generate_compliance_alerts", record_scope)
    monkeypatch.setattr(alerts_engine, "generate_agent_offline_alerts", record_scope)
    alerts_engine.run_scheduled_alerts()

    visited_ids = {organization_id for mode, organization_id in visited if mode == "tenant"}
    assert active_ids <= visited_ids
    assert disabled_id not in visited_ids
    assert all(mode == "tenant" for mode, _ in visited)

    cleanup = SessionLocal()
    set_system_session(cleanup)
    try:
        cleanup.query(models.Organization).filter(
            models.Organization.id.in_([*active_ids, disabled_id])
        ).delete(synchronize_session=False)
        cleanup.commit()
    finally:
        cleanup.close()


def test_recurring_scan_scheduler_executes_due_jobs_in_active_org_scope(monkeypatch):
    from datetime import datetime, timedelta, timezone

    from tls_analyzer.api.services import recurring_scan_service

    suffix = uuid4().hex[:8]
    setup = SessionLocal()
    set_system_session(setup)
    try:
        active_orgs = [
            models.Organization(
                name=f"Recurring active {label}-{suffix}",
                slug=f"recurring-active-{label}-{suffix}",
                status="active",
            )
            for label in ("a", "b")
        ]
        disabled_org = models.Organization(
            name=f"Recurring disabled-{suffix}",
            slug=f"recurring-disabled-{suffix}",
            status="disabled",
        )
        setup.add_all([*active_orgs, disabled_org])
        setup.flush()
        schedules = []
        for index, org in enumerate([*active_orgs, disabled_org]):
            schedule = models.RecurringScan(
                host=f"scheduled-{index}-{suffix}.example",
                organization_id=org.id,
                enabled=True,
                next_run_at=datetime.now(timezone.utc) - timedelta(minutes=1),
            )
            setup.add(schedule)
            schedules.append(schedule)
        setup.commit()
        active_ids = {org.id for org in active_orgs}
        disabled_id = disabled_org.id
        expected = {
            (org.id, schedule.id)
            for org, schedule in zip([*active_orgs, disabled_org], schedules)
            if org.status == "active"
        }
        org_ids = [*active_ids, disabled_id]
        schedule_ids = [schedule.id for schedule in schedules]
    finally:
        setup.close()

    executed = []
    monkeypatch.setattr(
        recurring_scan_service,
        "_execute_scheduled_scan",
        lambda schedule_id, organization_id=None: executed.append(
            (organization_id, schedule_id)
        ),
    )
    recurring_scan_service.run_scheduled_scans_tick()
    assert set(executed) == expected
    assert not any(org_id == disabled_id for org_id, _ in executed)

    cleanup = SessionLocal()
    set_system_session(cleanup)
    try:
        cleanup.query(models.RecurringScan).filter(
            models.RecurringScan.id.in_(schedule_ids)
        ).delete(synchronize_session=False)
        cleanup.query(models.Organization).filter(
            models.Organization.id.in_(org_ids)
        ).delete(synchronize_session=False)
        cleanup.commit()
    finally:
        cleanup.close()

def test_refresh_and_merge_reject_cross_org_objects():
    from tls_analyzer.api.tenancy import set_tenant_session

    suffix = uuid4().hex[:8]
    setup = SessionLocal()
    set_system_session(setup)
    try:
        org_a = models.Organization(
            name=f"Refresh-A-{suffix}", slug=f"refresh-a-{suffix}", status="active"
        )
        org_b = models.Organization(
            name=f"Refresh-B-{suffix}", slug=f"refresh-b-{suffix}", status="active"
        )
        setup.add_all([org_a, org_b])
        setup.flush()
        service_a = models.Service(
            id=f"refresh-a-{suffix}", host=f"a-{suffix}", port=443,
            organization_id=org_a.id,
        )
        service_b = models.Service(
            id=f"refresh-b-{suffix}", host=f"b-{suffix}", port=443,
            organization_id=org_b.id,
        )
        setup.add_all([service_a, service_b])
        setup.commit()
        org_ids = [org_a.id, org_b.id]
        service_ids = [service_a.id, service_b.id]
        detached_b = setup.get(models.Service, service_b.id)
        setup.expunge(detached_b)
    finally:
        setup.close()

    tenant_db = SessionLocal()
    try:
        set_tenant_session(tenant_db, org_ids[0])
        with pytest.raises(ValueError, match="another organization"):
            tenant_db.refresh(detached_b)
        with pytest.raises(ValueError, match="another organization"):
            tenant_db.merge(detached_b)
        same_org = models.Service(
            id=f"refresh-a-{suffix}", host=f"a-{suffix}", port=443,
            organization_id=org_ids[0],
        )
        merged = tenant_db.merge(same_org)
        assert merged.organization_id == org_ids[0]
        tenant_db.rollback()
    finally:
        tenant_db.close()

    cleanup = SessionLocal()
    set_system_session(cleanup)
    try:
        cleanup.query(models.Service).filter(
            models.Service.id.in_(service_ids)
        ).delete(synchronize_session=False)
        cleanup.query(models.Organization).filter(
            models.Organization.id.in_(org_ids)
        ).delete(synchronize_session=False)
        cleanup.commit()
    finally:
        cleanup.close()


def test_startup_rejects_cross_org_parent_child_rows():
    from tls_analyzer.api.main import _assert_tenant_parent_consistency

    suffix = uuid4().hex[:8]
    db = SessionLocal()
    set_system_session(db)
    try:
        org_a = models.Organization(
            name=f"Parent-A-{suffix}", slug=f"parent-a-{suffix}", status="active"
        )
        org_b = models.Organization(
            name=f"Parent-B-{suffix}", slug=f"parent-b-{suffix}", status="active"
        )
        db.add_all([org_a, org_b])
        db.flush()
        asset_b = models.Asset(
            id=f"asset-b-{suffix}", hostname=f"asset-b-{suffix}",
            organization_id=org_b.id,
        )
        db.add(asset_b)
        db.flush()
        service_a = models.Service(
            id=f"service-a-{suffix}", host=f"service-a-{suffix}", port=443,
            asset_id=asset_b.id, organization_id=org_a.id,
        )
        db.add(service_a)
        db.commit()
        org_ids = [org_a.id, org_b.id]
        service_id = service_a.id
        asset_id = asset_b.id
    finally:
        db.close()

    with pytest.raises(RuntimeError, match=r"services\.asset_id"):
        _assert_tenant_parent_consistency()

    cleanup = SessionLocal()
    set_system_session(cleanup)
    try:
        cleanup.query(models.Service).filter(
            models.Service.id == service_id
        ).delete(synchronize_session=False)
        cleanup.query(models.Asset).filter(
            models.Asset.id == asset_id
        ).delete(synchronize_session=False)
        cleanup.query(models.Organization).filter(
            models.Organization.id.in_(org_ids)
        ).delete(synchronize_session=False)
        cleanup.commit()
    finally:
        cleanup.close()
