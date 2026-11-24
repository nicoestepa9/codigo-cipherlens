"""Tests de Issues, ownership y equipos (Parte 2)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from tls_analyzer.api.db import SessionLocal
from tls_analyzer.api.main import app
from tls_analyzer.api.models import (
    Alert,
    Finding,
    Issue,
    IssueHistory,
    Organization,
    Scan,
    Service,
    Team,
    User,
)
from tls_analyzer.api.services import auth_service, issue_service, user_service
from tls_analyzer.api.tenancy import set_system_session, set_tenant_session


PASSWORD = "Sup3rSecret!pass"


def _make_user(db, email: str, role: str = "lead") -> User:
    org = db.query(Organization).order_by(Organization.id).first()
    if org is None:
        org = Organization(name="CryptoGuard")
        db.add(org)
        db.flush()
    u = user_service.create_user(
        db, email=email, name=email, password=PASSWORD,
        role=role, organization_id=org.id,
    )
    db.commit()
    return u


@pytest.fixture(autouse=True)
def _clean():
    """Limpia tablas compartidas entre tests (DB en memoria compartida)."""
    db = SessionLocal()
    try:
        db.query(IssueHistory).delete()
        db.query(Issue).delete()
        db.query(Finding).delete()
        db.query(Scan).delete()
        db.query(Service).delete()
        db.query(Team).delete()
        db.query(Alert).delete()
        db.commit()
    finally:
        db.close()
    yield


def _make_service(db, host: str = "example.com", *, owner_user=None, owner_team=None) -> Service:
    s = Service(
        host=host, port=443, name=host, ip_address="1.2.3.4",
        default_owner_user_id=owner_user.id if owner_user else None,
        default_owner_team_id=owner_team.id if owner_team else None,
    )
    db.add(s)
    db.commit()
    db.refresh(s)
    return s


def _make_scan(db, service: Service, findings: list[dict], *, status: str = "completed") -> Scan:
    scan = Scan(
        service_id=service.id, host=service.host, port=service.port,
        status=status, started_at=datetime.now(timezone.utc),
    )
    db.add(scan)
    db.flush()
    for f in findings:
        db.add(Finding(
            scan_id=scan.id,
            rule_id=f["ruleId"],
            title=f.get("title", f["ruleId"]),
            severity=f.get("severity", "medium"),
            source_document=f.get("sourceDocument", "80052"),
            evaluable=f.get("evaluable", True),
            status=f.get("status"),
            affected_host=service.host,
        ))
    db.flush()
    return scan


def _reconcile(db, scan: Scan):
    dtos = [
        {
            "ruleId": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "sourceDocument": f.source_document,
            "evaluable": f.evaluable,
            "status": f.status,
        }
        for f in db.query(Finding).filter(Finding.scan_id == scan.id).all()
    ]
    issue_service.reconcile_scan(db, scan, dtos)
    db.commit()


# ---------------------------------------------------------------------------
# Reconciliacion / identidad
# ---------------------------------------------------------------------------

def test_identity_dedup_same_rule_across_scans():
    db = SessionLocal()
    try:
        svc = _make_service(db)
        s1 = _make_scan(db, svc, [{"ruleId": "TLS-01", "severity": "high"}])
        _reconcile(db, s1)
        s2 = _make_scan(db, svc, [{"ruleId": "TLS-01", "severity": "high"}])
        _reconcile(db, s2)

        issues = db.query(Issue).filter(Issue.service_id == svc.id).all()
        assert len(issues) == 1
        issue = issues[0]
        assert issue.rule_id == "TLS-01"
        assert issue.source_document == "80052"
        # last_seen actualizado al segundo scan
        assert issue.last_scan_id == s2.id
        # vinculado al finding
        f2 = db.query(Finding).filter(Finding.scan_id == s2.id).first()
        assert f2.issue_id == issue.id
    finally:
        db.close()


def test_min_severity_filters_low_findings():
    db = SessionLocal()
    try:
        svc = _make_service(db)
        s = _make_scan(db, svc, [
            {"ruleId": "LOW-1", "severity": "low"},
            {"ruleId": "MED-1", "severity": "medium"},
        ])
        _reconcile(db, s)
        rules = {i.rule_id for i in db.query(Issue).all()}
        # ISSUE_MIN_SEVERITY=medium -> low no genera issue
        assert rules == {"MED-1"}
    finally:
        db.close()


def test_status_open_by_default_and_assigned_when_service_has_owner():
    db = SessionLocal()
    try:
        owner = _make_user(db, "owner1@example.com")
        svc_no = _make_service(db, "no-owner.com")
        s_no = _make_scan(db, svc_no, [{"ruleId": "R1", "severity": "high"}])
        _reconcile(db, s_no)
        issue_no = db.query(Issue).filter(Issue.service_id == svc_no.id).first()
        assert issue_no.status == "open"

        svc_yes = _make_service(db, "with-owner.com", owner_user=owner)
        s_yes = _make_scan(db, svc_yes, [{"ruleId": "R1", "severity": "high"}])
        _reconcile(db, s_yes)
        issue_yes = db.query(Issue).filter(Issue.service_id == svc_yes.id).first()
        assert issue_yes.status == "assigned"
    finally:
        db.close()


def test_sla_due_at_uses_organization_override():
    db = SessionLocal()
    org = db.query(Organization).order_by(Organization.id).first()
    try:
        org.sla_days_high = 2
        org.sla_days_medium = 11
        db.commit()

        svc = _make_service(db, "org-sla.com")
        scan = _make_scan(db, svc, [{"ruleId": "ORG-SLA", "severity": "high"}])
        _reconcile(db, scan)

        issue = db.query(Issue).filter(Issue.rule_id == "ORG-SLA").first()
        assert issue.organization_id == org.id
        expected = issue.first_seen_at.replace(tzinfo=timezone.utc) + timedelta(days=2)
        assert issue.due_at.replace(tzinfo=timezone.utc) == expected
        assert issue_service.sla_days_for("medium", org) == 11
    finally:
        org.sla_days_critical = None
        org.sla_days_high = None
        org.sla_days_medium = None
        db.commit()
        db.close()


def test_sla_due_at_computed_and_recalculated_on_higher_severity():
    db = SessionLocal()
    try:
        svc = _make_service(db)
        s1 = _make_scan(db, svc, [{"ruleId": "R1", "severity": "medium"}])
        _reconcile(db, s1)
        issue = db.query(Issue).filter(Issue.rule_id == "R1").first()
        expected_due = issue.first_seen_at.replace(tzinfo=timezone.utc) + timedelta(days=issue_service.sla_days_for("medium"))
        assert issue.due_at.replace(tzinfo=timezone.utc) == expected_due

        s2 = _make_scan(db, svc, [{"ruleId": "R1", "severity": "critical"}])
        _reconcile(db, s2)
        db.refresh(issue)
        assert issue.severity == "critical"
        expected_due2 = issue.last_seen_at.replace(tzinfo=timezone.utc) + timedelta(days=issue_service.sla_days_for("critical"))
        assert issue.due_at.replace(tzinfo=timezone.utc) == expected_due2
    finally:
        db.close()


def test_existing_issue_due_at_is_not_recomputed_when_org_sla_changes():
    db = SessionLocal()
    org = db.query(Organization).order_by(Organization.id).first()
    try:
        org.sla_days_high = 3
        db.commit()
        svc = _make_service(db, "sla-immutable.com")
        scan = _make_scan(
            db, svc, [{"ruleId": "SLA-IMMUTABLE", "severity": "high"}]
        )
        _reconcile(db, scan)
        issue = db.query(Issue).filter(Issue.rule_id == "SLA-IMMUTABLE").first()
        original_due = issue.due_at
        assert original_due is not None

        org.sla_days_high = 30
        db.commit()
        scan2 = _make_scan(
            db, svc, [{"ruleId": "SLA-IMMUTABLE", "severity": "high"}]
        )
        _reconcile(db, scan2)
        db.refresh(issue)

        assert issue.due_at == original_due
    finally:
        org.sla_days_high = None
        db.commit()
        db.close()


def test_auto_resolve_when_finding_disappears():
    db = SessionLocal()
    try:
        svc = _make_service(db)
        s1 = _make_scan(db, svc, [{"ruleId": "R1", "severity": "high"}])
        _reconcile(db, s1)
        issue = db.query(Issue).filter(Issue.rule_id == "R1").first()
        assert issue.status == "open"

        s2 = _make_scan(db, svc, [])  # ya no aparece
        _reconcile(db, s2)
        db.refresh(issue)
        assert issue.status == "resolved"
        assert issue.resolved_by == "system"
        assert issue.clean_scans_since_resolved == 1
    finally:
        db.close()


def test_auto_verify_after_clean_scans_threshold():
    db = SessionLocal()
    try:
        svc = _make_service(db)
        s1 = _make_scan(db, svc, [{"ruleId": "R1", "severity": "high"}])
        _reconcile(db, s1)
        issue = db.query(Issue).filter(Issue.rule_id == "R1").first()
        assert issue.status == "open"

        # desaparece -> resolved
        s2 = _make_scan(db, svc, [])
        _reconcile(db, s2)
        db.refresh(issue)
        assert issue.status == "resolved"

        # reaparece -> reopen
        s3 = _make_scan(db, svc, [{"ruleId": "R1", "severity": "high"}])
        _reconcile(db, s3)
        db.refresh(issue)
        assert issue.status == "open"
        assert issue.reopened_count == 1
        assert issue.clean_scans_since_resolved == 0

        # vuelve a desaparecer -> resolved
        s4 = _make_scan(db, svc, [])
        _reconcile(db, s4)
        db.refresh(issue)
        assert issue.status == "resolved"

        # scans limpios suficientes -> verified
        threshold = max(1, issue_service.settings.issue_verify_after_clean_scans)
        for _ in range(threshold):
            s = _make_scan(db, svc, [])
            _reconcile(db, s)
        db.refresh(issue)
        assert issue.status == "verified"
        assert issue.verified_at is not None
    finally:
        db.close()


def test_risk_accepted_expires_on_next_scan():
    db = SessionLocal()
    try:
        svc = _make_service(db)
        s1 = _make_scan(db, svc, [{"ruleId": "R1", "severity": "high"}])
        _reconcile(db, s1)
        issue = db.query(Issue).filter(Issue.rule_id == "R1").first()

        issue_service.change_status(
            db, issue, "risk_accepted", actor_user_id=None,
            reason="excepcion aprobada",
            risk_accepted_until=(datetime.now(timezone.utc) - timedelta(days=1)).isoformat(),
        )
        db.commit()
        assert issue.status == "risk_accepted"

        # reaparece con la aceptacion vencida -> vuelve a open
        s2 = _make_scan(db, svc, [{"ruleId": "R1", "severity": "high"}])
        _reconcile(db, s2)
        db.refresh(issue)
        assert issue.status == "open"
    finally:
        db.close()


def test_failed_scan_does_not_reconcile():
    db = SessionLocal()
    try:
        svc = _make_service(db)
        s = _make_scan(db, svc, [{"ruleId": "R1", "severity": "high"}], status="failed")
        issue_service.reconcile_scan(db, s, [])  # no deberia crear nada
        db.commit()
        assert db.query(Issue).count() == 0
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Owner removal al borrar usuario
# ---------------------------------------------------------------------------

def test_deleting_user_clears_issue_owner_and_raises_alert():
    db = SessionLocal()
    try:
        owner = _make_user(db, "owner2@example.com")
        svc = _make_service(db, owner_user=owner)
        s = _make_scan(db, svc, [{"ruleId": "R1", "severity": "high"}])
        _reconcile(db, s)
        issue = db.query(Issue).filter(Issue.rule_id == "R1").first()
        assert issue.status == "assigned"

        # asignar owner explicito al issue para probar el clear
        issue_service.assign(db, issue, owner_user_id=owner.id, owner_team_id=None, actor_user_id=None)
        db.commit()

        user_service.anonymize_and_delete(db, owner)
        db.commit()

        db.refresh(issue)
        assert issue.owner_user_id is None
        assert issue.status == "open"
        events = [h.event_type for h in issue.history]
        assert "owner_removed" in events
        alert = db.query(Alert).filter(
            Alert.type == "issue_owner_removed", Alert.related_issue_id == issue.id
        ).first()
        assert alert is not None
    finally:
        db.close()


# ---------------------------------------------------------------------------
# API: issues, transiciones, teams, owner de service
# ---------------------------------------------------------------------------

def _client() -> TestClient:
    return TestClient(app)


def test_api_list_get_and_transition_issue():
    db = SessionLocal()
    try:
        svc = _make_service(db)
        s = _make_scan(db, svc, [{"ruleId": "R1", "severity": "high", "title": "TLS finding"}])
        _reconcile(db, s)
        issue = db.query(Issue).filter(Issue.rule_id == "R1").first()
    finally:
        db.close()

    with _client() as client:
        resp = client.get("/api/issues")
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] >= 1
        assert any(i["id"] == issue.id for i in body["items"])

        resp = client.get(f"/api/issues/{issue.id}")
        assert resp.status_code == 200
        detail = resp.json()
        assert detail["ruleId"] == "R1"
        assert "serviceHost" in detail
        assert isinstance(detail["history"], list)

        # resolver
        resp = client.patch(f"/api/issues/{issue.id}", json={"status": "resolved", "comment": "arreglado"})
        assert resp.status_code == 200
        assert resp.json()["status"] == "resolved"

        # verificar solo desde resolved
        resp = client.patch(f"/api/issues/{issue.id}", json={"status": "verified"})
        assert resp.status_code == 200
        assert resp.json()["status"] == "verified"

        # transicion invalida: verified -> in_progress
        resp = client.patch(f"/api/issues/{issue.id}", json={"status": "in_progress"})
        assert resp.status_code == 400

        # reabrir un issue verificado (regresión: "reopened" debía estar en VALID_STATUSES)
        resp = client.patch(f"/api/issues/{issue.id}", json={"status": "reopened"})
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "open"
        assert body["reopenedCount"] == 1


def test_api_assign_owner_and_bulk_assign():
    db = SessionLocal()
    try:
        owner = _make_user(db, "owner3@example.com")
        svc = _make_service(db)
        s = _make_scan(db, svc, [
            {"ruleId": "R1", "severity": "high"},
            {"ruleId": "R2", "severity": "medium"},
        ])
        _reconcile(db, s)
        ids = [i.id for i in db.query(Issue).all()]
    finally:
        db.close()

    with _client() as client:
        resp = client.patch(f"/api/issues/{ids[0]}", json={"ownerUserId": owner.id})
        assert resp.status_code == 200
        body = resp.json()
        assert body["ownerUserId"] == owner.id
        assert body["status"] == "assigned"

        resp = client.post("/api/issues/assign", json={"issueIds": ids, "ownerUserId": owner.id})
        assert resp.status_code == 200
        assert resp.json()["updated"] == len(ids)


def test_api_teams_crud_and_membership():
    with _client() as client:
        resp = client.post("/api/teams", json={"name": "Equipo Rojo", "description": "rojo"})
        assert resp.status_code == 201
        team = resp.json()
        assert team["name"] == "Equipo Rojo"

        # duplicado -> 409
        resp = client.post("/api/teams", json={"name": "Equipo Rojo"})
        assert resp.status_code == 409

        db = SessionLocal()
        try:
            u = _make_user(db, "member1@example.com")
            uid = u.id
        finally:
            db.close()

        resp = client.post(f"/api/teams/{team['id']}/members", json={"userId": uid})
        assert resp.status_code == 200
        assert uid in resp.json()["memberIds"]

        resp = client.get("/api/teams")
        assert resp.status_code == 200
        assert any(t["id"] == team["id"] and t["memberCount"] == 1 for t in resp.json())

        resp = client.delete(f"/api/teams/{team['id']}/members/{uid}")
        assert resp.status_code == 200
        assert uid not in resp.json()["memberIds"]


def test_api_service_default_owner_endpoint():
    db = SessionLocal()
    try:
        owner = _make_user(db, "svcowner@example.com")
        svc = _make_service(db, "owner-svc.com")
        sid = svc.id
        oid = owner.id
    finally:
        db.close()

    with _client() as client:
        resp = client.patch(f"/api/services/{sid}/owner", json={"ownerUserId": oid})
        assert resp.status_code == 200
        body = resp.json()
        assert body["ownerUserId"] == oid

        resp = client.get(f"/api/services/{sid}/owner")
        assert resp.status_code == 200
        assert resp.json()["ownerUserId"] == oid


def test_effective_owner_falls_back_to_service_default():
    db = SessionLocal()
    try:
        owner = _make_user(db, "effowner@example.com")
        svc = _make_service(db, owner_user=owner)
        s = _make_scan(db, svc, [{"ruleId": "R1", "severity": "high"}])
        _reconcile(db, s)
        issue = db.query(Issue).filter(Issue.rule_id == "R1").first()
        # issue sin owner propio
        assert issue.owner_user_id is None
        out = issue_service.to_out(db, issue)
        assert out["effectiveOwnerUserId"] == owner.id
        assert out["ownerName"] is not None
    finally:
        db.close()

def test_default_org_id_uses_tenant_session():
    db = SessionLocal()
    try:
        set_system_session(db)
        org = Organization(name="Tenant issue org", slug="tenant-issue-org")
        db.add(org)
        db.commit()
        db.refresh(org)
        set_tenant_session(db, org.id)
        assert issue_service.default_org_id(db) == org.id
        db.delete(org)
        db.commit()
    finally:
        db.close()
