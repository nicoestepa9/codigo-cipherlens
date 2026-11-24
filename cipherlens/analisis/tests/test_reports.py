"""Tests de los endpoints de reporte para Grafana (Parte 6.2)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from tls_analyzer.api.db import SessionLocal
from tls_analyzer.api.main import app
from tls_analyzer.api.models import (
    Agent,
    Alert,
    ApiKey,
    Certificate,
    DiscoveryJob,
    DiscoveryResult,
    Finding,
    Issue,
    IssueHistory,
    Organization,
    Scan,
    Service,
    Team,
    User,
)
from tls_analyzer.api.services import user_service

PASSWORD = "Sup3rSecret!pass"
client = TestClient(app)


def _dt(y: int, m: int, d: int, h: int = 12) -> datetime:
    return datetime(y, m, d, h, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def _clean():
    """Limpia tablas compartidas (DB en memoria compartida) antes y despues."""
    def wipe() -> None:
        db = SessionLocal()
        try:
            db.query(DiscoveryResult).delete()
            db.query(DiscoveryJob).delete()
            db.query(IssueHistory).delete()
            db.query(Finding).delete()
            db.query(Issue).delete()
            db.query(Scan).delete()
            db.query(Certificate).delete()
            db.query(Service).delete()
            db.query(Agent).delete()
            db.query(ApiKey).delete()
            db.query(Alert).delete()
            db.query(User).filter(User.email.like("rep-%")).delete(synchronize_session=False)
            db.query(Team).delete()
            db.commit()
        finally:
            db.close()

    wipe()
    yield
    wipe()


def _make_service(db, host: str = "host.rep.local", *, agent_id=None, team_id=None) -> Service:
    s = Service(host=host, port=443, name=host, ip_address="10.0.0.1",
                agent_id=agent_id, default_owner_team_id=team_id)
    db.add(s)
    db.commit()
    db.refresh(s)
    return s


def _make_user(db, email: str, name: str) -> User:
    org = db.query(Organization).order_by(Organization.id).first()
    if org is None:
        org = Organization(name="CryptoGuard")
        db.add(org)
        db.flush()
    u = user_service.create_user(db, email=email, name=name, password=PASSWORD,
                                 role="lead", organization_id=org.id)
    db.commit()
    return u


def _make_issue(db, service: Service, *, severity="critical", status="open",
                first_seen=None, resolved_at=None, due_at=None,
                owner_user_id=None, owner_team_id=None, rule_id=None) -> Issue:
    _make_issue.seq += 1
    i = Issue(
        service_id=service.id, rule_id=rule_id or f"R-{_make_issue.seq}", title="t",
        severity=severity,
        status=status, first_seen_at=first_seen or _dt(2026, 1, 1),
        resolved_at=resolved_at, due_at=due_at,
        owner_user_id=owner_user_id, owner_team_id=owner_team_id,
    )
    db.add(i)
    db.commit()
    db.refresh(i)
    return i


_make_issue.seq = 0


# --------------------------------------------------------------- score-history

def test_score_history_buckets_and_ignores_non_completed():
    db = SessionLocal()
    try:
        svc = _make_service(db)
        for score, when, status in [
            (80, _dt(2026, 1, 1), "completed"),
            (100, _dt(2026, 1, 1), "completed"),
            (60, _dt(2026, 1, 2), "completed"),
            (10, _dt(2026, 1, 2), "failed"),
        ]:
            db.add(Scan(service_id=svc.id, host=svc.host, port=443, status=status,
                        score=score, started_at=when))
        db.commit()
    finally:
        db.close()

    r = client.get("/api/reports/score-history", params={
        "from": "2026-01-01T00:00:00Z", "to": "2026-01-03T23:59:59Z", "bucket": "day",
    })
    assert r.status_code == 200
    assert r.headers["cache-control"] == "private, max-age=60"
    data = r.json()
    assert [d["ts"] for d in data] == [
        "2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z", "2026-01-03T00:00:00Z",
    ]
    assert data[0] == {"ts": "2026-01-01T00:00:00Z", "avgScore": 90.0, "minScore": 80, "scans": 2}
    assert data[1]["avgScore"] == 60.0 and data[1]["scans"] == 1
    assert data[2] == {"ts": "2026-01-03T00:00:00Z", "avgScore": None, "minScore": None, "scans": 0}


# ---------------------------------------------------------------- issues-trend

def test_issues_trend_open_resolve_reopen():
    db = SessionLocal()
    try:
        svc = _make_service(db)
        issue = _make_issue(db, svc, severity="critical", status="open",
                            first_seen=_dt(2026, 1, 2), resolved_at=None)
        for ts, to_value in [
            (_dt(2026, 1, 2), "open"),
            (_dt(2026, 1, 4), "resolved"),
            (_dt(2026, 1, 6), "open"),
        ]:
            db.add(IssueHistory(issue_id=issue.id, ts=ts, event_type="test", to_value=to_value))
        db.commit()
    finally:
        db.close()

    r = client.get("/api/reports/issues-trend", params={
        "from": "2026-01-01T00:00:00Z", "to": "2026-01-07T23:59:59Z",
        "bucket": "day", "severity": "critical",
    })
    assert r.status_code == 200
    by_ts = {d["ts"]: d for d in r.json()}
    assert by_ts["2026-01-02T00:00:00Z"]["opened"] == 1
    assert by_ts["2026-01-02T00:00:00Z"]["openAtEnd"] == 1
    assert by_ts["2026-01-04T00:00:00Z"]["resolved"] == 1
    assert by_ts["2026-01-04T00:00:00Z"]["openAtEnd"] == 0
    assert by_ts["2026-01-06T00:00:00Z"]["opened"] == 1
    assert by_ts["2026-01-06T00:00:00Z"]["openAtEnd"] == 1
    assert by_ts["2026-01-07T00:00:00Z"]["openAtEnd"] == 1
    # Bucket sin datos -> ceros, no hueco.
    assert by_ts["2026-01-03T00:00:00Z"] == {
        "ts": "2026-01-03T00:00:00Z", "severity": "critical",
        "opened": 0, "resolved": 0, "openAtEnd": 1,
    }


def test_issues_trend_excludes_risk_accepted_and_false_positive():
    db = SessionLocal()
    try:
        svc = _make_service(db)
        _make_issue(db, svc, severity="high", status="risk_accepted", first_seen=_dt(2026, 1, 2))
        _make_issue(db, svc, severity="high", status="false_positive", first_seen=_dt(2026, 1, 2))
        db.commit()
    finally:
        db.close()

    r = client.get("/api/reports/issues-trend", params={
        "from": "2026-01-01T00:00:00Z", "to": "2026-01-03T23:59:59Z",
        "bucket": "day", "severity": "high",
    })
    assert r.status_code == 200
    assert all(d["openAtEnd"] == 0 for d in r.json())


# ---------------------------------------------------- certificates-by-expiry

def test_certificates_by_expiry():
    db = SessionLocal()
    try:
        for days, expired in [(-3, True), (3, False), (20, False), (60, False), (200, False)]:
            db.add(Certificate(domain="c.rep.local", days_until_expiry=days, is_expired=expired))
        db.commit()
    finally:
        db.close()

    r = client.get("/api/reports/certificates-by-expiry")
    assert r.status_code == 200
    assert r.json() == [
        {"bucket": "expired", "count": 1},
        {"bucket": "<=7d", "count": 1},
        {"bucket": "8-30d", "count": 1},
        {"bucket": "31-90d", "count": 1},
        {"bucket": ">90d", "count": 1},
    ]


# --------------------------------------------------------------- issues-by-owner

def test_issues_by_owner_masks_email_and_deleted_user():
    db = SessionLocal()
    try:
        svc = _make_service(db)
        user = _make_user(db, "rep-alt@corp.local", "Alice")
        ghost = _make_user(db, "rep-ghost@corp.local", "Ghost")
        team = Team(name="NetOps")
        db.add(team)
        db.commit()
        _make_issue(db, svc, severity="critical", status="open", owner_user_id=user.id)
        _make_issue(db, svc, severity="high", status="assigned", owner_team_id=team.id)
        _make_issue(db, svc, severity="low", status="open")
        _make_issue(db, svc, severity="low", status="open", owner_user_id=ghost.id)
        if db.get_bind().dialect.name == "postgresql":
            db.connection().exec_driver_sql(
                "SET LOCAL session_replication_role = replica"
            )
        db.query(User).filter(User.id == ghost.id).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()

    r = client.get("/api/reports/issues-by-owner")
    assert r.status_code == 200
    owners = {(o["ownerType"], o["ownerName"]): o for o in r.json()}
    assert owners[("user", "Alice")]["critical"] == 1
    assert owners[("team", "NetOps")]["high"] == 1
    assert ("none", "Sin owner") in owners
    assert owners[("user", "Usuario eliminado")]["open"] == 1
    assert "rep-alt@corp.local" not in r.text


# --------------------------------------------------------------- issues-by-status

def test_issues_by_status_includes_zeroes():
    db = SessionLocal()
    try:
        svc = _make_service(db)
        _make_issue(db, svc, status="open")
        _make_issue(db, svc, status="open")
        _make_issue(db, svc, status="resolved")
        db.commit()
    finally:
        db.close()

    r = client.get("/api/reports/issues-by-status")
    assert r.status_code == 200
    counts = {d["status"]: d["count"] for d in r.json()}
    assert counts["open"] == 2
    assert counts["resolved"] == 1
    assert counts["verified"] == 0


# --------------------------------------------------------------- shadow-it-trend

def test_shadow_it_trend():
    db = SessionLocal()
    try:
        job = DiscoveryJob(cidr_or_targets=["10.0.0.0/24"], started_at=_dt(2026, 1, 1))
        db.add(job)
        db.commit()
        db.refresh(job)
        for status, when in [("shadow_it", _dt(2026, 1, 1)), ("shadow_it", _dt(2026, 1, 2)),
                             ("inventoried", _dt(2026, 1, 2))]:
            db.add(DiscoveryResult(discovery_job_id=job.id, inventory_status=status, first_seen=when))
        db.commit()
    finally:
        db.close()

    r = client.get("/api/reports/shadow-it-trend", params={
        "from": "2026-01-01T00:00:00Z", "to": "2026-01-02T23:59:59Z", "bucket": "day",
    })
    assert r.status_code == 200
    data = r.json()
    assert data[0] == {"ts": "2026-01-01T00:00:00Z", "shadowIt": 1, "inventoried": 0}
    assert data[1] == {"ts": "2026-01-02T00:00:00Z", "shadowIt": 1, "inventoried": 1}


# ---------------------------------------------------------------- agents-status

def test_agents_status_lists_services():
    db = SessionLocal()
    try:
        agent = Agent(name="Sitio Central", site_label="HQ", status="active",
                      last_seen_at=datetime.now(timezone.utc))
        db.add(agent)
        db.commit()
        db.refresh(agent)
        _make_service(db, host="a.rep.local", agent_id=agent.id)
        _make_service(db, host="b.rep.local", agent_id=agent.id)
        db.commit()
    finally:
        db.close()

    r = client.get("/api/reports/agents-status")
    assert r.status_code == 200
    row = r.json()[0]
    assert row["agentId"]
    assert row["name"] == "Sitio Central"
    assert row["siteLabel"] == "HQ"
    assert row["services"] == 2
    assert row["online"] is True


# --------------------------------------------------------------------- summary

def test_summary_metrics():
    db = SessionLocal()
    try:
        agent = Agent(name="E2E Local", status="active")
        db.add(agent)
        db.flush()
        agent_id = agent.id
        svc = _make_service(db, agent_id=agent_id)
        _make_service(db, host="other.rep.local")
        now = datetime.now(timezone.utc)
        _make_issue(db, svc, severity="critical", status="open")
        _make_issue(db, svc, severity="high", status="open")
        _make_issue(db, svc, severity="critical", status="resolved",
                    resolved_at=now)
        _make_issue(db, svc, severity="medium", status="open", due_at=now - timedelta(days=1))
        db.add(Certificate(domain="c.rep.local", days_until_expiry=10, is_expired=False))
        db.add(Scan(service_id=svc.id, host=svc.host, port=443, status="completed",
                    score=70, started_at=now))
        db.commit()
    finally:
        db.close()

    r = client.get("/api/reports/summary")
    assert r.status_code == 200
    metrics = {m["metric"]: m["value"] for m in r.json()}
    assert metrics["totalServices"] == 2
    assert metrics["criticalOpen"] == 1
    assert metrics["highOpen"] == 1
    assert metrics["overdue"] == 1
    assert metrics["unassigned"] == 3
    assert metrics["certsExpiring30d"] == 1
    assert metrics["avgScore"] == 70.0
    all_response = client.get("/api/reports/summary", params={
        "agentId": "__all__", "teamId": "__all__", "serviceId": "__all__",
    })
    assert all_response.status_code == 200
    assert all_response.json() == r.json()

    agent_response = client.get("/api/reports/summary", params={
        "agentId": agent_id, "teamId": "__all__",
    })
    assert agent_response.status_code == 200
    agent_metrics = {m["metric"]: m["value"] for m in agent_response.json()}
    assert agent_metrics["totalServices"] == 1


def test_dimensions_shape():
    db = SessionLocal()
    try:
        svc = _make_service(db)
        team = Team(name="NetOps")
        db.add(team)
        agent = Agent(name="Sitio", site_label="HQ")
        db.add(agent)
        db.commit()
    finally:
        db.close()

    r = client.get("/api/reports/dimensions")
    assert r.status_code == 200
    data = r.json()
    assert set(data) == {"agents", "teams", "services"}
    assert data["teams"][0]["name"] == "NetOps"
    assert data["services"][0]["serviceId"]


# ---------------------------------------------------------------- validaciones

@pytest.mark.parametrize("params", [
    {"from": "2026-01-05T00:00:00Z", "to": "2026-01-01T00:00:00Z", "bucket": "day"},
    {"from": "2020-01-01T00:00:00Z", "to": "2026-01-01T00:00:00Z", "bucket": "day"},
    {"from": "2026-01-01T00:00:00Z", "to": "2026-01-05T00:00:00Z", "bucket": "month"},
])
def test_report_validation_returns_422(params):
    r = client.get("/api/reports/score-history", params=params)
    assert r.status_code == 422


# -------------------------------------------------------------------- permisos

@pytest.fixture()
def auth_on(monkeypatch):
    from tls_analyzer.api.config import settings

    monkeypatch.setattr(settings, "disable_api_auth", False)
    monkeypatch.setattr(settings, "auth_rate_limit_per_minute", 10000)
    yield


def test_reports_require_credentials(auth_on):
    assert client.get("/api/reports/summary").status_code == 401


def test_reports_allow_viewer_session(auth_on):
    db = SessionLocal()
    try:
        user = _make_user(db, "rep-viewer@corp.local", "Viewer")
        user.role = "viewer"
        db.commit()
        from tls_analyzer.api.services import auth_service

        token = auth_service.create_access_token(user.id, user.role)
    finally:
        db.close()
    r = client.get("/api/reports/summary", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200


def test_reports_allow_viewer_api_key(auth_on):
    db = SessionLocal()
    try:
        from tls_analyzer.api.services import integration_service

        _dto, plain = integration_service.create_api_key(db, "grafana", role="viewer")
    finally:
        db.close()
    r = client.get("/api/reports/summary", headers={"X-API-Key": plain})
    assert r.status_code == 200


def test_reports_block_agent_key(auth_on):
    db = SessionLocal()
    try:
        from tls_analyzer.api.services import agent_service

        _dto, plain = agent_service.create_agent(db, "site", "A", actor_user_id=None)
    finally:
        db.close()
    r = client.get("/api/reports/summary", headers={"X-API-Key": plain})
    assert r.status_code == 403

