"""Tests de scans recurrentes (CRUD, run-now, comparacion, alertas)."""

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from tls_analyzer.cloud_network import NonPublicTargetError
from tls_analyzer.api.db import SessionLocal
from tls_analyzer.api.main import app
from tls_analyzer.api.models import Alert, Finding, RecurringScan, Scan, Service
from tls_analyzer.api.services import agent_service, recurring_scan_service
from tls_analyzer.api.services.scan_service import persist_scan


@pytest.fixture(autouse=True)
def _clean_state(monkeypatch):
    from tls_analyzer.api import cloud_guardrails

    monkeypatch.setattr(
        cloud_guardrails,
        "resolve_target_addresses",
        lambda host, enforce_public=True: ("8.8.8.8",),
    )
    db = SessionLocal()
    try:
        db.query(RecurringScan).delete()
        test_scan_ids = [
            row[0]
            for row in db.query(Scan.id).filter(Scan.host.in_(("t.com", "h"))).all()
        ]
        if test_scan_ids:
            db.query(Finding).filter(Finding.scan_id.in_(test_scan_ids)).delete(
                synchronize_session=False
            )
        db.query(Alert).filter(Alert.related_target == "t.com:443").delete(
            synchronize_session=False
        )
        db.query(Scan).filter(Scan.host.in_(("t.com", "h"))).delete(
            synchronize_session=False
        )
        db.query(Service).filter(Service.host.in_(("t.com", "h"))).delete(
            synchronize_session=False
        )
        from tls_analyzer.api.models import AuditLog

        db.query(AuditLog).filter(
            AuditLog.action.in_(
                (
                    "cloud_scan.authorization_accepted",
                    "cloud_scan.destination_blocked",
                    "cloud_scan.quota_rejected",
                    "cloud_scan.scheduled_started",
                    "cloud_scan.started",
                    "cloud_discovery.started",
                    "recurring_scan.quota_rejected",
                )
            )
        ).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()
    yield
    db = SessionLocal()
    try:
        db.query(RecurringScan).delete()
        test_scan_ids = [
            row[0]
            for row in db.query(Scan.id).filter(Scan.host.in_(("t.com", "h"))).all()
        ]
        if test_scan_ids:
            db.query(Finding).filter(Finding.scan_id.in_(test_scan_ids)).delete(
                synchronize_session=False
            )
        db.query(Alert).filter(Alert.related_target == "t.com:443").delete(
            synchronize_session=False
        )
        db.query(Scan).filter(Scan.host.in_(("t.com", "h"))).delete(
            synchronize_session=False
        )
        db.query(Service).filter(Service.host.in_(("t.com", "h"))).delete(
            synchronize_session=False
        )
        db.query(AuditLog).filter(
            AuditLog.action.in_(
                (
                    "cloud_scan.authorization_accepted",
                    "cloud_scan.destination_blocked",
                    "cloud_scan.quota_rejected",
                    "cloud_scan.scheduled_started",
                    "cloud_scan.started",
                    "cloud_discovery.started",
                    "recurring_scan.quota_rejected",
                )
            )
        ).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()


def _client():
    return TestClient(app)


def _authorized(**values):
    return {
        **values,
        "authorizationAccepted": True,
        "authorizationVersion": "2026-10-v1",
    }


# --------------------------------------------------------------------------
# Endpoints CRUD
# --------------------------------------------------------------------------

def test_create_recurring_scan():
    with _client() as client:
        resp = client.post(
            "/api/recurring-scans",
            json=_authorized(
                host="example.com",
                port=443,
                intervalHours=24.0,
                profile="citizen-facing",
                enabled=True,
            ),
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["host"] == "example.com"
        assert data["intervalHours"] == 24.0
        assert data["enabled"] is True
        assert data["id"] > 0


def test_create_recurring_scan_for_agent_uses_payload_target():
    db = SessionLocal()
    try:
        agent, _ = agent_service.create_agent(
            db,
            name="recurring-agent",
            site_label="Sitio",
            actor_user_id=None,
        )
        agent_id = agent["id"]
    finally:
        db.close()

    with _client() as client:
        resp = client.post(
            "/api/recurring-scans",
            json={
                "host": "agent-target.local",
                "port": 8443,
                "agentId": agent_id,
                "intervalHours": 24.0,
                "enabled": True,
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["host"] == "agent-target.local"
        assert data["port"] == 8443
        assert data["agentId"] == agent_id


def test_list_recurring_scans_filter_enabled():
    with _client() as client:
        client.post("/api/recurring-scans", json=_authorized(host="a.com", enabled=True))
        client.post("/api/recurring-scans", json=_authorized(host="b.com", enabled=False))
        all_rows = client.get("/api/recurring-scans").json()
        enabled = client.get("/api/recurring-scans?enabled=true").json()
        assert len(all_rows) == 2
        assert all(r["enabled"] for r in enabled)
        assert len(enabled) == 1


def test_patch_recurring_scan():
    with _client() as client:
        created = client.post(
            "/api/recurring-scans", json=_authorized(host="a.com")
        ).json()
        resp = client.patch(f"/api/recurring-scans/{created['id']}",
                            json=_authorized(intervalHours=48.0, enabled=False))
        assert resp.status_code == 200
        data = resp.json()
        assert data["intervalHours"] == 48.0
        assert data["enabled"] is False


def test_get_recurring_scan_detail_includes_recent_scans():
    with _client() as client:
        created = client.post(
            "/api/recurring-scans", json=_authorized(host="a.com")
        ).json()
        resp = client.get(f"/api/recurring-scans/{created['id']}")
        assert resp.status_code == 200
        data = resp.json()
        assert "recentScans" in data
        assert data["recentScans"] == []


def test_delete_recurring_scan_sets_scan_fk_null():
    db = SessionLocal()
    try:
        schedule = recurring_scan_service.create_recurring_scan(
            db, recurring_scan_service.RecurringScanCreate(host="a.com")
        )
        scan = Scan(host="a.com", port=443, target="a.com:443", origin="scheduled",
                    recurring_scan_id=schedule.id, status="completed")
        db.add(scan)
        db.commit()
        db.refresh(scan)
        recurring_scan_service.delete_recurring_scan(db, schedule)
        db.refresh(scan)
        assert scan.recurring_scan_id is None
        assert db.get(RecurringScan, schedule.id) is None
    finally:
        db.close()


def test_404_get_missing_recurring_scan():
    with _client() as client:
        resp = client.get("/api/recurring-scans/999999")
        assert resp.status_code == 404


def test_recurring_scan_requires_current_authorization_consent():
    with _client() as client:
        missing = client.post("/api/recurring-scans", json={"host": "example.com"})
        stale = client.post(
            "/api/recurring-scans",
            json={
                "host": "example.com",
                "authorizationAccepted": True,
                "authorizationVersion": "old-version",
            },
        )
        assert missing.status_code == stale.status_code == 422


def test_recurring_scan_quota_is_audited_and_returns_conflict():
    from tls_analyzer.api.models import AuditLog, Organization

    db = SessionLocal()
    organization = db.get(Organization, 1)
    original_limit = organization.max_recurring_scans
    organization.max_recurring_scans = 1
    db.commit()
    db.close()
    try:
        with _client() as client:
            first = client.post(
                "/api/recurring-scans", json=_authorized(host="first.example")
            )
            second = client.post(
                "/api/recurring-scans", json=_authorized(host="second.example")
            )
        assert first.status_code == 201
        assert second.status_code == 409
        db = SessionLocal()
        try:
            assert db.query(AuditLog).filter(
                AuditLog.action == "recurring_scan.quota_rejected"
            ).count() >= 1
        finally:
            db.close()
    finally:
        db = SessionLocal()
        organization = db.get(Organization, 1)
        organization.max_recurring_scans = original_limit
        db.commit()
        db.close()


def test_recurring_scheduler_interleaves_due_tenants():
    assert recurring_scan_service._round_robin_schedule_keys(
        [1, 2, 3],
        {
            1: [(1, 10), (1, 11), (1, 12)],
            2: [(2, 20)],
            3: [(3, 30), (3, 31)],
        },
    ) == [
        (1, 10),
        (2, 20),
        (3, 30),
        (1, 11),
        (3, 31),
        (1, 12),
    ]


def test_manual_and_tick_scheduled_runs_share_global_concurrency_limit(monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    import threading
    import time

    from tls_analyzer.api.config import settings

    active = 0
    highest = 0
    lock = threading.Lock()

    def fake_execute(schedule_id, organization_id=None):
        nonlocal active, highest
        with lock:
            active += 1
            highest = max(highest, active)
        time.sleep(0.02)
        with lock:
            active -= 1

    monkeypatch.setattr(
        recurring_scan_service, "_execute_scheduled_scan_with_slot", fake_execute
    )
    workers = max(2, settings.max_concurrent_scans * 2)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        list(pool.map(recurring_scan_service._execute_scheduled_scan, range(workers)))

    assert highest <= settings.max_concurrent_scans


def test_scheduled_scan_re_resolves_and_uses_pinned_public_address(monkeypatch):
    from tls_analyzer.api.services import scan_service

    db = SessionLocal()
    schedule = recurring_scan_service.create_recurring_scan(
        db,
        recurring_scan_service.RecurringScanCreate(
            host="scheduled.example", port=8443
        ),
    )
    schedule_id = schedule.id
    db.close()

    captured = []
    monkeypatch.setattr(
        recurring_scan_service,
        "resolve_target_addresses",
        lambda host, enforce_public=True: ("8.8.8.8",),
    )
    monkeypatch.setattr(
        scan_service,
        "run_scan",
        lambda db, target, **kwargs: captured.append((target, kwargs)),
    )
    recurring_scan_service._execute_scheduled_scan(schedule_id)

    assert len(captured) == 1
    target, options = captured[0]
    assert target == "scheduled.example"
    assert options["port"] == 8443
    assert options["pinned_target"].address == "8.8.8.8"


def test_scheduled_scan_blocks_private_target_and_audits(monkeypatch):
    from tls_analyzer.api.models import AuditLog

    db = SessionLocal()
    schedule = recurring_scan_service.create_recurring_scan(
        db,
        recurring_scan_service.RecurringScanCreate(host="127.0.0.1", port=443),
    )
    schedule_id = schedule.id
    db.close()
    monkeypatch.setattr(
        recurring_scan_service,
        "resolve_target_addresses",
        lambda host, enforce_public=True: (_ for _ in ()).throw(
            NonPublicTargetError("private target")
        ),
    )

    recurring_scan_service._execute_scheduled_scan(schedule_id)

    db = SessionLocal()
    try:
        assert db.query(AuditLog).filter(
            AuditLog.action == "cloud_scan.destination_blocked",
            AuditLog.entity_id == "127.0.0.1:443",
        ).count() == 1
        updated = db.get(RecurringScan, schedule_id)
        assert updated is not None
        assert updated.consecutive_failures == 1
        assert updated.is_running is False
    finally:
        db.close()


def test_scheduled_scan_respects_hourly_cloud_quota(monkeypatch):
    from tls_analyzer.api.models import AuditLog, Organization
    from tls_analyzer.api.services import scan_service

    db = SessionLocal()
    organization = db.query(Organization).first()
    original_limit = organization.max_cloud_scans_per_hour
    organization.max_cloud_scans_per_hour = 1
    db.add(AuditLog(
        actor_type="system",
        action="cloud_scan.started",
        entity_type="cloud_target",
        entity_id="prior-target.example",
        organization_id=organization.id,
    ))
    schedule = recurring_scan_service.create_recurring_scan(
        db,
        recurring_scan_service.RecurringScanCreate(host="quota.example", port=443),
    )
    schedule_id = schedule.id
    db.commit()
    db.close()
    monkeypatch.setattr(
        recurring_scan_service,
        "resolve_target_addresses",
        lambda host, enforce_public=True: ("8.8.8.8",),
    )
    monkeypatch.setattr(
        scan_service,
        "run_scan",
        lambda *args, **kwargs: pytest.fail("quota must block scheduled scan"),
    )

    try:
        recurring_scan_service._execute_scheduled_scan(schedule_id)
        db = SessionLocal()
        try:
            assert db.query(AuditLog).filter(
                AuditLog.action == "cloud_scan.quota_rejected",
                AuditLog.entity_id == str(schedule_id),
            ).count() == 1
            updated = db.get(RecurringScan, schedule_id)
            assert updated.next_run_at - updated.last_run_at >= timedelta(hours=1)
        finally:
            db.close()
    finally:
        db = SessionLocal()
        organization = db.query(Organization).first()
        organization.max_cloud_scans_per_hour = original_limit
        db.commit()
        db.close()


def test_persist_scan_defaults_origin_manual():
    """El endpoint manual debe seguir creando scans origin=manual sin recurring_scan_id."""
    from tls_analyzer import analysis

    db = SessionLocal()
    try:
        result = analysis.AnalysisResult(
            host="h", port=443,
            started_at=datetime.now(timezone.utc).isoformat(), duration_ms=10,
        )
        row = persist_scan(db, result)
        assert row.origin == "manual"
        assert row.recurring_scan_id is None
    finally:
        db.close()


# --------------------------------------------------------------------------
# Comparacion entre corridas
# --------------------------------------------------------------------------

def _make_scan(db, *, score, findings, service, started_at=None, extra_cert=None):
    scan = Scan(
        host="t.com", port=443, target="t.com:443", status="completed",
        score=score, service_id=service.id,
        started_at=started_at or datetime.now(timezone.utc),
        raw_result={"certificate": extra_cert or {}},
    )
    db.add(scan)
    db.flush()
    for rule_id, sev in findings:
        db.add(Finding(scan_id=scan.id, rule_id=rule_id, severity=sev,
                       title=rule_id, evaluable=True))
    db.flush()
    return scan


def _make_service(db):
    # (host, port) es unico para el inventario de plataforma (Parte 5): reusar
    # si ya existe para no violar el constraint entre tests.
    svc = db.query(Service).filter(Service.host == "t.com", Service.port == 443).first()
    if svc is None:
        svc = Service(host="t.com", port=443)
        db.add(svc)
        db.flush()
    return svc


def test_comparison_no_previous_is_baseline():
    db = SessionLocal()
    try:
        svc = _make_service(db)
        scan = _make_scan(db, score=60, findings=[("CIPH-01", "critical")], service=svc)
        cmp = recurring_scan_service.compute_scan_comparison(db, scan)
        assert cmp.has_previous is False
    finally:
        db.close()


def test_comparison_detects_regression():
    db = SessionLocal()
    try:
        svc = _make_service(db)
        prev = _make_scan(db, score=80, findings=[("CIPH-01", "high")], service=svc)
        scan = _make_scan(db, score=50, findings=[("CIPH-01", "high"), ("PROTO-01", "critical")], service=svc)
        cmp = recurring_scan_service.compute_scan_comparison(db, scan)
        assert cmp.has_previous is True
        assert cmp.score_delta == -30
        assert cmp.new_critical_or_high_rule_ids == ["PROTO-01"]
        assert cmp.resolved_rule_ids == []
    finally:
        db.close()


def test_comparison_detects_resolved():
    db = SessionLocal()
    try:
        svc = _make_service(db)
        prev = _make_scan(db, score=50, findings=[("PROTO-01", "critical")], service=svc)
        scan = _make_scan(db, score=80, findings=[], service=svc)
        cmp = recurring_scan_service.compute_scan_comparison(db, scan)
        assert cmp.score_delta == 30
        assert cmp.resolved_rule_ids == ["PROTO-01"]
        assert cmp.new_critical_or_high_rule_ids == []
    finally:
        db.close()


def test_comparison_expiry_crossed_threshold():
    db = SessionLocal()
    try:
        from tls_analyzer.api.models import AlertThreshold

        # fijar umbral deterministico (7 dias) para no depender de estado compartido
        threshold = db.query(AlertThreshold).first()
        if threshold is None:
            threshold = AlertThreshold(days_before_expiry=[30, 15, 7], critical_days=7, warning_days=30)
            db.add(threshold)
        threshold.critical_days = 7
        db.commit()

        svc = _make_service(db)
        prev = _make_scan(db, score=70, findings=[], service=svc, extra_cert={"daysUntilExpiry": 15})
        scan = _make_scan(db, score=70, findings=[], service=svc, extra_cert={"daysUntilExpiry": 5})
        # asegurar prev queda como el "anterior" (prev > scan en started_at)
        scan.started_at = datetime.now(timezone.utc) + timedelta(seconds=1)
        db.commit()
        cmp = recurring_scan_service.compute_scan_comparison(db, scan)
        assert cmp.certificate_expiry_crossed_threshold is True
    finally:
        db.close()


# --------------------------------------------------------------------------
# Alertas tras corrida programada
# --------------------------------------------------------------------------

def test_regression_alert_created():
    db = SessionLocal()
    try:
        svc = _make_service(db)
        prev = _make_scan(db, score=80, findings=[("CIPH-01", "high")], service=svc)
        scan = _make_scan(db, score=40, findings=[("CIPH-01", "high"), ("PROTO-01", "critical")], service=svc)
        schedule = recurring_scan_service.create_recurring_scan(
            db, recurring_scan_service.RecurringScanCreate(host="t.com")
        )
        comparison = recurring_scan_service.compute_scan_comparison(db, scan)
        n = recurring_scan_service.handle_scheduled_scan_alerts(db, schedule, comparison)
        assert n >= 1
        alert = db.query(Alert).filter(Alert.type == "vulnerability_regression").first()
        assert alert is not None
        assert "empeor" in alert.description.lower() or "worsened" in alert.description.lower()
    finally:
        db.close()


def test_run_now_executes_and_updates_schedule():
    """run-now dispara el scan programado y actualiza last/next run. Usa host no alcanzable
    — el scan falla graciosamente (sin excepcion) pero el schedule se marca como corrido."""
    db = SessionLocal()
    try:
        schedule = recurring_scan_service.create_recurring_scan(
            db, recurring_scan_service.RecurringScanCreate(
                host="nonexistent.invalid.internal", port=443, intervalHours=1.0
            )
        )
        recurring_scan_service._execute_scheduled_scan(schedule.id)
        db.expire_all()
        updated = db.get(RecurringScan, schedule.id)
        assert updated.last_run_at is not None
        assert updated.next_run_at > updated.last_run_at
        assert updated.is_running is False
    finally:
        db.close()
