"""Tests del motor de discovery (asyncio puro)."""

import pytest

from tls_analyzer import discovery


def test_is_internal_ip():
    assert discovery.is_internal_ip("10.0.0.1") is True
    assert discovery.is_internal_ip("192.168.1.1") is True
    assert discovery.is_internal_ip("172.16.0.1") is True
    assert discovery.is_internal_ip("127.0.0.1") is True
    assert discovery.is_internal_ip("8.8.8.8") is False
    assert discovery.is_internal_ip("not-an-ip") is False


def test_expand_cidr():
    ips = discovery.expand_cidr("10.0.0.0/30")
    assert ips == ["10.0.0.1", "10.0.0.2"]
    assert discovery.expand_cidr("127.0.0.1") == ["127.0.0.1"]
    assert discovery.expand_cidr("garbage") == []


def test_parse_targets():
    targets = discovery.parse_targets("127.0.0.1, 10.0.0.1", [])
    assert targets == [("127.0.0.1", None), ("10.0.0.1", None)]
    assert len(discovery.parse_targets("", [])) == 0


def test_run_discovery_sync_closed_port():
    found = discovery.run_discovery_sync(
        ip_range="127.0.0.1",
        ports=[9],
        timeout=0.3,
    )
    assert found == []


def test_scan_ip_closed_port():
    found = discovery.run_discovery_sync(
        ip_range="127.0.0.1", ports=[65432], timeout=0.3
    )
    assert isinstance(found, list)


def test_progress_callback_called():
    calls = []
    discovery.run_discovery_sync(
        ip_range="127.0.0.1, 127.0.0.2", ports=[9], timeout=0.3,
        progress_cb=lambda done, total: calls.append((done, total)),
    )
    assert calls == [(1, 2), (2, 2)]


def _make_job(status: str, progress: int) -> str:
    from tls_analyzer.api.db import SessionLocal
    from tls_analyzer.api.models import DiscoveryJob

    db = SessionLocal()
    try:
        job = DiscoveryJob(
            cidr_or_targets=["10.0.0.0/24"],
            port_list=[443],
            domains=[],
            scan_internal=True,
            status=status,
            progress=progress,
        )
        db.add(job)
        db.commit()
        return job.id
    finally:
        db.close()


def test_reap_orphaned_jobs_closes_stale_running_jobs():
    from tls_analyzer.api.db import SessionLocal
    from tls_analyzer.api.models import DiscoveryJob
    from tls_analyzer.api.services.discovery_service import reap_orphaned_jobs

    running_id = _make_job("running", 64)
    queued_id = _make_job("queued", 0)
    completed_id = _make_job("completed", 100)

    assert reap_orphaned_jobs() == 2

    db = SessionLocal()
    try:
        for job_id in (running_id, queued_id):
            job = db.get(DiscoveryJob, job_id)
            assert job.status == "failed"
            assert job.error == "Interrupted by server restart"
            assert job.completed_at is not None
        # Un job ya terminado no se toca.
        assert db.get(DiscoveryJob, completed_id).status == "completed"
    finally:
        db.close()


def test_reap_orphaned_jobs_is_idempotent():
    from tls_analyzer.api.services.discovery_service import reap_orphaned_jobs

    _make_job("running", 10)
    assert reap_orphaned_jobs() == 1
    # La segunda pasada no encuentra nada que cerrar.
    assert reap_orphaned_jobs() == 0


def test_estimate_target_count_matches_real_expansion():
    est = discovery.estimate_target_count
    # Un /30 son 2 hosts usables, los mismos que devuelve expand_cidr.
    assert est("10.0.0.0/30", []) == len(discovery.expand_cidr("10.0.0.0/30"))
    assert est("127.0.0.1", []) == 1
    assert est("", []) == 0
    assert est("10.0.0.0/24", []) == 254
    # Varios tokens separados por coma o espacio.
    assert est("127.0.0.1, 10.0.0.1", []) == 2
    # Cada dominio cuenta como piso 1 (puede resolver a mas de una IP).
    assert est("127.0.0.1", ["example.com", "other.com"]) == 3
    assert est("basura", []) == 0


def test_estimate_target_count_rejects_huge_range():
    assert discovery.estimate_target_count("10.0.0.0/8", []) == 16_777_214


def test_create_job_rejects_range_over_limit():
    from tls_analyzer.api.db import SessionLocal
    from tls_analyzer.api.services import discovery_service

    db = SessionLocal()
    try:
        with pytest.raises(discovery_service.DiscoveryTargetTooLarge) as exc:
            discovery_service.create_job(db, {"ipRange": "10.0.0.0/16", "ports": [443]})
        assert exc.value.estimated == 65_534
        assert "Range too large" in str(exc.value)
        # Un /19 entra justo y si se crea.
        job = discovery_service.create_job(db, {"ipRange": "10.0.0.0/19", "ports": [443]})
        assert job.status == "queued"
    finally:
        db.close()


def test_create_job_allows_range_at_the_limit():
    from tls_analyzer.api.db import SessionLocal
    from tls_analyzer.api.services import discovery_service

    db = SessionLocal()
    try:
        job = discovery_service.create_job(db, {"ipRange": "10.0.0.0/19", "ports": [443]})
        assert job.status == "queued"
    finally:
        db.close()


def test_run_discovery_sync_raises_when_cancel_check_true():
    calls = []

    def _always_cancel():
        return True

    with pytest.raises(discovery.DiscoveryCancelled):
        discovery.run_discovery_sync(
            ip_range="127.0.0.1", ports=[9], timeout=0.3,
            progress_cb=lambda done, total: calls.append((done, total)),
            cancel_check=_always_cancel,
        )
    # Se aborta antes de escanear: ningun probe llego a completarse.
    assert calls == []


def test_run_discovery_sync_cancel_triggers_midway():
    """El scan se frena a mitad de camino, no solo al arranque."""
    state = {"done": 0}

    def _cancel_after_first():
        return state["done"] >= 1

    def _progress(done, total):
        state["done"] = done

    with pytest.raises(discovery.DiscoveryCancelled):
        discovery.run_discovery_sync(
            ip_range="127.0.0.1, 127.0.0.2, 127.0.0.3, 127.0.0.4",
            ports=[9], timeout=0.3,
            progress_cb=_progress,
            max_concurrency=1,
            cancel_check=_cancel_after_first,
        )
    # Con max_concurrency=1 se completaron 1 host y se abortó el resto.
    assert state["done"] == 1


def test_request_cancel_marks_job_and_signals_worker():
    from tls_analyzer.api.db import SessionLocal
    from tls_analyzer.api.models import DiscoveryJob
    from tls_analyzer.api.services.discovery_service import (
        _cancel_was_requested,
        request_cancel,
    )

    job_id = _make_job("running", 5)
    assert request_cancel(job_id) is True
    assert _cancel_was_requested(job_id) is True

    db = SessionLocal()
    try:
        job = db.get(DiscoveryJob, job_id)
        assert job.status == "cancelled"
        assert job.completed_at is not None
    finally:
        db.close()

    # Un job ya terminal no se puede volver a cancelar.
    assert request_cancel(job_id) is False
    assert request_cancel("no-existe") is False


def test_run_job_cloud_without_pinned_targets_fails_closed(monkeypatch):
    from tls_analyzer.api.db import SessionLocal
    from tls_analyzer.api.models import DiscoveryJob
    from tls_analyzer.api.services import discovery_service

    job_id = _make_job("queued", 0)

    def forbidden_scan(*_args, **_kwargs):
        raise AssertionError("cloud job without pinned targets must not scan")

    monkeypatch.setattr(discovery_service, "run_discovery_sync", forbidden_scan)
    discovery_service.run_job(job_id)

    db = SessionLocal()
    try:
        job = db.get(DiscoveryJob, job_id)
        assert job.status == "failed"
        assert "pinned targets" in job.error
    finally:
        db.close()


def test_run_job_cloud_pinned_targets_enforce_public(monkeypatch):
    from tls_analyzer.api.db import SessionLocal
    from tls_analyzer.api.models import DiscoveryJob
    from tls_analyzer.api.services import discovery_service

    db = SessionLocal()
    try:
        job = DiscoveryJob(
            cidr_or_targets=["8.8.8.0/30"],
            port_list=[443],
            domains=[],
            resolved_targets=[{"ip": "8.8.8.8", "hostname": None}],
            scan_internal=False,
            status="queued",
            progress=0,
        )
        db.add(job)
        db.commit()
        job_id = job.id
    finally:
        db.close()

    calls = {}

    def fake_scan(**kwargs):
        calls.update(kwargs)
        return []

    monkeypatch.setattr(discovery_service, "run_discovery_sync", fake_scan)
    discovery_service.run_job(job_id)

    assert calls["enforce_public"] is True
    assert calls["resolved_targets"] == [("8.8.8.8", None)]

    db = SessionLocal()
    try:
        assert db.get(DiscoveryJob, job_id).status == "completed"
    finally:
        db.close()


def test_run_job_cancelled_leaves_status_cancelled():
    """El worker que aborta por cancelacion no pisa el estado a 'failed'."""
    from tls_analyzer.api.db import SessionLocal
    from tls_analyzer.api.models import DiscoveryJob
    from tls_analyzer.api.services.discovery_service import request_cancel, run_job

    job_id = _make_job("running", 0)
    assert request_cancel(job_id) is True
    # run_job ve el flag apenas arranca y aborta de inmediato.
    run_job(job_id)

    db = SessionLocal()
    try:
        assert db.get(DiscoveryJob, job_id).status == "cancelled"
    finally:
        db.close()


def test_upsert_result_updates_tls_on_matched_asset():
    """Discovery debe completar el TLS del asset existente, no solo del resultado."""
    from tls_analyzer.api.db import SessionLocal
    from tls_analyzer.api.models import Asset, DiscoveryJob, Organization
    from tls_analyzer.api.services.discovery_service import _upsert_result
    from tls_analyzer.api.tenancy import set_system_session, set_tenant_session
    from tls_analyzer.discovery import DiscoveredService

    db = SessionLocal()
    try:
        set_system_session(db)
        org = db.query(Organization).order_by(Organization.id).first()
        assert org is not None
        set_tenant_session(db, org.id)
        asset = Asset(
            ip_address="192.0.2.44",
            hostname="tls-asset.test",
            port=443,
            organization_id=org.id,
        )
        job = DiscoveryJob(
            cidr_or_targets=["192.0.2.44"],
            port_list=[443],
            domains=[],
            scan_internal=False,
            status="completed",
            organization_id=org.id,
        )
        db.add_all([asset, job])
        db.flush()

        _upsert_result(
            db,
            job,
            DiscoveredService(
                ip_address="192.0.2.44",
                hostname="tls-asset.test",
                port=443,
                has_tls=True,
                tls_version="TLSv1.3",
            ),
        )

        assert asset.tls_version == "TLSv1.3"
    finally:
        db.rollback()
        db.close()
