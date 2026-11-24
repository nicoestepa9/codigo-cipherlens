"""Tests del programa agente (Parte 5.5/5.6): config, minimizacion, cliente, e2e."""

from __future__ import annotations

import json

import httpx
import pytest

from tls_analyzer import analysis
from tls_analyzer.agent import state
from tls_analyzer.agent.client import (
    AgentClient,
    AgentFatalAuthError,
    AgentIngestError,
)
from tls_analyzer.agent.config import AgentConfig, ConfigError, load_config
from tls_analyzer.agent.minimize import build_scan_payload
from tls_analyzer.agent.pseudonymize import Pseudonymizer


@pytest.fixture
def state_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("CRYPTOGUARD_AGENT_STATE_DIR", str(tmp_path))
    return tmp_path


def _fake_ar() -> analysis.AnalysisResult:
    return analysis.AnalysisResult(
        host="intranet.corp.local",
        port=443,
        score=80,
        status="completed",
        started_at="2024-10-01T00:00:00+00:00",
        duration_ms=10,
        ip_address="10.0.0.5",
        negotiated_protocol="TLSv1.2",
        supported_protocols=["TLSv1.2", "TLSv1.3"],
        findings=[
            {
                "ruleId": "PROTO-01",
                "title": "Protocolo obsoleto",
                "description": "El servidor admite TLS 1.0.",
                "evidence": "TLSv1.0 aceptado",
                "recommendation": "Deshabilitar TLS 1.0",
                "sectionReference": "4.1",
                "citation": "NIST SP 800-52r2",
                "severity": "high",
                "category": "protocol",
                "affectedHost": "intranet.corp.local",
            }
        ],
        certificate={
            "keyType": "RSA",
            "keySize": 2048,
            "signatureAlgorithm": "sha256WithRSAEncryption",
            "notBefore": "2024-01-01",
            "notAfter": "2025-01-01",
            "isExpired": False,
            "daysUntilExpiry": 90,
            "fingerprintSha256": "ab:cd",
            "subject": {"CN": "intranet.corp.local"},
            "issuer": {"CN": "Corp CA"},
            "san": ["intranet.corp.local"],
        },
        chain=[{"subject": {"CN": "Corp CA"}, "issuer": {"CN": "Root CA"}}],
        handshake={"ip_address": "10.0.0.5", "negotiated_protocol": "TLSv1.2", "cipher_suites": []},
        os_fingerprint={"detected": True, "banner": "nginx", "raw_banner": "Server: nginx"},
        raw_result={"big": "payload"},
    )


# --- minimizacion ---------------------------------------------------------

def test_minimal_payload_strips_sensitive_fields():
    payload = build_scan_payload(_fake_ar(), "cid-1", "minimal")
    assert "handshake" not in payload
    assert "rawResult" not in payload
    assert "chain" not in payload
    assert "san" not in payload["certificate"]
    assert "subject" not in payload["certificate"]
    assert "banner" not in payload["osFingerprint"]
    assert "raw_banner" not in payload["osFingerprint"]
    assert payload["certificate"]["keyType"] == "RSA"


def test_standard_payload_has_cert_no_raw():
    payload = build_scan_payload(_fake_ar(), "c", "standard")
    assert "rawResult" not in payload
    assert "chain" in payload
    assert payload["certificate"]["san"]
    assert "ip_address" in payload["handshake"]


def test_full_payload_includes_raw():
    payload = build_scan_payload(_fake_ar(), "c", "full")
    assert payload["rawResult"] == {"big": "payload"}
    assert "cipher_suites" in payload["handshake"]


# -- sin raw_result ni handshake crudo en minimal/standard --
def test_no_raw_leak_minimal_standard():
    for level in ("minimal", "standard"):
        payload = build_scan_payload(_fake_ar(), "c", level)
        blob = json.dumps(payload)
        assert "raw_banner" not in blob
        assert "payload" not in blob  # rawResult no debe filtrarse


# -- pseudonimizacion --
def test_pseudonymize_internal_stable(state_dir):
    secret = state.ensure_secret()
    p = Pseudonymizer(secret, "internal")
    h1 = p.host("intranet.corp.local")
    assert h1.startswith("host-")
    assert p.host("example.com") == "example.com"
    assert p.ip("10.0.0.5").startswith("ip-")
    assert p.ip("8.8.8.8") == "8.8.8.8"
    p.flush()

    # Estable entre corridas (mismo secreto + mapeo en disco).
    p2 = Pseudonymizer(state.ensure_secret(), "internal")
    assert p2.host("intranet.corp.local") == h1


def test_pseudonymize_strict_and_mapping(state_dir):
    secret = state.ensure_secret()
    p = Pseudonymizer(secret, "strict")
    assert p.host("example.com").startswith("host-")
    assert p.ip("8.8.8.8").startswith("ip-")
    p.flush()

    pseudo = p.host("intranet.corp.local")
    assert p.host("intranet.corp.local") == pseudo
    p.flush()
    assert state.resolve_pseudonym(pseudo) == "intranet.corp.local"

    out = state_dir / "map.csv"
    count = state.export_mapping_csv(str(out))
    assert count >= 1
    text = open(out, encoding="utf-8").read()
    assert "intranet.corp.local" in text


def test_pseudonymize_payload_hides_real_values(state_dir):
    payload = build_scan_payload(_fake_ar(), "c", "standard")
    p = Pseudonymizer(state.ensure_secret(), "strict")
    out = p.apply_scan(payload)
    blob = json.dumps(out)
    assert "intranet.corp.local" not in blob
    assert "10.0.0.5" not in blob
    assert out["target"]["host"].startswith("host-")
    assert out["ipAddress"].startswith("ip-")
    assert out["findings"][0]["affectedHost"].startswith("host-")


def test_export_and_resolve(state_dir):
    secret = state.ensure_secret()
    p = Pseudonymizer(secret, "strict")
    pseudo = p.host("host.internal")
    p.flush()
    assert state.resolve_pseudonym(pseudo) == "host.internal"
    out = state_dir / "mapa.csv"
    assert state.export_mapping_csv(str(out)) >= 1
    assert "host.internal" in out.read_text(encoding="utf-8")


# -- configuracion --
def test_config_rejects_http(tmp_path):
    cfg = tmp_path / "agent.yaml"
    cfg.write_text("server_url: http://platform.example.com\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(str(cfg))


def test_config_accepts_https(tmp_path):
    cfg = tmp_path / "agent.yaml"
    cfg.write_text(
        "server_url: https://platform.example.com\n"
        "targets:\n  - host: a.local\n    port: 443\n",
        encoding="utf-8",
    )
    c = load_config(str(cfg))
    assert c.server_url == "https://platform.example.com"
    assert c.targets[0].host == "a.local"


def test_config_allows_http_localhost_only_with_flag(tmp_path):
    cfg = tmp_path / "agent.yaml"
    cfg.write_text("server_url: http://localhost:8000\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(str(cfg))
    ok = load_config(str(cfg), allow_insecure_localhost=True)
    assert ok.server_url == "http://localhost:8000"


def test_invalid_upload_level(tmp_path):
    cfg = tmp_path / "agent.yaml"
    cfg.write_text(
        "server_url: https://x.test\nupload_level: burner\n", encoding="utf-8"
    )
    with pytest.raises(ConfigError):
        load_config(str(cfg))


# -- cliente --
class _ScriptedTransport(httpx.BaseTransport):
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = 0

    def handle_request(self, request):
        self.calls += 1
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        status, headers, body = item
        return httpx.Response(
            status, headers=headers, content=body, request=request
        )


def _client(transport, *, key="cg_secret_key", retries=3):
    config = AgentConfig(server_url="https://platform.test", max_concurrent=1)
    config.api_key_env = "DUMMY_UNSET_VAR"
    return AgentClient(config, transport=transport)


def test_client_fatal_on_401():
    t = _ScriptedTransport([(401, {}, b'{"detail":"bad"}')])
    client = _client(t)
    with pytest.raises(AgentFatalAuthError):
        client.ingest_scan({"clientScanId": "x"})
    assert t.calls == 1


def test_client_no_retry_on_422():
    t = _ScriptedTransport([(422, {}, b'{"detail":"bad"}')])
    client = _client(t)
    with pytest.raises(AgentIngestError):
        client.ingest_scan({"clientScanId": "x"})
    assert t.calls == 1


def test_client_retries_5xx_same_payload_and_backs_off():
    sleeps: list[float] = []
    t = _ScriptedTransport([
        (500, {}, b"err"),
        (502, {}, b"err"),
        (201, {}, b'{"scanId":"s1"}'),
    ])
    config = AgentConfig(server_url="https://platform.test")
    client = AgentClient(config, transport=t, sleep=sleeps.append)
    resp = client.ingest_scan({"clientScanId": "stable-id"})
    assert resp["scanId"] == "s1"
    assert t.calls == 3
    assert len(sleeps) == 2
    assert sleeps[1] > sleeps[0]  # backoff creciente


def test_client_honors_retry_after():
    sleeps: list[float] = []
    t = _ScriptedTransport([(429, {"Retry-After": "2"}, b""), (201, {}, b'{"scanId":"s2"}')])
    client = AgentClient(
        AgentConfig(server_url="https://platform.test"), transport=t, sleep=sleeps.append
    )
    client.ingest_scan({"clientScanId": "y"})
    assert sleeps and 2.0 <= sleeps[0] <= 3.0


def test_client_verify_never_false():
    client = _client(_ScriptedTransport([(201, {}, b"{}")]))
    assert client.verify is not False
    client.close()


def test_key_not_in_dry_run_output(state_dir, monkeypatch, capsys):
    monkeypatch.setenv("CRYPTOGUARD_AGENT_KEY", "cg_super_secret")
    monkeypatch.setattr(
        "tls_analyzer.agent.runner.analyze_target", lambda *a, **k: _fake_ar()
    )
    from tls_analyzer.agent.config import TargetConfig

    config = AgentConfig(
        server_url="https://platform.test",
        pseudonymize="off",
        upload_level="standard",
        targets=[TargetConfig(host="intranet.corp.local", port=443)],
    )
    config.api_key_env = "CRYPTOGUARD_AGENT_KEY"
    from tls_analyzer.agent.runner import AgentRunner

    code = AgentRunner(config, dry_run=True, once=True).run()
    assert code == 0
    out = capsys.readouterr()
    assert "cg_super_secret" not in out.out + out.err
    assert "intranet.corp.local" in out.out


def test_verify_never_false_and_https_default():
    config = AgentConfig(server_url="https://platform.test")
    assert config.verify is True
    config2 = AgentConfig(server_url="https://platform.test", ca_bundle="/tmp/ca.pem")
    assert config2.verify == "/tmp/ca.pem"


# -- e2e: agente -> app real via transporte de prueba --
class _TestClientTransport(httpx.BaseTransport):
    def __init__(self, test_client):
        self.tc = test_client

    def handle_request(self, request):
        path = request.url.path
        if request.url.query:
            path += "?" + request.url.query.decode()
        headers = {k.decode(): v.decode() for k, v in request.headers.raw}
        resp = self.tc.request(
            request.method, path, content=request.content, headers=headers
        )
        return httpx.Response(
            resp.status_code, headers=resp.headers, content=resp.content, request=request
        )


def test_agent_e2e_once(state_dir, monkeypatch, clean_db_after):
    from fastapi.testclient import TestClient

    from tls_analyzer.api.db import SessionLocal
    from tls_analyzer.api.main import app
    from tls_analyzer.api.services import agent_service

    db = SessionLocal()
    try:
        _, key = agent_service.create_agent(db, "e2e", "Sitio E2E", actor_user_id=None)
    finally:
        db.close()

    monkeypatch.setenv("CRYPTOGUARD_AGENT_KEY", key)
    monkeypatch.setattr(
        "tls_analyzer.agent.runner.analyze_target", lambda *a, **k: _fake_ar()
    )

    from tls_analyzer.agent.config import TargetConfig

    config = AgentConfig(
        server_url="https://platform.test",
        upload_level="standard",
        pseudonymize="off",
        targets=[TargetConfig(host="intranet.corp.local", port=443)],
    )
    config.api_key_env = "CRYPTOGUARD_AGENT_KEY"

    with TestClient(app) as tc:
        client = AgentClient(config, transport=_TestClientTransport(tc))
        from tls_analyzer.agent.runner import AgentRunner

        code = AgentRunner(config, once=True, client=client).run()
        client.close()
        assert code == 0

        resp = tc.get("/api/scans", params={"search": "intranet.corp.local"})
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert items and items[0]["host"] == "intranet.corp.local"
        assert items[0]["agentId"]
