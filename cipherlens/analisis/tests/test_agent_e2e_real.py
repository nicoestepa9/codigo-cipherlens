"""E2E real de Parte A: agente, TLS local, discovery y tareas remotas."""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest
import uvicorn

from tests.local_tls import TlsServer, write_certificate

from tls_analyzer.api import models
from tls_analyzer.api.db import SessionLocal
from tls_analyzer.api.main import app
from tls_analyzer.api.services import agent_service, auth_service, user_service
from tls_analyzer.api.tenancy import set_system_session, set_tenant_session


ROOT = Path(__file__).resolve().parents[1]
# La corrida de la suite no debe ensuciar el worktree: la evidencia automatica
# va a artifacts/ (ignorada).
EVIDENCE = ROOT / "artifacts" / "evidencia_agente_e2e.md"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class _PlatformServer:
    def __init__(self) -> None:
        self.port = _free_port()
        config = uvicorn.Config(
            app,
            host="127.0.0.1",
            port=self.port,
            log_level="warning",
            access_log=False,
        )
        self.server = uvicorn.Server(config)
        self.server.install_signal_handlers = lambda: None
        self.thread = threading.Thread(target=self.server.run, daemon=True)

    def start(self) -> None:
        self.thread.start()
        deadline = time.monotonic() + 20
        while not self.server.started and time.monotonic() < deadline:
            if not self.thread.is_alive():
                raise RuntimeError("Platform server stopped during startup")
            time.sleep(0.05)
        if not self.server.started:
            raise RuntimeError("Platform server did not start in time")

    def stop(self) -> None:
        self.server.should_exit = True
        self.thread.join(timeout=15)


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": "".join(("Bear", "er ", token))}


def _wait_for_tasks(client: httpx.Client, headers: dict[str, str], agent_id: str):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        response = client.get(
            "/api/agent-tasks", params={"agentId": agent_id}, headers=headers
        )
        response.raise_for_status()
        tasks = response.json()
        if tasks and all(
            task["status"] in {"done", "rejected", "failed", "expired", "cancelled"}
            for task in tasks
        ):
            return tasks
        time.sleep(0.2)
    raise AssertionError("Remote tasks did not reach a terminal state")


@pytest.mark.e2e
def test_agent_once_real_tls_discovery_and_remote_tasks(tmp_path, monkeypatch):
    from tls_analyzer.api.services import cve_service

    monkeypatch.setattr(cve_service, "query_nvd_by_cpe", lambda *_a, **_k: [])
    monkeypatch.setattr(cve_service, "query_nvd_by_keyword", lambda *_a, **_k: [])

    suffix = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")
    cert_path, key_path = write_certificate(tmp_path)
    tls_server = TlsServer(cert_path, key_path)

    db = SessionLocal()
    set_system_session(db)
    try:
        organization = models.Organization(
            name=f"E2E Org {suffix}",
            slug=f"e2e-org-{suffix}",
            status="active",
        )
        db.add(organization)
        db.flush()
        administrator = user_service.create_user(
            db,
            email=f"e2e-admin-{suffix}@example.test",
            name="E2E Admin",
            password="E2E-pass-1234!",
            role="admin",
            organization_id=organization.id,
        )
        db.commit()
        organization_id = organization.id
        administrator_id = administrator.id
    finally:
        db.close()

    db = SessionLocal()
    try:
        set_tenant_session(db, organization_id)
        agent_dto, agent_key = agent_service.create_agent(
            db,
            f"e2e-agent-{suffix}",
            "E2E Site",
            actor_user_id=administrator_id,
        )
        agent_id = agent_dto["id"]
    finally:
        db.close()

    admin_token = auth_service.create_access_token(administrator_id, "admin")
    platform = _PlatformServer()
    platform.start()
    evidence: dict = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "platformUrl": f"http://127.0.0.1:{platform.port}",
        "tlsPort": tls_server.port,
        "organizationId": organization_id,
        "agentId": agent_id,
    }
    agent_output = ""
    try:
        with httpx.Client(
            base_url=f"http://127.0.0.1:{platform.port}", timeout=20
        ) as client:
            accepted = client.post(
                "/api/scans",
                headers=_auth(admin_token),
                json={
                    "target": "127.0.0.1",
                    "port": tls_server.port,
                    "executor": {"type": "agent", "agentId": agent_id},
                },
            )
            assert accepted.status_code == 202, accepted.text
            accepted_task_id = accepted.json()["taskId"]

            rejected = client.post(
                "/api/scans",
                headers=_auth(admin_token),
                json={
                    "target": "192.0.2.1",
                    "port": 443,
                    "executor": {"type": "agent", "agentId": agent_id},
                },
            )
            assert rejected.status_code == 202, rejected.text
            rejected_task_id = rejected.json()["taskId"]

            agent_config = tmp_path / "agent.yaml"
            agent_config.write_text(
                "\n".join(
                    (
                        f"server_url: http://127.0.0.1:{platform.port}",
                        "allow_insecure_localhost: true",
                        "site_label: E2E Site",
                        "upload_level: standard",
                        "pseudonymize: off",
                        "allow_remote_tasks: true",
                        "allowed_networks:",
                        "  - 127.0.0.1/32",
                        "allowed_ports:",
                        f"  - {tls_server.port}",
                        "max_task_hosts: 16",
                        "max_task_ports: 4",
                        "poll_seconds: 1",
                        "targets:",
                        "  - host: 127.0.0.1",
                        f"    port: {tls_server.port}",
                        "    profile: citizen-facing",
                        "discovery:",
                        "  - cidr: 127.0.0.1/32",
                        "    ports:",
                        f"      - {tls_server.port}",
                    )
                )
                + "\n",
                encoding="utf-8",
            )
            env = os.environ.copy()
            env["CRYPTOGUARD_AGENT_KEY"] = agent_key
            env["CRYPTOGUARD_AGENT_STATE_DIR"] = str(tmp_path / "agent-state")
            env["PYTHONPATH"] = os.pathsep.join(
                (str(ROOT / "src"), env.get("PYTHONPATH", ""))
            )
            process = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "tls_analyzer.agent",
                    "run",
                    "--config",
                    str(agent_config),
                    "--once",
                ],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                timeout=180,
            )
            agent_output = process.stdout + process.stderr
            assert process.returncode == 0, agent_output

            scans = client.get(
                "/api/scans",
                params={"agentId": agent_id},
                headers=_auth(admin_token),
            )
            assert scans.status_code == 200, scans.text
            scan_items = scans.json()["items"]
            assert any(item["host"] == "127.0.0.1" for item in scan_items), (
                f"scans={scan_items}\nagent output:\n{agent_output}"
            )
            scan = next(item for item in scan_items if item["host"] == "127.0.0.1")
            assert scan["agentId"] == agent_id
            assert scan["siteLabel"] == "E2E Site"

            detail = client.get(
                f"/api/scans/{scan['id']}", headers=_auth(admin_token)
            )
            assert detail.status_code == 200, detail.text
            detail_json = detail.json()
            assert detail_json["findings"], detail_json
            assert detail_json["agentId"] == agent_id
            assert detail_json["siteLabel"] == "E2E Site"
            assert detail_json["certificate"]["commonName"] == "127.0.0.1"
            assert detail_json["certificate"]["isSelfSigned"] is True

            services = client.get(
                "/api/services",
                params={"agentId": agent_id},
                headers=_auth(admin_token),
            )
            assert services.status_code == 200, services.text
            service_items = services.json()["items"]
            matching_service = next(
                (
                    item
                    for item in service_items
                    if item["host"] == "127.0.0.1" and item["port"] == tls_server.port
                ),
                None,
            )
            assert matching_service is not None, service_items
            assert matching_service["agentId"] == agent_id
            assert matching_service["siteLabel"] == "E2E Site"

            certificates = client.get(
                "/api/certificates",
                params={"agentId": agent_id},
                headers=_auth(admin_token),
            )
            assert certificates.status_code == 200, certificates.text
            certificate_items = certificates.json()["items"]
            matching_certificate = next(
                (
                    item
                    for item in certificate_items
                    if item["commonName"] == "127.0.0.1"
                ),
                None,
            )
            assert matching_certificate is not None, certificate_items
            assert matching_certificate["agentId"] == agent_id
            assert matching_certificate["siteLabel"] == "E2E Site"

            issues = client.get(
                "/api/issues",
                params={"agentId": agent_id},
                headers=_auth(admin_token),
            )
            assert issues.status_code == 200, issues.text
            issue_items = issues.json()["items"]
            assert issue_items, issues.text
            assert all(item["agentId"] == agent_id for item in issue_items)
            assert all(item["siteLabel"] == "E2E Site" for item in issue_items)

            discovery = client.get(
                "/api/discovery/results",
                params={"agentId": agent_id},
                headers=_auth(admin_token),
            )
            assert discovery.status_code == 200, discovery.text
            discovery_items = discovery.json()
            matching_discovery = next(
                (
                    item
                    for item in discovery_items
                    if item["ipAddress"] == "127.0.0.1"
                    and item["port"] == tls_server.port
                ),
                None,
            )
            assert matching_discovery is not None, discovery_items
            assert matching_discovery["agentId"] == agent_id
            assert matching_discovery["siteLabel"] == "E2E Site"

            tasks = _wait_for_tasks(client, _auth(admin_token), agent_id)
            by_id = {task["id"]: task for task in tasks}
            assert by_id[accepted_task_id]["status"] == "done"
            assert by_id[rejected_task_id]["status"] == "rejected"
            assert by_id[rejected_task_id]["error"] == "target_not_allowed"

            evidence.update(
                {
                    "scanId": scan["id"],
                    "scanAgentId": scan["agentId"],
                    "scanSiteLabel": scan["siteLabel"],
                    "findings": len(detail_json["findings"]),
                    "certificateCommonName": detail_json["certificate"]["commonName"],
                    "certificateSelfSigned": detail_json["certificate"]["isSelfSigned"],
                    "serviceCount": len(service_items),
                    "discoveryResults": len(discovery_items),
                    "acceptedTask": by_id[accepted_task_id]["status"],
                    "rejectedTask": by_id[rejected_task_id]["status"],
                }
            )
    finally:
        platform.stop()
        tls_server.stop()
        cleanup = SessionLocal()
        set_system_session(cleanup)
        try:
            from tls_analyzer.cli import _purge_organization

            _purge_organization(cleanup, organization_id)
            cleanup.commit()
        finally:
            cleanup.close()

    EVIDENCE.parent.mkdir(parents=True, exist_ok=True)
    EVIDENCE.write_text(
        "\n".join(
            (
                "# Evidencia E2E real del agente",
                "",
                f"Fecha: {evidence['timestamp']}",
                "",
                "Test: `pytest tests/test_agent_e2e_real.py -m e2e -q`",
                "",
                "## Resultado",
                "",
                "```json",
                json.dumps(evidence, indent=2, ensure_ascii=False),
                "```",
                "",
                "## Salida del agente `--once`",
                "",
                "```text",
                agent_output.strip(),
                "```",
                "",
            )
        ),
        encoding="utf-8",
    )
