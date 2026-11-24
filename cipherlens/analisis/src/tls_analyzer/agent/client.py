"""Cliente HTTPS del agente hacia la plataforma (solo conexiones salientes)."""

from __future__ import annotations

import os
import random
import time

import httpx

from .config import AgentConfig


class AgentFatalAuthError(Exception):
    """401/403 de la plataforma: key invalida o revocada. El agente se detiene."""


class AgentIngestError(Exception):
    """Error de ingesta no recuperable o reintentos agotados."""


def _max_retries() -> int:
    try:
        return int(os.getenv("AGENT_MAX_RETRIES", "5"))
    except ValueError:
        return 5


class AgentClient:
    def __init__(
        self,
        config: AgentConfig,
        *,
        transport: httpx.BaseTransport | None = None,
        sleep=time.sleep,
        agent_version: str = "0.1.0",
    ) -> None:
        self.config = config
        self.agent_version = agent_version
        self.max_retries = _max_retries()
        self._sleep = sleep
        self._started = time.monotonic()
        # Valor de verificacion TLS efectivo (nunca False: seria MITM).
        self.verify = config.verify
        self._client = httpx.Client(
            base_url=config.server_url,
            verify=config.verify,
            headers={"X-API-Key": config.api_key},
            timeout=httpx.Timeout(
                config.ingest_timeout,
                connect=config.connect_timeout,
                read=config.read_timeout,
            ),
            transport=transport,
        )

    def close(self) -> None:
        self._client.close()

    def _post(self, path: str, payload: dict) -> httpx.Response:
        delay = 1.0
        last_error: object = None
        for attempt in range(self.max_retries + 1):
            retry_after: float | None = None
            try:
                resp = self._client.post(path, json=payload)
            except httpx.HTTPError as exc:
                last_error = exc
            else:
                if resp.status_code in (200, 201, 204):
                    return resp
                if resp.status_code in (401, 403):
                    raise AgentFatalAuthError(
                        "key invalida o revocada (HTTP %s)" % resp.status_code
                    )
                if resp.status_code == 429:
                    try:
                        retry_after = float(resp.headers.get("Retry-After", "5"))
                    except ValueError:
                        retry_after = 5.0
                    last_error = "rate limited (429)"
                elif 400 <= resp.status_code < 500:
                    raise AgentIngestError(
                        f"payload rechazado ({resp.status_code}): {resp.text[:200]}"
                    )
                else:
                    last_error = f"HTTP {resp.status_code}"
            if attempt < self.max_retries:
                wait = retry_after if retry_after is not None else delay
                jitter = random.uniform(0, max(0.1, wait * 0.3))
                self._sleep(wait + jitter)
                delay = min(delay * 2, 60.0)
        raise AgentIngestError(
            f"reintentos agotados ({self.max_retries}): {last_error}"
        )

    def heartbeat(self) -> None:
        capabilities = {
            "allowRemoteTasks": bool(self.config.allow_remote_tasks),
            "networkCount": len(self.config.allowed_networks)
            if self.config.allow_remote_tasks
            else 0,
            "portCount": len(self.config.allowed_ports)
            if self.config.allow_remote_tasks
            else 0,
        }
        if self.config.allow_remote_tasks:
            capabilities["allowedNetworks"] = list(self.config.allowed_networks)
            capabilities["allowedPorts"] = list(self.config.allowed_ports)
        self._post(
            "/api/agent/heartbeat",
            {
                "agentVersion": self.agent_version,
                "schemaVersion": 1,
                "rulesVersion": None,
                "uptimeSeconds": int(time.monotonic() - self._started),
                "capabilities": capabilities,
            },
        )

    def claim_tasks(self, max_tasks: int = 1) -> list[dict]:
        response = self._post(
            "/api/agent/tasks/claim",
            {"maxTasks": max(1, min(int(max_tasks), 16)), "agentVersion": self.agent_version},
        )
        data = response.json()
        if not isinstance(data, list):
            raise AgentIngestError("invalid task claim response")
        return data

    def update_task_status(
        self, task_id: str, status: str, reason: str | None = None
    ) -> dict:
        payload: dict = {"status": status}
        if reason is not None:
            payload["reason"] = reason
        return self._post(
            f"/api/agent/tasks/{task_id}/status", payload
        ).json()

    def ingest_scan(self, payload: dict) -> dict:
        return self._post("/api/agent/ingest/scan", payload).json()

    def ingest_discovery(self, payload: dict) -> dict:
        return self._post("/api/agent/ingest/discovery", payload).json()
