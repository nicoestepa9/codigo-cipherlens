"""Bucle principal del agente de recoleccion (Parte 5.5)."""

from __future__ import annotations

import json
import logging
import os
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

from ..analysis import analyze_target
from ..discovery import run_discovery_sync
from . import state
from .client import AgentClient, AgentFatalAuthError
from .minimize import build_discovery_payload, build_scan_payload
from .pseudonymize import Pseudonymizer
from .remote_tasks import TargetNotAllowed, execute_remote_task

_log = logging.getLogger("tls_analyzer.agent")


def _build_pseudonymizer(mode: str) -> Pseudonymizer | None:
    if mode == "off":
        return None
    return Pseudonymizer(state.ensure_secret(), mode)


class AgentRunner:
    def __init__(
        self,
        config,
        *,
        dry_run: bool = False,
        once: bool = False,
        client: AgentClient | None = None,
    ) -> None:
        self.config = config
        self.dry_run = dry_run
        self.once = once
        self.pseudonymizer = _build_pseudonymizer(config.pseudonymize)
        self._last_remote_poll = 0.0
        if dry_run:
            self.client: AgentClient | None = None
        else:
            self.client = client or AgentClient(config)

    # -- ciclo --------------------------------------------------------------
    def run(self) -> int:
        if self.config.upload_level == "full":
            _log.warning(
                "upload_level=full: se enviara el resultado crudo completo "
                "(solo depuracion)."
            )
        if self.config.pseudonymize != "off":
            _log.info(
                "Seudonimizacion activa (%s). El mapeo queda local; usa "
                "'cryptoguard-agent resolve/export-mapping' para verlo.",
                self.config.pseudonymize,
            )
        try:
            if self.once:
                self.tick()
                return 0
            tick = float(os.getenv("AGENT_TICK_SECONDS", "30"))
            while True:
                self.tick()
                wait = min(tick, self.config.poll_seconds) if self.config.allow_remote_tasks else tick
                time.sleep(max(0.1, wait))
        except AgentFatalAuthError as exc:
            _log.error("Key invalida o revocada: el agente se detiene. (%s)", exc)
            return 2
        finally:
            if self.pseudonymizer is not None:
                self.pseudonymizer.flush()
            if self.client is not None:
                self.client.close()
        return 0

    def tick(self) -> None:
        self._heartbeat()
        self._run_targets()
        self._run_discovery()
        self._run_remote_tasks()

    # -- heartbeat ----------------------------------------------------------
    def _heartbeat(self) -> None:
        if self.client is None:
            return
        try:
            self.client.heartbeat()
        except AgentFatalAuthError:
            raise
        except Exception as exc:  # red transitoria: no tumba al agente
            _log.warning("Heartbeat fallo: %s", exc)

    def _run_remote_tasks(self) -> None:
        if self.client is None or not self.config.allow_remote_tasks:
            return
        now = time.monotonic()
        if now - self._last_remote_poll < self.config.poll_seconds:
            return
        self._last_remote_poll = now
        try:
            tasks = self.client.claim_tasks(
                max_tasks=max(1, min(self.config.max_concurrent, 16))
            )
        except AgentFatalAuthError:
            raise
        except Exception as exc:
            _log.warning("No se pudieron consultar tareas remotas: %s", exc)
            return
        for task in tasks:
            self._process_remote_task(task)

    def _process_remote_task(self, task: dict) -> None:
        task_id = str(task.get("taskId") or "")
        try:
            self.client.update_task_status(task_id, "running")
            kind, payload = execute_remote_task(
                task, self.config, pseudonymizer=self.pseudonymizer
            )
            if kind == "scan":
                self.client.ingest_scan(payload)
            else:
                self.client.ingest_discovery(payload)
            _log.info("Tarea remota completada: %s (%s)", task_id, kind)
        except TargetNotAllowed:
            try:
                self.client.update_task_status(
                    task_id, "rejected", reason="target_not_allowed"
                )
            except AgentFatalAuthError:
                raise
            except Exception as exc:
                _log.error("No se pudo rechazar la tarea %s: %s", task_id, exc)
        except AgentFatalAuthError:
            raise
        except Exception as exc:
            _log.error("Tarea remota %s fallo: %s", task_id, exc)
            try:
                self.client.update_task_status(
                    task_id, "failed", reason=type(exc).__name__
                )
            except AgentFatalAuthError:
                raise
            except Exception as status_exc:
                _log.error(
                    "No se pudo informar el fallo de la tarea %s: %s",
                    task_id,
                    status_exc,
                )

    # -- objetivos ----------------------------------------------------------
    def _run_targets(self) -> None:
        due = [t for t in self.config.targets if self._is_due(t.key, t.interval_hours)]
        if not due:
            return
        workers = max(1, min(self.config.max_concurrent, len(due)))
        fatal: AgentFatalAuthError | None = None
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(self._process_target, t) for t in due]
            for fut in futures:
                try:
                    fut.result()
                except AgentFatalAuthError as exc:
                    fatal = exc
                except Exception as exc:  # un objetivo caido no afecta al resto
                    _log.error("Objetivo fallo: %s", exc)
        if fatal is not None:
            raise fatal

    def _process_target(self, target) -> None:
        opts = {
            "profile": target.profile,
            "timeout": self.config.read_timeout,
            "alternatePorts": target.alternate_ports,
        }
        ar = analyze_target(target.host, opts, port=target.port)
        client_scan_id = str(uuid.uuid4())
        payload = build_scan_payload(ar, client_scan_id, self.config.upload_level)
        if self.pseudonymizer is not None:
            payload = self.pseudonymizer.apply_scan(payload)
        if self.client is None:  # dry-run
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            self.client.ingest_scan(payload)
            _log.info("Enviado scan de %s:%s (score=%s)", target.host, target.port, ar.score)
        state.mark_run(target.key)

    # -- discovery ----------------------------------------------------------
    def _run_discovery(self) -> None:
        for d in self.config.discovery:
            if not self._is_due(d.key, d.interval_hours):
                continue
            try:
                self._process_discovery(d)
            except AgentFatalAuthError:
                raise
            except Exception as exc:
                _log.error("Discovery %s fallo: %s", d.cidr, exc)

    def _process_discovery(self, disc) -> None:
        results = run_discovery_sync(
            ip_range=disc.cidr,
            domains=[],
            ports=disc.ports,
            scan_internal=True,
            timeout=min(1.5, self.config.connect_timeout),
        )
        client_job_id = str(uuid.uuid4())
        payload = build_discovery_payload(
            results,
            client_job_id,
            cidr=disc.cidr,
            ports=disc.ports,
            scan_internal=True,
        )
        if self.pseudonymizer is not None:
            payload = self.pseudonymizer.apply_discovery(payload)
        if self.client is None:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            self.client.ingest_discovery(payload)
            _log.info("Enviado discovery %s (%d resultados)", disc.cidr, len(results))
        state.mark_run(disc.key)

    # -- helpers ------------------------------------------------------------
    def _is_due(self, key: str, interval_hours: float) -> bool:
        last = state.last_run(key)
        if last is None:
            return True
        return datetime.now(timezone.utc) - last > timedelta(hours=interval_hours)
