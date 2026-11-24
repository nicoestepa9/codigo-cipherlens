"""Configuracion del agente: agent.yaml + overrides por variables de entorno."""

from __future__ import annotations

import os
import ipaddress
from dataclasses import dataclass, field
from urllib.parse import urlparse


class ConfigError(Exception):
    """Configuracion invalida del agente."""


_ALLOWED_UPLOAD_LEVELS = {"minimal", "standard", "full"}
_ALLOWED_PSEUDONYMIZE = {"off", "internal", "strict"}
_LOCALHOSTS = {"localhost", "127.0.0.1", "::1"}


@dataclass
class TargetConfig:
    host: str
    port: int = 443
    alternate_ports: list[int] = field(default_factory=list)
    profile: str = "citizen-facing"
    interval_hours: float = 24.0

    @property
    def key(self) -> str:
        return f"target:{self.host}:{self.port}"


@dataclass
class DiscoveryConfig:
    cidr: str
    ports: list[int] = field(default_factory=lambda: [443])
    interval_hours: float = 168.0

    @property
    def key(self) -> str:
        return f"discovery:{self.cidr}"


@dataclass
class AgentConfig:
    server_url: str
    api_key_env: str = "CRYPTOGUARD_AGENT_KEY"
    ca_bundle: str | None = None
    site_label: str = ""
    upload_level: str = "standard"
    pseudonymize: str = "off"
    max_concurrent: int = 3
    connect_timeout: float = 5.0
    read_timeout: float = 10.0
    ingest_timeout: float = 30.0
    targets: list[TargetConfig] = field(default_factory=list)
    discovery: list[DiscoveryConfig] = field(default_factory=list)
    allow_insecure_localhost: bool = False
    allow_remote_tasks: bool = False
    allowed_networks: list[str] = field(default_factory=list)
    allowed_ports: list[int] = field(default_factory=list)
    max_task_hosts: int = 1024
    max_task_ports: int = 32
    poll_seconds: int = 15

    @property
    def api_key(self) -> str:
        return os.getenv(self.api_key_env, "").strip()

    @property
    def verify(self):
        """Valor de verificacion TLS para httpx. Nunca ``False``."""
        return self.ca_bundle if self.ca_bundle else True


def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _is_localhost(host: str) -> bool:
    return host.lower() in _LOCALHOSTS


def validate_server_url(url: str, *, allow_insecure_localhost: bool) -> None:
    parsed = urlparse(url or "")
    if parsed.scheme == "https":
        return
    if (
        parsed.scheme == "http"
        and allow_insecure_localhost
        and _is_localhost(parsed.hostname or "")
    ):
        return
    raise ConfigError(
        f"server_url inseguro: {url!r}. Debe ser https:// "
        "(http solo se permite para localhost con --allow-insecure-localhost)."
    )


def load_config(path: str, *, allow_insecure_localhost: bool = False) -> AgentConfig:
    try:
        import yaml
    except ImportError as exc:  # pragma: no cover - dependencia del extra agent
        raise ConfigError(
            "Falta PyYAML. Instala el agente con: pip install 'pkg[agent]'"
        ) from exc

    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh) or {}
    except FileNotFoundError as exc:
        raise ConfigError(f"No existe el archivo de configuracion: {path}") from exc

    allow = allow_insecure_localhost or bool(raw.get("allow_insecure_localhost"))

    server_url = (
        os.getenv("CRYPTOGUARD_SERVER_URL") or raw.get("server_url") or ""
    ).strip()
    if not server_url:
        raise ConfigError("server_url es obligatorio en agent.yaml")
    validate_server_url(server_url, allow_insecure_localhost=allow)

    upload_level = (
        os.getenv("CRYPTOGUARD_UPLOAD_LEVEL") or raw.get("upload_level") or "standard"
    ).strip().lower()
    if upload_level not in _ALLOWED_UPLOAD_LEVELS:
        raise ConfigError(
            f"upload_level invalido: {upload_level!r} "
            f"(esperado {sorted(_ALLOWED_UPLOAD_LEVELS)})"
        )

    pseudonymize = (
        os.getenv("CRYPTOGUARD_PSEUDONYMIZE") or raw.get("pseudonymize") or "off"
    ).strip().lower()
    if pseudonymize not in _ALLOWED_PSEUDONYMIZE:
        raise ConfigError(
            f"pseudonymize invalido: {pseudonymize!r} "
            f"(esperado {sorted(_ALLOWED_PSEUDONYMIZE)})"
        )

    allow_remote_tasks = raw.get("allow_remote_tasks", False)
    if not isinstance(allow_remote_tasks, bool):
        raise ConfigError("allow_remote_tasks debe ser true o false")
    allowed_networks = []
    networks_raw = raw.get("allowed_networks") or []
    if not isinstance(networks_raw, list):
        raise ConfigError("allowed_networks debe ser una lista de CIDR")
    for value in networks_raw:
        try:
            allowed_networks.append(str(ipaddress.ip_network(str(value), strict=False)))
        except ValueError as exc:
            raise ConfigError(f"CIDR invalido en allowed_networks: {value!r}") from exc

    allowed_ports_raw = raw.get("allowed_ports") or []
    if not isinstance(allowed_ports_raw, list):
        raise ConfigError("allowed_ports debe ser una lista")
    try:
        allowed_ports = sorted({int(port) for port in allowed_ports_raw})
    except (TypeError, ValueError) as exc:
        raise ConfigError("allowed_ports debe contener puertos numericos") from exc
    if any(port < 1 or port > 65535 for port in allowed_ports):
        raise ConfigError("allowed_ports debe estar entre 1 y 65535")

    try:
        max_task_hosts = int(raw.get("max_task_hosts", 1024))
        max_task_ports = int(raw.get("max_task_ports", 32))
        poll_seconds = int(os.getenv("AGENT_POLL_SECONDS", raw.get("poll_seconds", 15)))
    except (TypeError, ValueError) as exc:
        raise ConfigError("Limites de tareas remotas deben ser enteros") from exc
    if not 1 <= max_task_hosts <= 65536:
        raise ConfigError("max_task_hosts debe estar entre 1 y 65536")
    if not 1 <= max_task_ports <= 1024:
        raise ConfigError("max_task_ports debe estar entre 1 y 1024")
    if not 1 <= poll_seconds <= 3600:
        raise ConfigError("poll_seconds debe estar entre 1 y 3600")

    timeouts = raw.get("timeouts") or {}
    targets = [
        TargetConfig(
            host=str(t["host"]),
            port=int(t.get("port", 443)),
            alternate_ports=[int(p) for p in (t.get("alternate_ports") or [])],
            profile=str(t.get("profile") or "citizen-facing"),
            interval_hours=float(t.get("interval_hours", 24)),
        )
        for t in (raw.get("targets") or [])
        if t.get("host")
    ]
    discovery = [
        DiscoveryConfig(
            cidr=str(d["cidr"]),
            ports=[int(p) for p in (d.get("ports") or [443])],
            interval_hours=float(d.get("interval_hours", 168)),
        )
        for d in (raw.get("discovery") or [])
        if d.get("cidr")
    ]

    return AgentConfig(
        server_url=server_url.rstrip("/"),
        api_key_env=os.getenv("CRYPTOGUARD_API_KEY_ENV")
        or raw.get("api_key_env")
        or "CRYPTOGUARD_AGENT_KEY",
        ca_bundle=os.getenv("CRYPTOGUARD_CA_BUNDLE") or raw.get("ca_bundle"),
        site_label=str(raw.get("site_label") or ""),
        upload_level=upload_level,
        pseudonymize=pseudonymize,
        max_concurrent=int(
            os.getenv("CRYPTOGUARD_MAX_CONCURRENT") or raw.get("max_concurrent", 3)
        ),
        connect_timeout=float(timeouts.get("connect", 5)),
        read_timeout=float(timeouts.get("read", 10)),
        ingest_timeout=float(timeouts.get("ingest", 30)),
        targets=targets,
        discovery=discovery,
        allow_insecure_localhost=allow,
        allow_remote_tasks=allow_remote_tasks,
        allowed_networks=allowed_networks,
        allowed_ports=allowed_ports,
        max_task_hosts=max_task_hosts,
        max_task_ports=max_task_ports,
        poll_seconds=poll_seconds,
    )
