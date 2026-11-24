"""Validate and execute the two explicitly supported remote task types."""

from __future__ import annotations

import ipaddress
import socket
from typing import Any

from .. import analysis
from ..cloud_network import PinnedTarget, parse_scan_target, resolve_target_addresses
from ..discovery import (
    estimate_target_count,
    parse_targets,
    run_discovery_sync,
)
from .minimize import build_discovery_payload, build_scan_payload


class TargetNotAllowed(ValueError):
    """The task exceeds the agent's locally configured network/port scope."""


def _allowed_networks(config) -> list:
    try:
        return [
            ipaddress.ip_network(value, strict=False)
            for value in config.allowed_networks
        ]
    except ValueError as exc:
        raise TargetNotAllowed("target_not_allowed") from exc


def _require_allowed_address(value: str, networks: list) -> None:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise TargetNotAllowed("target_not_allowed") from exc
    if not networks or not any(
        address.version == network.version and address in network
        for network in networks
    ):
        raise TargetNotAllowed("target_not_allowed")


def _validate_ports(values: Any, config) -> list[int]:
    if not isinstance(values, list) or not values:
        raise TargetNotAllowed("target_not_allowed")
    try:
        ports = sorted({int(port) for port in values})
    except (TypeError, ValueError) as exc:
        raise TargetNotAllowed("target_not_allowed") from exc
    if (
        len(ports) > config.max_task_ports
        or any(port < 1 or port > 65535 for port in ports)
        or not config.allowed_ports
        or not set(ports).issubset(set(config.allowed_ports))
    ):
        raise TargetNotAllowed("target_not_allowed")
    return ports


def validate_remote_task(task: dict, config) -> dict:
    """Return a pinned, normalized task or reject it before any network I/O."""
    if not config.allow_remote_tasks:
        raise TargetNotAllowed("target_not_allowed")
    if not isinstance(task, dict) or task.get("type") not in {"scan", "discovery"}:
        raise TargetNotAllowed("target_not_allowed")
    payload = task.get("payload")
    if not isinstance(payload, dict):
        raise TargetNotAllowed("target_not_allowed")
    networks = _allowed_networks(config)

    if task["type"] == "scan":
        target = payload.get("target")
        options = payload.get("options") or {}
        if not isinstance(target, dict) or not isinstance(options, dict):
            raise TargetNotAllowed("target_not_allowed")
        try:
            host, port = parse_scan_target(
                str(target.get("host") or ""), int(target.get("port") or 443)
            )
            alternates = _validate_ports(
                options.get("alternatePorts") or [], config
            ) if options.get("alternatePorts") else []
            ports = _validate_ports([port, *alternates], config)
            addresses = resolve_target_addresses(host, enforce_public=False)
        except (ValueError, OSError, TypeError) as exc:
            raise TargetNotAllowed("target_not_allowed") from exc
        for address in addresses:
            _require_allowed_address(address, networks)
        if config.max_task_hosts < 1:
            raise TargetNotAllowed("target_not_allowed")
        return {
            "type": "scan",
            "host": host,
            "port": port,
            "ports": ports,
            "pinned_address": addresses[0],
            "options": dict(options),
        }

    ip_range = payload.get("ipRange") or ""
    domains = payload.get("domains") or []
    if not isinstance(ip_range, str) or not isinstance(domains, list):
        raise TargetNotAllowed("target_not_allowed")
    if any(not isinstance(domain, str) or not domain.strip() for domain in domains):
        raise TargetNotAllowed("target_not_allowed")
    ports = _validate_ports(payload.get("ports") or [443], config)
    requested_count = estimate_target_count(ip_range, domains)
    if requested_count < 1 or requested_count > config.max_task_hosts:
        raise TargetNotAllowed("target_not_allowed")

    # Limit the CIDR expansion before parsing, then pin every resolved address.
    cidr_targets: list[tuple[str, str | None]] = []
    tokens = [token for token in ip_range.replace(",", " ").split() if token]
    for token in tokens:
        try:
            network = ipaddress.ip_network(token, strict=False)
        except ValueError as exc:
            raise TargetNotAllowed("target_not_allowed") from exc
        for allowed in networks:
            if network.version == allowed.version and network.subnet_of(allowed):
                break
        else:
            raise TargetNotAllowed("target_not_allowed")
    try:
        cidr_targets = parse_targets(ip_range, [])
    except (ValueError, OSError) as exc:
        raise TargetNotAllowed("target_not_allowed") from exc
    targets = list(cidr_targets)
    for address, _ in cidr_targets:
        _require_allowed_address(address, networks)
    for domain in domains:
        try:
            addresses = resolve_target_addresses(
                domain.strip(), enforce_public=False, resolver=socket.getaddrinfo
            )
        except (ValueError, OSError) as exc:
            raise TargetNotAllowed("target_not_allowed") from exc
        for address in addresses:
            _require_allowed_address(address, networks)
            targets.append((address, domain.strip()))
    if len(targets) > config.max_task_hosts or not targets:
        raise TargetNotAllowed("target_not_allowed")
    return {
        "type": "discovery",
        "cidr": ip_range,
        "domains": [domain.strip() for domain in domains],
        "ports": ports,
        "resolved_targets": targets,
    }


def execute_remote_task(task: dict, config, *, pseudonymizer=None) -> tuple[str, dict]:
    """Run a validated TLS scan or discovery and return its minimized payload."""
    validated = validate_remote_task(task, config)
    task_id = str(task.get("taskId") or "")
    if len(task_id) != 36:
        raise TargetNotAllowed("target_not_allowed")
    if validated["type"] == "scan":
        options = dict(validated["options"])
        options["timeout"] = config.read_timeout
        result = analysis.analyze_target(
            validated["host"],
            options,
            port=validated["port"],
            pinned_target=PinnedTarget(
                validated["pinned_address"], enforce_public=False
            ),
        )
        client_scan_id = f"task-{task_id}"
        body = build_scan_payload(result, client_scan_id, config.upload_level)
        if pseudonymizer is not None:
            body = pseudonymizer.apply_scan(body)
        body["taskId"] = task_id
        return "scan", body

    results = run_discovery_sync(
        ip_range="",
        domains=[],
        ports=validated["ports"],
        scan_internal=True,
        timeout=min(1.5, config.connect_timeout),
        resolved_targets=validated["resolved_targets"],
    )
    client_job_id = f"task-{task_id}"
    body = build_discovery_payload(
        results,
        client_job_id,
        cidr=validated["cidr"] or ", ".join(validated["domains"]),
        ports=validated["ports"],
        scan_internal=True,
    )
    if pseudonymizer is not None:
        body = pseudonymizer.apply_discovery(body)
    body["taskId"] = task_id
    return "discovery", body
