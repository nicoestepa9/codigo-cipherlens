"""Pinned target resolution and socket helpers for cloud-initiated probes."""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from typing import Callable
from urllib.parse import urlsplit

CLOUD_SCAN_AUTHORIZATION_VERSION = "2026-10-v1"
CLOUD_SCAN_AUTHORIZATION_TEXT = (
    "Confirmo que soy titular de este activo o cuento con autorización "
    "para escanearlo."
)


class NonPublicTargetError(ValueError):
    """A cloud scan target resolves to an address that is not globally routable."""


@dataclass(frozen=True)
class PinnedTarget:
    """An IP selected and validated before the scan; hostname remains the SNI."""

    address: str
    enforce_public: bool = True


def _normalized_address(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    address = ipaddress.ip_address(value)
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        return address.ipv4_mapped
    return address


def is_public_address(value: str) -> bool:
    """Return False for private, local, shared, multicast, reserved and special IPs."""
    try:
        address = _normalized_address(value)
    except ValueError:
        return False
    return bool(
        address.is_global
        and not address.is_private
        and not address.is_loopback
        and not address.is_link_local
        and not address.is_multicast
        and not address.is_reserved
        and not address.is_unspecified
    )


def validate_public_address(value: str) -> str:
    """Normalize and validate one IP at resolution time and again before connect."""
    try:
        address = _normalized_address(value)
    except ValueError as exc:
        raise NonPublicTargetError(f"Invalid IP address: {value}") from exc
    normalized = str(address)
    if not is_public_address(normalized):
        raise NonPublicTargetError(
            "Para objetivos internos o reservados usá un agente."
        )
    return normalized


def parse_scan_target(target: str, default_port: int | None = None) -> tuple[str, int]:
    """Parse host, URL, host:port, and bracketed IPv6 targets without ambiguity."""
    raw = (target or "").strip()
    if not raw:
        raise NonPublicTargetError("El objetivo está vacío.")
    parsed = urlsplit(raw if "://" in raw else f"//{raw}")
    if parsed.username or parsed.password or not parsed.hostname:
        raise NonPublicTargetError("El objetivo no es un host válido.")
    if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise NonPublicTargetError("Indicá solo el host y puerto del objetivo.")
    try:
        parsed_port = parsed.port
    except ValueError as exc:
        raise NonPublicTargetError("El puerto del objetivo no es válido.") from exc
    port = parsed_port if parsed_port is not None else default_port
    if port is None:
        port = 443
    if not 1 <= port <= 65535:
        raise NonPublicTargetError("El puerto del objetivo no es válido.")
    return parsed.hostname, port


def resolve_target_addresses(
    host: str,
    *,
    enforce_public: bool = True,
    resolver: Callable = socket.getaddrinfo,
) -> tuple[str, ...]:
    """Resolve once, validate every A/AAAA answer, and return immutable IP strings."""
    try:
        literal = _normalized_address(host)
    except ValueError:
        literal = None

    if literal is not None:
        addresses = [str(literal)]
    else:
        try:
            records = resolver(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        except OSError as exc:
            raise NonPublicTargetError(
                f"No se pudo resolver el objetivo: {host}."
            ) from exc
        addresses = []
        for record in records:
            try:
                address = _normalized_address(record[4][0])
            except (ValueError, IndexError, TypeError):
                continue
            value = str(address)
            if value not in addresses:
                addresses.append(value)

    if not addresses:
        raise NonPublicTargetError(f"No se pudo resolver el objetivo: {host}.")
    if enforce_public:
        for address in addresses:
            validate_public_address(address)
    return tuple(addresses)


def open_target_connection(
    host: str,
    port: int,
    timeout: float,
    *,
    pinned_target: PinnedTarget | None = None,
):
    """Connect to a previously resolved IP; never resolve the hostname again."""
    destination = host
    if pinned_target is not None:
        destination = pinned_target.address
        if pinned_target.enforce_public:
            validate_public_address(destination)
    return socket.create_connection((destination, port), timeout=timeout)
