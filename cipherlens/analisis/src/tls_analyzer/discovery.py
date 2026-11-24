"""Motor de descubrimiento de servicios en la red (asyncio + sockets puros).

Capacidades:
- Expandir CIDR / IPs / dominios a una lista de direcciones.
- Port scan no bloqueante con semaforo y timeout por conexion.
- Probe TLS (handshake) para detectar has_tls y version negociada.
- Banner grab best-effort para identificacion de servicio/SO.
- Clasificacion de alcance interno (RFC1918) vs externo.

NOTA DE SEGURIDAD: solo debe usarse contra rangos autorizados. El escaneo
activo puede disparar alertas de IDS/IPS en redes ajenas.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import ssl
from dataclasses import dataclass, field
from typing import Callable, Optional

from .cloud_network import (
    PinnedTarget,
    validate_public_address,
)
from .fingerprint import fingerprint_from_banner, grab_banner

SERVICE_BY_PORT = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 143: "imap", 443: "https",
    3306: "mysql", 5432: "postgresql", 6379: "redis",
    8080: "http-proxy", 8000: "http-alt", 8443: "https-alt",
    4443: "https-alt", 9200: "elasticsearch", 27017: "mongodb",
}

SERVICE_NAME_BY_PORT = {
    443: "HTTPS", 8443: "HTTPS", 4443: "HTTPS", 8080: "HTTP",
    8000: "HTTP", 80: "HTTP", 22: "SSH", 5432: "PostgreSQL",
    3306: "MySQL", 9200: "Elasticsearch", 6379: "Redis",
}


@dataclass
class DiscoveredService:
    ip_address: str
    port: int
    hostname: str | None = None
    service: str = ""
    service_name: str = ""
    has_tls: bool = False
    tls_version: str | None = None
    os_fingerprint: str | None = None
    scope: str = "external"

    def to_dict(self) -> dict:
        return {
            "ip_address": self.ip_address,
            "port": self.port,
            "hostname": self.hostname,
            "service": self.service,
            "service_name": self.service_name,
            "has_tls": self.has_tls,
            "tls_version": self.tls_version,
            "os_fingerprint": self.os_fingerprint,
            "scope": self.scope,
        }


def is_internal_ip(ip_str: str) -> bool:
    """True si la IP es privada/loopback/link-local (RFC1918 y afines)."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return addr.is_private or addr.is_loopback or addr.is_link_local


def expand_cidr(cidr: str) -> list[str]:
    """Expande un CIDR ('10.0.0.0/24') o IP suelta a lista de IPs."""
    try:
        if "/" in cidr:
            network = ipaddress.ip_network(cidr, strict=False)
            return [str(ip) for ip in network.hosts()]
        return [str(ipaddress.ip_address(cidr))]
    except ValueError:
        return []


def parse_targets(ip_range: str, domains: list[str]) -> list[tuple[str, str | None]]:
    """Convierte rango/dominios en una lista de (ip, hostname)."""
    targets: list[tuple[str, str | None]] = []
    seen: set[str] = set()

    for token in [p.strip() for p in (ip_range or "").replace(",", " ").split() if p.strip()]:
        for ip in expand_cidr(token):
            if ip not in seen:
                seen.add(ip)
                targets.append((ip, None))

    for domain in domains:
        domain = domain.strip()
        if not domain:
            continue
        try:
            infos = socket.getaddrinfo(domain, None)
        except socket.gaierror:
            continue
        for info in infos:
            ip = info[4][0]
            if ip not in seen:
                seen.add(ip)
                targets.append((ip, domain))

    return targets


async def _tcp_open(
    ip: str,
    port: int,
    timeout: float,
    *,
    enforce_public: bool = False,
) -> bool:
    try:
        if enforce_public:
            validate_public_address(ip)
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except (OSError, asyncio.TimeoutError):
        return False


async def _tls_probe(
    ip: str,
    port: int,
    timeout: float,
    *,
    hostname: str | None = None,
    enforce_public: bool = False,
) -> tuple[bool, str | None]:
    """Intenta un handshake TLS; devuelve (ok, version)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        if enforce_public:
            validate_public_address(ip)
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(
                ip, port, ssl=ctx, server_hostname=hostname or ip
            ),
            timeout=timeout,
        )
        ssl_obj = writer.get_extra_info("ssl_object")
        version = ssl_obj.version() if ssl_obj else None
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True, version
    except (OSError, asyncio.TimeoutError, ssl.SSLError):
        return False, None


async def _banner_grab(
    ip: str,
    port: int,
    timeout: float,
    *,
    enforce_public: bool = False,
) -> str | None:
    """Wrapper async que delega al grab_banner síncrono del módulo fingerprint."""
    loop = asyncio.get_running_loop()
    pinned_target = PinnedTarget(ip, enforce_public=True) if enforce_public else None
    return await loop.run_in_executor(
        None,
        lambda: grab_banner(
            ip, port, timeout, pinned_target=pinned_target
        ),
    )


async def scan_ip(
    ip: str,
    ports: list[int],
    timeout: float = 1.5,
    hostname: str | None = None,
    enforce_public: bool = False,
) -> list[DiscoveredService]:
    """Escanea una IP en los puertos dados; devuelve los servicios hallados."""
    found: list[DiscoveredService] = []
    semaphore = asyncio.Semaphore(64)

    async def probe(port: int) -> None:
        async with semaphore:
            if not await _tcp_open(
                ip, port, timeout, enforce_public=enforce_public
            ):
                return
            service = SERVICE_BY_PORT.get(port, "unknown")
            service_name = SERVICE_NAME_BY_PORT.get(port, service.upper())
            has_tls, tls_version = False, None
            if service in ("https", "https-alt") or port in (443, 8443, 4443, 8000, 8080, 8000):
                has_tls, tls_version = await _tls_probe(
                    ip,
                    port,
                    timeout,
                    hostname=hostname,
                    enforce_public=enforce_public,
                )
            banner = await _banner_grab(
                ip, port, timeout, enforce_public=enforce_public
            )
            fp = fingerprint_from_banner(service, banner)
            os_fp = f"{fp.software_name} ({fp.software_version})" if fp.detected and fp.software_version else (fp.software_name if fp.detected else None)
            found.append(DiscoveredService(
                ip_address=ip,
                port=port,
                hostname=hostname,
                service=service,
                service_name=service_name,
                has_tls=has_tls,
                tls_version=tls_version,
                os_fingerprint=os_fp,
                scope="internal" if is_internal_ip(ip) else "external",
            ))

    await asyncio.gather(*(probe(p) for p in ports))
    found.sort(key=lambda d: d.port)
    return found


class DiscoveryCancelled(Exception):
    """Se lanzo para abortar un scan en curso desde el manejador de cancelacion."""


def estimate_target_count(ip_range: str, domains: list[str]) -> int:
    """Estima cuantos hosts escanearia un request, sin resolver DNS ni expandir.

    Sirve para rechazar rangos giganticos antes de arrancar el job: expandir un
    /16 son 65k IPs en memoria y, con el rendimiento real medido (5.7s por tanda de
    128), el scan se va a decenas de minutos. Los dominios se cuentan como 1 host
    cada uno, que es el piso (pueden resolver a mas de una IP).
    """
    count = 0
    for token in [p.strip() for p in (ip_range or "").replace(",", " ").split() if p.strip()]:
        try:
            if "/" in token:
                network = ipaddress.ip_network(token, strict=False)
                count += max(network.num_addresses - 2, 1)
            else:
                ipaddress.ip_address(token)
                count += 1
        except ValueError:
            continue
    count += sum(1 for d in domains if (d or "").strip())
    return count


async def run_discovery(
    ip_range: str = "",
    domains: list[str] | None = None,
    ports: list[int] | None = None,
    scan_internal: bool = True,
    timeout: float = 1.5,
    progress_cb: Optional[Callable[[int, int], None]] = None,
    max_concurrency: int = 128,
    cancel_check: Optional[Callable[[], bool]] = None,
    resolved_targets: list[tuple[str, str | None]] | None = None,
    enforce_public: bool = False,
) -> list[DiscoveredService]:
    """Barre targets y puertos en paralelo; reporta progreso via callback (done, total)."""
    targets = (
        list(resolved_targets)
        if resolved_targets is not None
        else parse_targets(ip_range, domains or [])
    )
    if enforce_public:
        # Validate the immutable list again immediately before probing.
        for ip, _hostname in targets:
            validate_public_address(ip)
    if not scan_internal:
        targets = [(ip, hn) for ip, hn in targets if not is_internal_ip(ip)]
    ports = ports or [443]

    total = len(targets)
    if not total:
        if progress_cb:
            progress_cb(0, 0)
        return []

    results: list[DiscoveredService] = []
    semaphore = asyncio.Semaphore(max_concurrency)
    lock = asyncio.Lock()
    done = 0

    async def probe_host(ip: str, hostname: str | None) -> None:
        nonlocal done
        # Chequeo temprano: los probes que todavia no tomaron el semaforo abandonan
        # de una, en vez de esperar turno para descubrir que el scan ya murio.
        if cancel_check and cancel_check():
            raise DiscoveryCancelled()
        async with semaphore:
            try:
                found = await scan_ip(
                    ip,
                    ports,
                    timeout=timeout,
                    hostname=hostname,
                    enforce_public=enforce_public,
                )
            except Exception:
                found = []
        async with lock:
            results.extend(found)
            done += 1
            if progress_cb:
                progress_cb(done, total)
        if cancel_check and cancel_check():
            raise DiscoveryCancelled()

    await asyncio.gather(*(probe_host(ip, hn) for ip, hn in targets))
    results.sort(key=lambda d: (d.ip_address, d.port))
    return results


def run_discovery_sync(
    ip_range: str = "",
    domains: list[str] | None = None,
    ports: list[int] | None = None,
    scan_internal: bool = True,
    timeout: float = 1.5,
    progress_cb: Optional[Callable[[int, int], None]] = None,
    max_concurrency: int = 128,
    cancel_check: Optional[Callable[[], bool]] = None,
    resolved_targets: list[tuple[str, str | None]] | None = None,
    enforce_public: bool = False,
) -> list[DiscoveredService]:
    """Version bloqueante de run_discovery (para background jobs / tests).

    Levanta DiscoveryCancelled si cancel_check() empieza a responder True.
    """
    return asyncio.run(
        run_discovery(
            ip_range=ip_range,
            domains=domains,
            ports=ports,
            scan_internal=scan_internal,
            timeout=timeout,
            progress_cb=progress_cb,
            max_concurrency=max_concurrency,
            cancel_check=cancel_check,
            resolved_targets=resolved_targets,
            enforce_public=enforce_public,
        )
    )
