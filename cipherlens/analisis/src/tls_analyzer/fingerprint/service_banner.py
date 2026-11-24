"""Banner grabbing síncrono para identificar software/SO del servidor.

Extrae la lógica de discovery.py y la pone a disposición como módulo compartido
tanto para TLS Scanner puntual como para Network Discovery.
"""

from __future__ import annotations

import re
import socket
import ssl
from typing import Optional

from ..cloud_network import PinnedTarget, open_target_connection
from .models import ServiceFingerprint

# Patrones de parsing de banners — (regex sobre banner lowercase, software_name, software_version)
_HTTP_SERVER_PATTERNS = [
    (re.compile(r"nginx/([\d.]+)"), "nginx"),
    (re.compile(r"apache/([\d.]+)"), "Apache httpd"),
    (re.compile(r"openresty/([\d.]+)"), "OpenResty"),
    (re.compile(r"cloudfront"), "CloudFront"),
    (re.compile(r"microsoft-iis/([\d.]+)"), "Microsoft IIS"),
    (re.compile(r"lighttpd/([\d.]+)"), "Lighttpd"),
    (re.compile(r"caddy"), "Caddy"),
    (re.compile(r"gunicorn/([\d.]+)"), "Gunicorn"),
    (re.compile(r"uvicorn"), "Uvicorn"),
    (re.compile(r"cloudflare"), "Cloudflare"),
    (re.compile(r"litespeed/([\d.]+)"), "LiteSpeed"),
    (re.compile(r"haproxy"), "HAProxy"),
    (re.compile(r"varnish/([\d.]+)"), "Varnish"),
    (re.compile(r"ats/([\d.]+)"), "Apache Traffic Server"),
]

_SSH_BANNER_RE = re.compile(r"SSH-[\d.]+-(\S+?)(?:\s|$)")
_SMTP_BANNER_RE = re.compile(r"220\s+\S+\s+(?:ESMTP|SMTP)\s+(\S+)", re.IGNORECASE)


def grab_banner(
    host: str,
    port: int,
    timeout: float = 3.0,
    *,
    pinned_target: PinnedTarget | None = None,
) -> Optional[str]:
    """Conexión TCP cruda para leer el banner del servidor.

    Funciona para HTTP (puerto 80), SSH, SMTP. Para HTTPS (puerto 443)
    usar grab_https_banner().
    Devuelve el banner (max 512 bytes) o None si no se pudo leer.
    """
    try:
        sock = open_target_connection(
            host,
            port,
            min(timeout, 3.0),
            pinned_target=pinned_target,
        )
        try:
            sock.settimeout(min(timeout, 2.0))
            data = sock.recv(512)
        except (socket.timeout, ConnectionError):
            data = b""
        finally:
            sock.close()
        banner = data.decode("utf-8", errors="replace").strip()
        return banner[:512] if banner else None
    except (OSError, socket.timeout):
        return None


def grab_https_banner(
    host: str,
    port: int,
    timeout: float = 5.0,
    *,
    pinned_target: PinnedTarget | None = None,
) -> Optional[str]:
    """Hace una petición HTTPS para extraer el header 'Server:' del servidor.

    Devuelve el valor del header Server (ej: 'nginx/1.24.0') o None.
    """
    try:
        if pinned_target is not None:
            raw_sock = open_target_connection(
                host,
                port,
                min(timeout, 5.0),
                pinned_target=pinned_target,
            )
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            tls_sock = context.wrap_socket(raw_sock, server_hostname=host)
            host_header = f"[{host}]" if ":" in host else host
            if port != 443:
                host_header = f"{host_header}:{port}"
            tls_sock.sendall(
                (
                    "GET / HTTP/1.1\r\n"
                    f"Host: {host_header}\r\n"
                    "User-Agent:\r\n"
                    "Connection: close\r\n\r\n"
                ).encode("ascii", errors="ignore")
            )
            tls_sock.settimeout(min(timeout, 5.0))
            response = bytearray()
            while b"\r\n\r\n" not in response and len(response) < 32768:
                chunk = tls_sock.recv(min(4096, 32768 - len(response)))
                if not chunk:
                    break
                response.extend(chunk)
            tls_sock.close()
            header_block = bytes(response).split(b"\r\n\r\n", 1)[0]
            for line in header_block.decode("iso-8859-1", errors="replace").splitlines()[1:]:
                name, separator, value = line.partition(":")
                if separator and name.strip().lower() == "server":
                    return value.strip() or None
            return None

        import httpx

        url = f"https://{host}:{port}/"
        with httpx.Client(
            timeout=min(timeout, 5.0),
            follow_redirects=False,
            verify=False,
        ) as client:
            resp = client.get(url, headers={"User-Agent": ""})
            server = resp.headers.get("server", "")
            return server if server else None
    except Exception:
        return None


def parse_http_banner(banner: str) -> tuple[str | None, str | None]:
    """Extrae software_name y version del header HTTP Server."""
    if not banner:
        return None, None
    low = banner.lower()
    for pattern, name in _HTTP_SERVER_PATTERNS:
        m = pattern.search(low)
        if m:
            version = m.group(1) if m.lastindex else None
            return name, version
    return None, None


def parse_ssh_banner(banner: str) -> tuple[str | None, str | None]:
    """Extrae software del banner SSH (ej. 'OpenSSH_8.9p1')."""
    if not banner:
        return None, None
    m = _SSH_BANNER_RE.search(banner)
    if m:
        return "OpenSSH", m.group(1)
    return None, None


def parse_smtp_banner(banner: str) -> tuple[str | None, str | None]:
    """Extrae software del banner SMTP (ej. 'Postfix')."""
    if not banner:
        return None, None
    m = _SMTP_BANNER_RE.search(banner)
    if m:
        return m.group(1), None
    return None, None


def fingerprint_from_banner(service: str, banner: str | None) -> ServiceFingerprint:
    """Convierte un banner crudo en un ServiceFingerprint estructurado.

    ``service`` es el nombre del servicio detectado (http, ssh, smtp, etc.).
    """
    if not banner:
        return ServiceFingerprint(detected=False)

    low = banner.lower()
    software_name: str | None = None
    software_version: str | None = None
    method: str | None = None

    # HTTP
    if service in ("http", "https", "https-alt", "http-proxy", "http-alt"):
        software_name, software_version = parse_http_banner(banner)
        if software_name:
            method = "http_banner"

    # SSH
    if not software_name and (service == "ssh" or "ssh" in low):
        software_name, software_version = parse_ssh_banner(banner)
        if software_name:
            method = "ssh_banner"

    # SMTP
    if not software_name and service in ("smtp",):
        software_name, software_version = parse_smtp_banner(banner)
        if software_name:
            method = "smtp_banner"

    # Fallback genérico: si el banner contiene "ssh" en cualquier contexto
    if not software_name and "ssh" in low:
        software_name = "SSH"
        method = "ssh_banner"

    if software_name:
        return ServiceFingerprint(
            detected=True,
            method=method,
            software_name=software_name,
            software_version=software_version,
            confidence="high",
            raw_banner=banner,
        )

    return ServiceFingerprint(detected=False, raw_banner=banner)
