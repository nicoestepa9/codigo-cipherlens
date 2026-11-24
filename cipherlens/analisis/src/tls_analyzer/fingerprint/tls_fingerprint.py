"""Fingerprint TLS pasivo: JA3/JA3S y heurística de TTL.

JA3/JA3S son hashes MD5 calculados a partir de los campos del ClientHello
y ServerHello respectivamente. Identifican la implementación TLS (librería
y versión) del servidor sin requerir conexión adicional.

Requiere que handshake.py preserve el ClientHello/ServerHello crudo con
el orden original de cipher suites y extensiones.
"""

from __future__ import annotations

import hashlib
import struct
from typing import Optional

from .models import ServiceFingerprint


def _compute_md5(data: str) -> str:
    """Calcula hash MD5 de un string y devuelve el hex digest."""
    return hashlib.md5(data.encode("utf-8")).hexdigest()


def _parse_client_hello_extensions(data: bytes, offset: int, ext_end: int) -> dict:
    """Parsea extensiones del ClientHello para JA3."""
    extensions: list[str] = []
    ec_point_formats: list[str] = []
    elliptic_curves: list[str] = []

    while offset < ext_end:
        if offset + 4 > ext_end:
            break
        etype = struct.unpack("!H", data[offset:offset + 2])[0]
        elen = struct.unpack("!H", data[offset + 2:offset + 4])[0]
        edata = data[offset + 4:offset + 4 + elen]
        offset += 4 + elen

        extensions.append(str(etype))

        if etype == 0x000A and len(edata) >= 2:
            num = struct.unpack("!H", edata[0:2])[0] // 2
            for i in range(min(num, (len(edata) - 2) // 2)):
                g = struct.unpack("!H", edata[2 + i * 2:4 + i * 2])[0]
                elliptic_curves.append(str(g))

        elif etype == 0x000B and len(edata) >= 1:
            num = edata[0]
            for i in range(min(num, len(edata) - 1)):
                ec_point_formats.append(str(edata[1 + i]))

    return {
        "extensions": extensions,
        "ec_point_formats": ec_point_formats,
        "elliptic_curves": elliptic_curves,
    }


def compute_ja3(client_hello_raw: bytes) -> Optional[str]:
    """Calcula JA3 hash desde un ClientHello crudo.

    JA3 = MD5(TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats)

    ``client_hello_raw`` debe ser el registro TLS completo que contiene el
    ClientHello, incluyendo el prefix de content type + handshake type.
    """
    if not client_hello_raw or len(client_hello_raw) < 44:
        return None

    try:
        offset = 0
        while offset < len(client_hello_raw):
            content_type = client_hello_raw[offset]
            if content_type != 0x16:
                break

            rec_len = struct.unpack("!H", client_hello_raw[offset + 3:offset + 5])[0]
            if offset + 5 + rec_len > len(client_hello_raw):
                break

            hs_type = client_hello_raw[offset + 5]
            if hs_type != 0x01:  # ClientHello
                offset += 5 + rec_len
                continue

            pos = offset + 9  # skip hs_type(1) + hs_len(3)

            # TLS version
            tls_version = struct.unpack("!H", client_hello_raw[pos:pos + 2])[0]
            pos += 2

            # Random (32 bytes)
            pos += 32

            # Session ID
            sid_len = client_hello_raw[pos]
            pos += 1 + sid_len

            # Cipher suites
            cs_len = struct.unpack("!H", client_hello_raw[pos:pos + 2])[0]
            pos += 2
            ciphers = []
            for i in range(cs_len // 2):
                c = struct.unpack("!H", client_hello_raw[pos + i * 2:pos + i * 2 + 2])[0]
                ciphers.append(str(c))
            pos += cs_len

            # Compression methods
            comp_len = client_hello_raw[pos]
            pos += 1 + comp_len

            # Extensions
            ext_len = struct.unpack("!H", client_hello_raw[pos:pos + 2])[0]
            pos += 2
            ext_end = pos + ext_len

            parsed = _parse_client_hello_extensions(client_hello_raw, pos, ext_end)

            # Construir string JA3
            ja3_parts = [
                str(tls_version),
                "-".join(ciphers),
                "-".join(parsed["extensions"]),
                "-".join(parsed["elliptic_curves"]),
                "-".join(parsed["ec_point_formats"]),
            ]
            ja3_string = ",".join(ja3_parts)
            return _compute_md5(ja3_string)

    except (struct.error, IndexError):
        return None

    return None


def compute_ja3s(server_hello_raw: bytes) -> Optional[str]:
    """Calcula JA3S hash desde un ServerHello crudo.

    JA3S = MD5(TLSVersion,SelectedCipher,Extensions)

    ``server_hello_raw`` debe contener los bytes del ServerHello (o la
    respuesta completa del servidor que incluya el ServerHello).
    """
    if not server_hello_raw or len(server_hello_raw) < 44:
        return None

    try:
        offset = 0
        while offset < len(server_hello_raw):
            content_type = server_hello_raw[offset]
            if content_type != 0x16:
                break

            rec_len = struct.unpack("!H", server_hello_raw[offset + 3:offset + 5])[0]
            if offset + 5 + rec_len > len(server_hello_raw):
                break

            hs_type = server_hello_raw[offset + 5]
            if hs_type != 0x02:  # ServerHello
                offset += 5 + rec_len
                continue

            pos = offset + 9

            # TLS version
            tls_version = struct.unpack("!H", server_hello_raw[pos:pos + 2])[0]
            pos += 2

            # Random (32 bytes)
            pos += 32

            # Session ID
            sid_len = server_hello_raw[pos]
            pos += 1 + sid_len

            # Selected cipher suite
            cipher_suite = struct.unpack("!H", server_hello_raw[pos:pos + 2])[0]
            pos += 2

            # Compression method
            pos += 1

            # Extensions
            ext_len = struct.unpack("!H", server_hello_raw[pos:pos + 2])[0]
            pos += 2
            ext_end = pos + ext_len

            extensions: list[str] = []
            while pos < ext_end:
                if pos + 4 > ext_end:
                    break
                etype = struct.unpack("!H", server_hello_raw[pos:pos + 2])[0]
                elen = struct.unpack("!H", server_hello_raw[pos + 2:pos + 4])[0]
                pos += 4 + elen
                extensions.append(str(etype))

            ja3s_parts = [
                str(tls_version),
                str(cipher_suite),
                "-".join(extensions),
            ]
            ja3s_string = ",".join(ja3s_parts)
            return _compute_md5(ja3s_string)

    except (struct.error, IndexError):
        return None

    return None


def fingerprint_from_handshake(
    *,
    client_hello_raw: bytes | None = None,
    server_hello_raw: bytes | None = None,
) -> ServiceFingerprint:
    """Construye un ServiceFingerprint con JA3/JA3S calculados desde los datos crudos del handshake.

    No determina software_name/version (eso requiere banner grabbing),
    pero proporciona los hashes de implementación TLS.
    """
    ja3 = compute_ja3(client_hello_raw) if client_hello_raw else None
    ja3s = compute_ja3s(server_hello_raw) if server_hello_raw else None

    detected = ja3 is not None or ja3s is not None
    confidence = "medium" if detected else "low"

    return ServiceFingerprint(
        detected=detected,
        method="ja3" if ja3 else ("ja3s" if ja3s else None),
        confidence=confidence,
        ja3_hash=ja3,
        ja3s_hash=ja3s,
    )
