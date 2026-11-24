"""TLS Handshake analyzer - core module for connecting and capturing TLS data."""

import shutil
import socket
import ssl
import subprocess
import json
import struct
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from typing import Optional

from .cloud_network import PinnedTarget, open_target_connection

TLS_VERSIONS = {
    ssl.TLSVersion.TLSv1: "TLS 1.0",
    ssl.TLSVersion.TLSv1_1: "TLS 1.1",
    ssl.TLSVersion.TLSv1_2: "TLS 1.2",
    ssl.TLSVersion.TLSv1_3: "TLS 1.3",
}

TLS_EXTENSION_NAMES = {
    0x0000: "server_name",
    0x0001: "max_fragment_length",
    0x0005: "status_request",
    0x000A: "supported_groups",
    0x000B: "ec_point_formats",
    0x000D: "signature_algorithms",
    0x0010: "ALPN",
    0x0012: "signed_certificate_timestamp",
    0x0013: "client_certificate_type",
    0x0015: "padding",
    0x001B: "compress_certificate",
    0x0023: "extended_master_secret",
    0x002B: "supported_versions",
    0x0033: "key_share",
    0x4469: "certificate_authorities",
    0xFE0D: "encrypted_client_hello_outer",
    0xFF01: "renegotiation_info",
}


@dataclass
class HandshakeResult:
    """Result of a TLS handshake analysis."""

    host: str
    port: int
    ip_address: str = ""
    negotiated_protocol: str = ""
    negotiated_cipher: str = ""
    cipher_info: dict = field(default_factory=dict)
    supported_protocols: list[str] = field(default_factory=list)
    shared_ciphers: list[dict] = field(default_factory=list)
    server_hello_extensions: dict = field(default_factory=dict)
    accepted_cipher_suites: list[dict] = field(default_factory=list)
    rejected_cipher_suites: list[str] = field(default_factory=list)
    extensions: dict = field(default_factory=dict)
    server_cert_chain: list[dict] = field(default_factory=list)
    connection_error: Optional[str] = None
    peer_cert_der: Optional[bytes] = field(default=None, repr=False)
    peer_cert_chain_der: list = field(default_factory=list, repr=False)
    raw_client_hello: Optional[bytes] = field(default=None, repr=False)
    raw_server_hello: Optional[bytes] = field(default=None, repr=False)

    def to_dict(self) -> dict:
        d = asdict(self)
        d.pop("peer_cert_der", None)
        d.pop("peer_cert_chain_der", None)
        d.pop("raw_client_hello", None)
        d.pop("raw_server_hello", None)
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, default=str)


def _resolve_host(host: str) -> str:
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return ""


def _create_ssl_context(
    protocol: Optional[ssl.TLSVersion] = None,
    min_version: Optional[ssl.TLSVersion] = None,
    max_version: Optional[ssl.TLSVersion] = None,
) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    if protocol:
        ctx.minimum_version = protocol
        ctx.maximum_version = protocol
    else:
        if min_version:
            ctx.minimum_version = min_version
        if max_version:
            ctx.maximum_version = max_version

    return ctx


def _do_handshake(
    host: str,
    port: int,
    ctx: ssl.SSLContext,
    timeout: float = 5.0,
    *,
    pinned_target: PinnedTarget | None = None,
) -> dict:
    raw_sock = open_target_connection(
        host, port, timeout, pinned_target=pinned_target
    )
    ssl_sock = ctx.wrap_socket(raw_sock, server_hostname=host)

    result = {
        "protocol": ssl_sock.version(),
        "cipher": ssl_sock.cipher(),
        "shared_ciphers": ssl_sock.shared_ciphers() or [],
        "alpn_protocol": ssl_sock.selected_alpn_protocol(),
        "npn_protocol": getattr(ssl_sock, "selected_npn_protocol", lambda: None)(),
        "compression": ssl_sock.compression(),
    }

    peer_cert = ssl_sock.getpeercert(binary_form=True)
    if peer_cert:
        result["peer_cert_der"] = peer_cert

    try:
        chain = ssl_sock.getpeercert_chain()
        if chain:
            result["peer_cert_chain_der"] = chain
    except Exception:
        pass

    ssl_sock.close()
    raw_sock.close()
    return result


def _capture_raw_server_hello(
    host: str,
    port: int,
    ctx: ssl.SSLContext,
    timeout: float = 5.0,
    *,
    pinned_target: PinnedTarget | None = None,
) -> tuple[Optional[bytes], Optional[bytes]]:
    """
    Perform a TLS handshake using MemoryBIO to capture raw ClientHello and ServerHello bytes.
    Returns (raw_server_response, raw_client_hello), or (None, None) on failure.
    """
    raw_sock = open_target_connection(
        host, port, timeout, pinned_target=pinned_target
    )
    try:
        in_bio = ssl.MemoryBIO()
        out_bio = ssl.MemoryBIO()
        ssl_obj = ctx.wrap_bio(in_bio, out_bio)

        # Step 1: generate ClientHello
        try:
            ssl_obj.do_handshake()
        except ssl.SSLWantReadError:
            pass

        client_hello = out_bio.read()
        raw_sock.sendall(client_hello)

        # Step 2: receive raw server response
        server_response = b""
        while True:
            try:
                chunk = raw_sock.recv(16384)
                if not chunk:
                    break
                server_response += chunk
                in_bio.write(chunk)

                try:
                    ssl_obj.do_handshake()
                    break
                except ssl.SSLWantReadError:
                    continue
                except ssl.SSLZeroReturnError:
                    break
            except socket.timeout:
                break

        # Step 3: also get cert chain via normal SSL
        try:
            chain = ssl_obj.getpeercert_chain()
            if chain:
                der_certs = []
                for c in chain:
                    try:
                        der_certs.append(c)
                    except Exception:
                        pass
        except Exception:
            pass

        return (server_response or None, client_hello or None)

    except Exception:
        return (None, None)
    finally:
        try:
            raw_sock.close()
        except Exception:
            pass


def _parse_server_hello_extensions(raw_data: bytes) -> dict:
    """
    Parse raw TLS record bytes to extract ServerHello extensions.
    Returns a dict with the parsed ServerHello info.
    """
    result = {
        "tls_version": "",
        "cipher_suite": "",
        "cipher_suite_name": "",
        "session_id": "",
        "compression_method": 0,
        "extensions": [],
    }

    if not raw_data or len(raw_data) < 5:
        return result

    offset = 0

    while offset < len(raw_data):
        content_type = raw_data[offset]
        if content_type != 0x16:
            break

        rec_len = struct.unpack("!H", raw_data[offset + 3 : offset + 5])[0]
        if offset + 5 + rec_len > len(raw_data):
            break

        hs_type = raw_data[offset + 5]
        hs_len = struct.unpack("!I", b"\x00" + raw_data[offset + 6 : offset + 9])[0]

        if hs_type == 0x02:  # ServerHello
            pos = offset + 9

            srv_ver = struct.unpack("!H", raw_data[pos : pos + 2])[0]
            result["tls_version"] = f"0x{srv_ver:04x}"
            pos += 2

            random_bytes = raw_data[pos : pos + 32]
            result["random"] = random_bytes.hex()
            pos += 32

            sid_len = raw_data[pos]
            pos += 1
            session_id = raw_data[pos : pos + sid_len]
            result["session_id"] = session_id.hex()
            pos += sid_len

            cipher_suite = struct.unpack("!H", raw_data[pos : pos + 2])[0]
            result["cipher_suite"] = f"0x{cipher_suite:04x}"
            result["cipher_suite_name"] = _get_cipher_name(cipher_suite)
            pos += 2

            compression = raw_data[pos]
            result["compression_method"] = compression
            pos += 1

            ext_len = struct.unpack("!H", raw_data[pos : pos + 2])[0]
            pos += 2
            ext_end = pos + ext_len

            while pos < ext_end:
                if pos + 4 > ext_end:
                    break
                etype = struct.unpack("!H", raw_data[pos : pos + 2])[0]
                elen = struct.unpack("!H", raw_data[pos + 2 : pos + 4])[0]
                edata = raw_data[pos + 4 : pos + 4 + elen]
                pos += 4 + elen

                ext_info = {
                    "type": etype,
                    "type_name": TLS_EXTENSION_NAMES.get(etype, f"unknown(0x{etype:04x})"),
                    "length": elen,
                    "data_hex": edata.hex(),
                }

                _parse_extension_data(etype, edata, ext_info)
                result["extensions"].append(ext_info)

            break

        offset += 5 + rec_len

    return result


def _parse_extension_data(etype: int, edata: bytes, ext_info: dict):
    """Parse specific extension data into human-readable fields."""
    try:
        if etype == 0x0000:  # server_name (SNI response)
            if len(edata) >= 5:
                sni_name_len = struct.unpack("!H", edata[3:5])[0]
                if len(edata) >= 5 + sni_name_len:
                    ext_info["sni"] = edata[5 : 5 + sni_name_len].decode("ascii", errors="replace")

        elif etype == 0x000A:  # supported_groups
            if len(edata) >= 2:
                num_groups = struct.unpack("!H", edata[0:2])[0] // 2
                groups = []
                for i in range(min(num_groups, (len(edata) - 2) // 2)):
                    g = struct.unpack("!H", edata[2 + i * 2 : 4 + i * 2])[0]
                    groups.append(f"0x{g:04x} ({_get_group_name(g)})")
                ext_info["groups"] = groups

        elif etype == 0x000B:  # ec_point_formats
            if len(edata) >= 1:
                num = edata[0]
                formats = []
                format_names = {0: "uncompressed", 1: "ansiX962_compressed_prime", 2: "ansiX962_compressed_char2"}
                for i in range(min(num, len(edata) - 1)):
                    f = edata[1 + i]
                    formats.append(f"{f} ({format_names.get(f, 'unknown')})")
                ext_info["point_formats"] = formats

        elif etype == 0x000D:  # signature_algorithms
            if len(edata) >= 2:
                sig_len = struct.unpack("!H", edata[0:2])[0]
                sig_algs = []
                for i in range(min(sig_len // 2, (len(edata) - 2) // 2)):
                    sa = struct.unpack("!H", edata[2 + i * 2 : 4 + i * 2])[0]
                    sig_algs.append(f"0x{sa:04x}")
                ext_info["algorithms"] = sig_algs

        elif etype == 0x0010:  # ALPN
            if len(edata) >= 2:
                alpn_len = struct.unpack("!H", edata[0:2])[0]
                protocols = []
                pos = 2
                while pos < 2 + alpn_len and pos < len(edata):
                    proto_len = edata[pos]
                    if pos + 1 + proto_len <= len(edata):
                        protocols.append(edata[pos + 1 : pos + 1 + proto_len].decode("ascii", errors="replace"))
                    pos += 1 + proto_len
                ext_info["protocols"] = protocols

        elif etype == 0x002B:  # supported_versions
            if len(edata) >= 1:
                num = edata[0]
                versions = []
                for i in range(min(num, (len(edata) - 1) // 2)):
                    v = struct.unpack("!H", edata[1 + i * 2 : 3 + i * 2])[0]
                    versions.append(f"0x{v:04x} ({TLS_VERSIONS.get(v, 'unknown')})")
                ext_info["versions"] = versions

        elif etype == 0x0033:  # key_share
            if len(edata) >= 4:
                group = struct.unpack("!H", edata[0:2])[0]
                key_len = struct.unpack("!H", edata[2:4])[0]
                key_data = edata[4 : 4 + key_len] if len(edata) >= 4 + key_len else b""
                ext_info["group"] = f"0x{group:04x} ({_get_group_name(group)})"
                ext_info["key_length"] = key_len
                ext_info["key_hex"] = key_data.hex() if key_data else ""

        elif etype == 0xFF01:  # renegotiation_info
            if len(edata) >= 1:
                ext_info["renegotiation_support"] = edata[0] == 1

        elif etype == 0x0023:  # extended_master_secret
            ext_info["supported"] = True

    except Exception:
        pass


def _get_cipher_name(cipher_id: int) -> str:
    """Map cipher suite ID to name."""
    cipher_names = {
        0x1301: "TLS_AES_128_GCM_SHA256",
        0x1302: "TLS_AES_256_GCM_SHA384",
        0x1303: "TLS_CHACHA20_POLY1305_SHA256",
        0xC02B: "ECDHE-ECDSA-AES128-GCM-SHA256",
        0xC02C: "ECDHE-ECDSA-AES256-GCM-SHA384",
        0xC02F: "ECDHE-RSA-AES128-GCM-SHA256",
        0xC030: "ECDHE-RSA-AES256-GCM-SHA384",
        0xCCA9: "ECDHE-ECDSA-CHACHA20-POLY1305",
        0xCCA8: "ECDHE-RSA-CHACHA20-POLY1305",
        0xC023: "ECDHE-ECDSA-AES128-SHA256",
        0xC024: "ECDHE-ECDSA-AES256-SHA384",
        0xC027: "ECDHE-RSA-AES128-SHA256",
        0xC028: "ECDHE-RSA-AES256-SHA384",
        0xC013: "ECDHE-RSA-AES128-SHA",
        0xC014: "ECDHE-RSA-AES256-SHA",
        0x009C: "AES128-GCM-SHA256",
        0x009D: "AES256-GCM-SHA384",
        0x0033: "DHE-RSA-AES128-SHA",
        0x0039: "DHE-RSA-AES256-SHA",
        0x006B: "DHE-RSA-AES128-SHA256",
        0x006D: "DHE-RSA-AES256-SHA256",
        0x009E: "DHE-RSA-AES128-GCM-SHA256",
        0x009F: "DHE-RSA-AES256-GCM-SHA384",
    }
    return cipher_names.get(cipher_id, f"unknown(0x{cipher_id:04x})")


def _get_group_name(group_id: int) -> str:
    group_names = {
        0x001D: "x25519",
        0x0017: "secp256r1",
        0x0018: "secp384r1",
        0x0019: "secp521r1",
        0x0100: "x25519kyber768",
        0x6399: "x25519_mlkem768",
    }
    return group_names.get(group_id, f"unknown(0x{group_id:04x})")


def _try_handshake_with_version(
    host: str,
    port: int,
    version: ssl.TLSVersion,
    timeout: float = 5.0,
    pinned_target: PinnedTarget | None = None,
) -> Optional[dict]:
    try:
        ctx = _create_ssl_context(protocol=version)
        return _do_handshake(
            host, port, ctx, timeout, pinned_target=pinned_target
        )
    except (ssl.SSLError, socket.error, OSError):
        return None


def _curl_probe(host: str, port: int, version_name: str, timeout: float = 5.0) -> bool:
    """Probe a TLS version using system curl (SChannel on Windows, OpenSSL elsewhere).

    Returns True if the server successfully negotiated the given TLS version.
    """
    curl = shutil.which("curl")
    if not curl:
        return False

    args = [curl, "-v", "-k", "--max-time", str(int(timeout)), "--silent"]
    if version_name == "TLS 1.0":
        args += ["--tlsv1.0", "--tls-max", "1.0"]
    elif version_name == "TLS 1.1":
        args += ["--tlsv1.1", "--tls-max", "1.1"]
    else:
        return False

    url = f"https://{host}:{port}/" if port != 443 else f"https://{host}/"
    args.append(url)

    try:
        proc = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout + 2,
            encoding="utf-8", errors="replace",
        )
        if proc.returncode == 0:
            return True
        return False
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False


def _sslyze_probe(host: str, port: int, timeout: float = 60.0) -> bool:
    """Probe SSLv3 support using sslyze via subprocess.

    Returns True if the server supports SSLv3.
    Gracefully returns False if sslyze is not installed.
    """
    import sys

    python = sys.executable
    cmd = [
        python, "-m", "sslyze",
        "--sslv3",
        "--json_out=-",
        f"{host}:{port}",
    ]

    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            encoding="utf-8", errors="replace",
        )
        if proc.returncode != 0 and not proc.stdout:
            return False
        data = json.loads(proc.stdout)
        try:
            scan = data["server_scan_results"][0]["scan_result"]
        except (KeyError, IndexError, TypeError):
            return False
        if scan is None:
            return False
        ssl3 = scan.get("ssl_3_0_cipher_suites", {})
        if ssl3.get("status") == "COMPLETED" and ssl3.get("result"):
            return ssl3["result"].get("is_tls_version_supported", False)
        return False
    except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError, KeyError, OSError, TypeError, AttributeError):
        return False


# sslyze reports cipher suites per TLS version under these result keys. Maps each
# to (openssl-style protocol string, display name) used across the analyzer.
_SSLYZE_VERSION_MAP = {
    "ssl_2_0_cipher_suites": ("SSLv2", "SSL 2.0"),
    "ssl_3_0_cipher_suites": ("SSLv3", "SSL 3.0"),
    "tls_1_0_cipher_suites": ("TLSv1", "TLS 1.0"),
    "tls_1_1_cipher_suites": ("TLSv1.1", "TLS 1.1"),
    "tls_1_2_cipher_suites": ("TLSv1.2", "TLS 1.2"),
    "tls_1_3_cipher_suites": ("TLSv1.3", "TLS 1.3"),
}

# CLI flag that enables the scan for each version key above.
_SSLYZE_VERSION_FLAGS = {
    "ssl_2_0_cipher_suites": "--sslv2",
    "ssl_3_0_cipher_suites": "--sslv3",
    "tls_1_0_cipher_suites": "--tlsv1",
    "tls_1_1_cipher_suites": "--tlsv1_1",
    "tls_1_2_cipher_suites": "--tlsv1_2",
    "tls_1_3_cipher_suites": "--tlsv1_3",
}


def _run_sslyze_full(host: str, port: int, timeout: float = 60.0) -> Optional[dict]:
    """Execute a full sslyze scan and return its ``scan_result`` dict.

    sslyze bundles its own OpenSSL with legacy ciphers (RC4, 3DES, ...), so it can
    reach servers that Python's OpenSSL can no longer negotiate (e.g. rc4.badssl.com).
    Returns ``None`` if sslyze is unavailable or the run fails.
    """
    import sys

    python = sys.executable
    cmd = [python, "-m", "sslyze", "--certinfo", "--json_out=-", f"{host}:{port}"]
    # Turn on per-version cipher scans in the order of the version map.
    for key in _SSLYZE_VERSION_FLAGS:
        cmd.insert(len(cmd) - 1, _SSLYZE_VERSION_FLAGS[key])

    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            encoding="utf-8", errors="replace",
        )
        if proc.returncode != 0 and not proc.stdout:
            return None
        data = json.loads(proc.stdout)
        return data["server_scan_results"][0]["scan_result"]
    except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError, KeyError, OSError):
        return None


def _build_handshake_from_sslyze(host: str, port: int, scan_result: dict) -> Optional[HandshakeResult]:
    """Build a HandshakeResult from a sslyze ``scan_result`` dict.

    Used as a fallback when Python's OpenSSL cannot negotiate a TLS handshake
    (legacy-only cipher hosts). Populates the protocol/cipher/cert fields the NIST
    analysis needs so the scan can proceed; ``connection_error`` stays ``None``.
    """
    result = HandshakeResult(host=host, port=port)
    result.ip_address = _resolve_host(host)

    accepted: list[dict] = []
    rejected: list[str] = []
    supported_protocols: list[str] = []
    ordered_versions: list[tuple[int, str]] = []  # (min ssl/tls level, display name)

    # Which versions are supported (highest-supported fingerprint for 'negotiated').
    _LEVELS: dict[str, int] = {
        "ssl_2_0_cipher_suites": 0, "ssl_3_0_cipher_suites": 1,
        "tls_1_0_cipher_suites": 2, "tls_1_1_cipher_suites": 3,
        "tls_1_2_cipher_suites": 4, "tls_1_3_cipher_suites": 5,
    }

    for key, (proto_str, display_name) in _SSLYZE_VERSION_MAP.items():
        block = (scan_result or {}).get(key)
        if not isinstance(block, dict):
            continue
        res = block.get("result")
        if not isinstance(res, dict) or not res.get("is_tls_version_supported"):
            continue

        supported_protocols.append(display_name)
        ordered_versions.append((_LEVELS[key], proto_str))

        for entry in res.get("accepted_cipher_suites", []) or []:
            cs = (entry or {}).get("cipher_suite") or {}
            accepted.append({
                "name": cs.get("openssl_name") or cs.get("name") or "",
                "protocol": proto_str,
                "description": "",
                "bits": cs.get("key_size", 0),
                "mac": "",
                "kea": "",
            })
        for entry in res.get("rejected_cipher_suites", []) or []:
            cs = (entry or {}).get("cipher_suite") or {}
            name = cs.get("openssl_name") or cs.get("name") or ""
            if name:
                rejected.append(name)

    if not supported_protocols or not accepted:
        return None

    # Highest supported version with accepted ciphers becomes the "negotiated" one.
    ordered_versions.sort(key=lambda t: t[0])
    _, negotiated_proto = ordered_versions[-1]
    negotiated = next((c["name"] for c in accepted if c["protocol"] == negotiated_proto), None)

    result.supported_protocols = supported_protocols
    result.accepted_cipher_suites = accepted
    result.rejected_cipher_suites = rejected
    result.negotiated_protocol = negotiated_proto
    if negotiated:
        result.negotiated_cipher = negotiated

    # Certificates: sslyze exposes each chain cert as PEM; decode to DER so the
    # certificate analyzer can consume them.
    try:
        ci = (scan_result or {}).get("certificate_info") or {}
        ci_res = ci.get("result")
        deployments = (ci_res or {}).get("certificate_deployments") or []
        chain = []
        if deployments:
            chain = (deployments[0] or {}).get("received_certificate_chain") or []
        der_list = []
        for cert in chain:
            pem = (cert or {}).get("as_pem") or ""
            if pem:
                der_list.append(ssl.PEM_cert_to_DER_cert(pem))
        if der_list:
            result.peer_cert_der = der_list[0]
            result.peer_cert_chain_der = der_list
    except Exception:
        pass

    return result


def analyze_protocols(
    host: str,
    port: int,
    timeout: float = 5.0,
    *,
    pinned_target: PinnedTarget | None = None,
) -> list[str]:
    supported = []

    # Stage 1: OpenSSL probes (fast, parallel)
    with ThreadPoolExecutor(max_workers=len(TLS_VERSIONS)) as pool:
        futures = {
            pool.submit(
                _try_handshake_with_version,
                host,
                port,
                ver,
                timeout,
                pinned_target,
            ): ver
            for ver in TLS_VERSIONS
        }
        for future in as_completed(futures):
            if future.result():
                supported.append(TLS_VERSIONS[futures[future]])

    has_modern = "TLS 1.2" in supported or "TLS 1.3" in supported

    # Stage 2: curl + sslyze in parallel (only if needed)
    needs_deprecated = not has_modern or "SSL 3.0" not in supported
    if needs_deprecated and pinned_target is None:
        with ThreadPoolExecutor(max_workers=3) as pool:
            futures = {}
            # curl for TLS 1.0/1.1
            for v in ["TLS 1.0", "TLS 1.1"]:
                if v not in supported:
                    futures[pool.submit(_curl_probe, host, port, v, timeout)] = v
            # sslyze for SSLv3 — only if no modern TLS detected
            if not has_modern:
                futures[pool.submit(_sslyze_probe, host, port, 60.0)] = "SSL 3.0"

            for future in as_completed(futures):
                ver = futures[future]
                if ver == "SSL 3.0":
                    if future.result():
                        supported.append("SSL 3.0")
                else:
                    if future.result() and ver not in supported:
                        supported.append(ver)

    return supported


def _probe_single_cipher(
    host: str,
    port: int,
    cipher_name: str,
    cipher_info: dict,
    timeout: float,
    pinned_target: PinnedTarget | None = None,
) -> dict | None:
    """Probe a single cipher suite. Returns accepted cipher dict or None."""
    try:
        probe_ctx = _create_ssl_context()
        probe_ctx.set_ciphers(cipher_name)
        result = _do_handshake(
            host,
            port,
            probe_ctx,
            timeout=min(timeout, 3.0),
            pinned_target=pinned_target,
        )
        if result:
            return {
                "name": cipher_name,
                "protocol": result["protocol"],
                "description": cipher_info.get("description", ""),
                "bits": cipher_info.get("alg_bits", 0),
                "mac": cipher_info.get("mac", ""),
                "kea": cipher_info.get("kea", ""),
            }
    except (ssl.SSLError, socket.error, OSError):
        pass
    except Exception:
        pass
    return None


def analyze_cipher_suites(
    host: str,
    port: int,
    timeout: float = 5.0,
    *,
    pinned_target: PinnedTarget | None = None,
) -> tuple[list[dict], list[str]]:
    accepted = []
    rejected = []

    try:
        ctx = _create_ssl_context()
        all_ciphers = ctx.get_ciphers()
    except Exception:
        return accepted, rejected

    with ThreadPoolExecutor(max_workers=10) as pool:
        futures = {
            pool.submit(
                _probe_single_cipher,
                host,
                port,
                c["name"],
                c,
                timeout,
                pinned_target,
            ): c["name"]
            for c in all_ciphers
        }
        for future in as_completed(futures):
            result = future.result()
            if result:
                accepted.append(result)
            else:
                rejected.append(futures[future])

    return accepted, rejected


def analyze_handshake(
    host: str,
    port: int = 443,
    timeout: float = 10.0,
    *,
    pinned_target: PinnedTarget | None = None,
) -> HandshakeResult:
    result = HandshakeResult(host=host, port=port)
    result.ip_address = (
        pinned_target.address if pinned_target is not None else _resolve_host(host)
    )

    # 1. Default handshake for basic info
    try:
        ctx = _create_ssl_context()
        handshake = _do_handshake(
            host, port, ctx, timeout, pinned_target=pinned_target
        )

        result.negotiated_protocol = handshake.get("protocol", "Unknown")

        # Save full cipher info (name, protocol, bits)
        cipher_tuple = handshake.get("cipher", {})
        if isinstance(cipher_tuple, tuple) and len(cipher_tuple) >= 3:
            result.cipher_info = {
                "name": cipher_tuple[0],
                "protocol": cipher_tuple[1],
                "bits": cipher_tuple[2],
            }
            result.negotiated_cipher = cipher_tuple[0]
        elif cipher_tuple:
            result.negotiated_cipher = str(cipher_tuple)

        # Save shared ciphers as list of dicts
        shared = handshake.get("shared_ciphers", [])
        if shared:
            result.shared_ciphers = [
                {"name": c[0], "protocol": c[1], "bits": c[2]}
                for c in shared
                if isinstance(c, tuple) and len(c) >= 3
            ]

        # ALPN / NPN
        if handshake.get("alpn_protocol"):
            result.extensions["ALPN"] = handshake["alpn_protocol"]
        if handshake.get("npn_protocol"):
            result.extensions["NPN"] = handshake["npn_protocol"]
        if handshake.get("compression"):
            result.extensions["Compression"] = handshake["compression"]

        # Store DER cert data for later analysis
        if "peer_cert_der" in handshake:
            result.peer_cert_der = handshake["peer_cert_der"]
        if "peer_cert_chain_der" in handshake:
            result.peer_cert_chain_der = handshake["peer_cert_chain_der"]

    except ssl.SSLError as e:
        # Negotiation failed. This often happens for legacy-only cipher hosts
        # (e.g. RC4/3DES servers) that Python's OpenSSL can no longer talk to but
        # that sslyze (which bundles its own OpenSSL with legacy ciphers) can reach.
        if pinned_target is None:
            fallback = _build_handshake_from_sslyze(
                host, port, _run_sslyze_full(host, port, 60.0)
            )
            if fallback is not None:
                return fallback
        result.connection_error = str(e)
        return result
    except Exception as e:
        result.connection_error = str(e)
        return result

    # 2-4. Run MemoryBIO capture, protocol detection, and cipher probing in parallel
    with ThreadPoolExecutor(max_workers=3) as pool:
        raw_future = pool.submit(
            _capture_raw_server_hello,
            host,
            port,
            _create_ssl_context(),
            timeout,
            pinned_target=pinned_target,
        )
        proto_future = pool.submit(
            analyze_protocols,
            host,
            port,
            timeout,
            pinned_target=pinned_target,
        )
        cipher_future = pool.submit(
            analyze_cipher_suites,
            host,
            port,
            timeout,
            pinned_target=pinned_target,
        )

        # 2. Capture raw ServerHello extensions via MemoryBIO
        try:
            raw_server_data, raw_client_data = raw_future.result()
            if raw_server_data:
                result.raw_server_hello = raw_server_data
                result.server_hello_extensions = _parse_server_hello_extensions(raw_server_data)
            if raw_client_data:
                result.raw_client_hello = raw_client_data
        except Exception:
            pass

        # 3. Detect supported protocol versions
        result.supported_protocols = proto_future.result()

        # 4. Detect accepted cipher suites
        result.accepted_cipher_suites, result.rejected_cipher_suites = cipher_future.result()

    return result
