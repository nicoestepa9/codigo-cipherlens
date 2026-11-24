"""Seudonimizacion local del agente (Parte 5.6).

Reemplaza identificadores internos por seudonimos **estables** calculados con
HMAC-SHA256 y un secreto local del agente. El mapeo seudonimo -> valor real
queda solo en el agente y nunca viaja a la plataforma.
"""

from __future__ import annotations

import hashlib
import hmac

from ..ai_privacy import _is_internal_hostname, _is_private_ipv4
from . import state


class Pseudonymizer:
    def __init__(self, secret: bytes, mode: str = "off") -> None:
        self.secret = secret
        self.mode = mode
        self.mapping: dict[str, str] = state.load_mapping()
        self._dirty = False

    def _pseudo(self, kind: str, value: str) -> str:
        digest = hmac.new(
            self.secret, f"{kind}:{value}".encode("utf-8"), hashlib.sha256
        ).hexdigest()[:6]
        pseudo = f"{kind}-{digest}"
        if self.mapping.get(pseudo) != value:
            self.mapping[pseudo] = value
            self._dirty = True
        return pseudo

    def host(self, host: str | None) -> str | None:
        if not host or self.mode == "off":
            return host
        if self.mode == "internal" and not self._is_internal_host(host):
            return host
        return self._pseudo("host", host)

    def ip(self, ip: str | None) -> str | None:
        if not ip or self.mode == "off":
            return ip
        if self.mode == "internal" and not _is_private_ipv4(ip):
            return ip
        return self._pseudo("ip", ip)

    @staticmethod
    def _is_internal_host(host: str) -> bool:
        if _is_private_ipv4(host):
            return True
        return _is_internal_hostname(host)

    def flush(self) -> None:
        if self._dirty:
            state.save_mapping(self.mapping)
            self._dirty = False

    # -- aplicacion al payload ---------------------------------------------
    def apply_scan(self, payload: dict) -> dict:
        if self.mode == "off":
            return payload
        target = payload.get("target") or {}
        if "host" in target:
            target["host"] = self.host(target["host"])
        if payload.get("ipAddress"):
            payload["ipAddress"] = self.ip(payload["ipAddress"])

        for finding in payload.get("findings", []):
            if finding.get("affectedHost"):
                finding["affectedHost"] = self.host(finding["affectedHost"])

        cert = payload.get("certificate") or {}
        self._apply_cert(cert)
        for c in payload.get("chain", []) or []:
            self._apply_cert(c)

        handshake = payload.get("handshake") or {}
        if handshake.get("ip_address"):
            handshake["ip_address"] = self.ip(handshake["ip_address"])
        return payload

    def _apply_cert(self, cert: dict) -> None:
        if not cert:
            return
        subject = cert.get("subject")
        if isinstance(subject, dict) and subject.get("CN"):
            subject["CN"] = self.host(subject["CN"])
        issuer = cert.get("issuer")
        if isinstance(issuer, dict) and issuer.get("CN"):
            issuer["CN"] = self.host(issuer["CN"])
        if isinstance(cert.get("san"), list):
            cert["san"] = [self.host(s) if isinstance(s, str) else s for s in cert["san"]]

    def apply_discovery(self, payload: dict) -> dict:
        if self.mode == "off":
            return payload
        for result in payload.get("results", []):
            if result.get("ipAddress"):
                result["ipAddress"] = self.ip(result["ipAddress"])
            if result.get("hostname"):
                result["hostname"] = self.host(result["hostname"])
        return payload
