"""Modelo de datos para OS/Service Fingerprint."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ServiceFingerprint:
    """Resultado del fingerprint de software/SO de un servidor TLS.

    Reemplaza el ``osFingerprint: {detected: false}`` hardcodeado.
    El nombre del campo en el frontend se mantiene ``osFingerprint`` por
    compatibilidad, pero internamente cubre software + version + SO.
    """

    detected: bool = False
    method: str | None = None  # "ja3" | "ja3s" | "http_banner" | "ssh_banner" | "smtp_banner" | "ttl_heuristic"
    software_name: str | None = None  # ej. "nginx", "OpenSSH"
    software_version: str | None = None  # ej. "1.18.0"
    os_family: str | None = None  # ej. "Linux", "Windows"
    confidence: str = "low"  # "high" | "medium" | "low"
    raw_banner: str | None = None
    ja3_hash: str | None = None
    ja3s_hash: str | None = None

    def to_dict(self) -> dict:
        return {
            "detected": self.detected,
            "method": self.method,
            "software_name": self.software_name,
            "software_version": self.software_version,
            "os_family": self.os_family,
            "confidence": self.confidence,
            "raw_banner": self.raw_banner,
            "ja3_hash": self.ja3_hash,
            "ja3s_hash": self.ja3s_hash,
        }

    def to_frontend_dto(self) -> dict:
        """Serializa al formato del frontend (camelCase, campos de OsFingerprintOut)."""
        return {
            "detected": self.detected,
            "os": self.os_family,
            "service": self.software_name,
            "banner": self.raw_banner,
            "confidence": self.confidence if self.detected else None,
            "note": "" if self.detected else "OS/service fingerprinting not available.",
            "softwareVersion": self.software_version,
            "ja3Hash": self.ja3_hash,
            "ja3sHash": self.ja3s_hash,
            "method": self.method,
        }
