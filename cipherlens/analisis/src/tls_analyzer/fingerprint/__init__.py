"""Módulo de OS/Service Fingerprinting compartido.

Provee fingerprint tanto para TLS Scanner puntual como para Network Discovery.
"""

from .models import ServiceFingerprint
from .service_banner import fingerprint_from_banner, grab_banner, grab_https_banner
from .tls_fingerprint import compute_ja3, compute_ja3s, fingerprint_from_handshake

__all__ = [
    "ServiceFingerprint",
    "fingerprint_from_banner",
    "fingerprint_from_handshake",
    "grab_banner",
    "grab_https_banner",
    "compute_ja3",
    "compute_ja3s",
]
