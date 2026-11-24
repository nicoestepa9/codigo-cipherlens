"""LLM Privacy: redacción/minimización de datos (Parte 4.3).

Reduce superficie de datos sensibles antes de enviar al LLM o al render.
"""

from __future__ import annotations

import re

from .api.config import settings

AI_FIELD_MAX_LEN = int(getattr(settings, "ai_field_max_len", 200))


# Patrones comunes de datos sensibles
_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6_RE = re.compile(
    r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,6}:(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}\b"
)
_PEM_RE = re.compile(r"-----BEGIN [A-Z0-9 ]+-----.*?-----END [A-Z0-9 ]+-----", flags=re.DOTALL | re.IGNORECASE)
_SERIAL_RE = re.compile(r"serial(?:Number)?\s*[:=]\s*[0-9A-Fa-f:-]+", flags=re.IGNORECASE)
_CN_SAN_RE = re.compile(r"(?:CN|Subject Alternative Name|DNS|IP Address)\s*[:=]\s*[^\s,;]+", flags=re.IGNORECASE)


def redact(text: str) -> str:
    if not text:
        return ""
    t = text
    t = _PEM_RE.sub("[PEM_REDACTED]", t)
    t = _EMAIL_RE.sub("[email_redacted]", t)
    t = _IPV6_RE.sub("[ipv6_redacted]", t)
    t = _IPV4_RE.sub("[ip_redacted]", t)
    t = _SERIAL_RE.sub("[serial_redacted]", t)
    t = _CN_SAN_RE.sub("[cert_ident_redacted]", t)
    return t


def minimize(text: str, max_len: int = AI_FIELD_MAX_LEN) -> str:
    if not text:
        return ""
    t = redact(text)
    if len(t) > max_len:
        t = t[: max_len - 1] + "…"
    return t


# ---------------------------------------------------------------------------
# Anonymizer (Parte 4.4): reemplaza identificadores internos por marcadores
# neutros y estables por request. El mapa vive solo en memoria (no se persiste
# ni se loguea). `restore()` se ejecuta en el servidor, después de sanear la
# salida del LLM.
# ---------------------------------------------------------------------------

# Sufijos/TLDs que suelen denotar infraestructura interna.
_INTERNAL_SUFFIXES = (
    ".local", ".lan", ".internal", ".corp", ".intranet",
    ".home", ".localdomain",
)

# CAs públicas conocidas: se permite conservar su nombre (es información
# pública, no identifica a la organización).
_PUBLIC_CA_NAMES = {
    "let's encrypt", "letsencrypt", "digicert", "sectigo", "comodo",
    "godaddy", "globalsign", "entrust", "actalis", "buypass",
}

# Componentes del subject/issuer que nunca se envían al LLM (pueden contener
# nombres de personas u organizaciones).
_FORBIDDEN_CERT_COMPONENTS = {
    "o", "ou", "l", "st", "c", "emailaddress", "serialnumber",
    "organization", "organizationalunit", "locality", "state",
    "country", "commonname", "email",
}


def _is_private_ipv4(ip: str) -> bool:
    """True para rangos privados, loopback, link-local y CGNAT (RFC1918/6598)."""
    try:
        parts = [int(p) for p in ip.split(".")]
    except ValueError:
        return False
    if len(parts) != 4 or any(p < 0 or p > 255 for p in parts):
        return False
    a, b = parts[0], parts[1]
    if a == 10:
        return True
    if a == 127:
        return True
    if a == 192 and b == 168:
        return True
    if a == 172 and 16 <= b <= 31:
        return True
    if a == 169 and b == 254:
        return True
    if a == 100 and 64 <= b <= 127:  # CGNAT 100.64.0.0/10
        return True
    if a == 0:
        return True
    return False


def _is_internal_hostname(host: str) -> bool:
    """True si el hostname parece resolver a infraestructura interna."""
    h = host.lower().rstrip(".")
    if not h:
        return False
    if any(h.endswith(suf) for suf in _INTERNAL_SUFFIXES):
        return True
    # Un solo label sin puntos (ej. "intranet", "servidor01").
    if "." not in h:
        return True
    return False


class Anonymizer:
    """Reemplaza IPs/hostnames/emails por marcadores neutros por request.

    Modos:
      - ``internal`` (default): reemplaza IPs privadas/loopback/link-local/CGNAT,
        hostnames de un solo label, hostnames con sufijo interno y **siempre**
        direcciones de email.
      - ``strict``: además reemplaza **toda** IP y todo hostname/SAN.
      - ``off``: no anonimiza (solo desarrollo; se loguea warning al arrancar).

    Los marcadores son estables dentro de una request: el mismo valor siempre
    recibe el mismo marcador (HOST_1, IP_1, EMAIL_1).
    """

    def __init__(self, mode: str | None = None) -> None:
        self.mode = (mode or getattr(settings, "ai_anonymization", "internal")).lower()
        if self.mode not in {"internal", "strict", "off"}:
            self.mode = "internal"
        self._internal_domains = [
            d.lower().lstrip(".")
            for d in getattr(settings, "ai_internal_domains", [])
        ]
        self._map: dict[str, str] = {}
        self._host_n = 0
        self._ip_n = 0
        self._email_n = 0

    # -- helpers de marcador ------------------------------------------------
    def _host_marker(self, value: str) -> str:
        key = f"host::{value.lower()}"
        if key not in self._map:
            self._host_n += 1
            self._map[key] = f"HOST_{self._host_n}"
        return self._map[key]

    def _ip_marker(self, value: str) -> str:
        key = f"ip::{value}"
        if key not in self._map:
            self._ip_n += 1
            self._map[key] = f"IP_{self._ip_n}"
        return self._map[key]

    def _email_marker(self, value: str) -> str:
        key = f"email::{value.lower()}"
        if key not in self._map:
            self._email_n += 1
            self._map[key] = f"EMAIL_{self._email_n}"
        return self._map[key]

    # -- política por modo --------------------------------------------------
    def _should_anonymize_ip(self, ip: str) -> bool:
        if self.mode == "off":
            return False
        if self.mode == "strict":
            return True
        return _is_private_ipv4(ip)

    def _should_anonymize_host(self, host: str) -> bool:
        if self.mode == "off":
            return False
        if self.mode == "strict":
            return True
        h = host.lower().rstrip(".")
        if any(h == d or h.endswith("." + d) for d in self._internal_domains):
            return True
        return _is_internal_hostname(h)

    # -- API pública --------------------------------------------------------
    def anonymize_host(self, host: str) -> str:
        if not host:
            return host
        if self._should_anonymize_host(host):
            return self._host_marker(host)
        return host

    def anonymize_ip(self, ip: str) -> str:
        if not ip:
            return ip
        if self._should_anonymize_ip(ip):
            return self._ip_marker(ip)
        return ip

    def anonymize_email(self, email: str) -> str:
        """Los emails siempre se anonimizan en modo internal/strict."""
        if not email or self.mode == "off":
            return email
        return self._email_marker(email)

    def anonymize_text(self, text: str) -> str:
        """Aplica redacción + sustitución de emails/IPs/hosts en un texto libre."""
        if not text or self.mode == "off":
            return text
        t = text
        # Emails primero (para no capturar dominios sueltos como host).
        import re as _re
        t = _re.sub(
            r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            lambda m: self._email_marker(m.group(0)),
            t,
        )
        t = _re.sub(
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            lambda m: self._ip_marker(m.group(0)) if self._should_anonymize_ip(m.group(0)) else m.group(0),
            t,
        )
        return t

    def filter_cert_component(self, name: str, value: str) -> str | None:
        """Filtra un componente de subject/issuer del certificado.

        Devuelve ``None`` si el componente no debe enviarse al LLM (O, OU, L,
        ST, C, emailAddress, serialNumber), el nombre público de la CA si
        coincide con una CA conocida, o un indicador "presente"/"ausente".
        """
        if not name or not value:
            return None
        if name.strip().lower() in _FORBIDDEN_CERT_COMPONENTS:
            return None
        if name.strip().lower() in {"issuer", "ca", "issuer_commonname"}:
            if value.strip().lower() in _PUBLIC_CA_NAMES:
                return value.strip()
            return "presente"
        return "presente"

    def restore(self, text: str) -> str:
        """Reemplaza los marcadores por los valores reales (en el servidor).

        Se ejecuta después de ``sanitize_llm_output``. Un marcador desconocido
        en la respuesta se deja como está.
        """
        if not text or not self._map:
            return text
        # Ordenar por longitud descendente para evitar reemplazos parciales.
        for original_key, marker in sorted(
            self._map.items(), key=lambda kv: len(kv[1]), reverse=True
        ):
            original = original_key.split("::", 1)[1]
            text = text.replace(marker, original)
        return text
