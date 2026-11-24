"""LLM Safety & Prompt Injection Hardening (Parte 4.3).

Capa 1: saneado, delimitado con nonce aleatorio por request, detección de
intentos de prompt injection y truncado. Todo valor no confiable (del host)
se envuelve en bloque delimitado.

El daño máximo ya está acotado: el LLM no tiene herramientas ni ejecuta
acciones; solo devuelve texto. Estas capas reducen riesgos de degradación,
falsificación/ocultamiento de hallazgos o fuga de datos por render.
"""

from __future__ import annotations

import re
import secrets
import unicodedata

from .api.config import settings

# Configuraciones (con defaults razonables)
AI_FIELD_MAX_LEN = int(getattr(settings, "ai_field_max_len", 200))


# Caracteres a considerar peligrosos para markdown estructural / delimitadores
_DELIM_PATTERNS = (
    r"<<", r">>", r"```",
    r"(?:^|\s)#",  # hash al inicio de linea o tras espacio
    r"\bsystem\s*:", r"\buser\s*:", r"\bassistant\s*:",  # role injection
    r"(?:^|\s)ignore\s+(?:previous|above|all)\b", r"(?:^|\s)forget\s+all\b",
    r"do\s+not\s+(?:follow|comply)\b", r"system\s*prompt\b",
)
_DELIM_RE = re.compile("|".join(_DELIM_PATTERNS), flags=re.IGNORECASE | re.MULTILINE)


def _untrusted(value: object, max_len: int = AI_FIELD_MAX_LEN) -> str:
    """Sanitiza un valor NO CONFIABLE proveniente del host.

    - Convierte a str
    - Elimina caracteres de control (excepto espacio/tab/nl? pero colapsamos)
    - Elimina caracteres Unicode de formato y bidireccionales
    - Neutraliza secuencias que imitan delimitadores/markdown estructural/role injection
    - Colapsa espacios en blanco
    - Trunca a max_len agregando '…' si truncó
    - Elimina cualquier nonce que pudiera colarse
    """
    if value is None:
        return ""
    s = str(value)

    # Eliminar chars Unicode de formato y bidi
    s2 = []
    for ch in s:
        cat = unicodedata.category(ch)
        if cat.startswith("Cf"):  # format
            continue
        if unicodedata.bidirectional(ch) in {"R", "AL", "RLE", "RLO", "PDF", "LRE", "LRO"}:
            # neutralizar bidi "espejado" más simple: reemplazar por espacio? o quitar
            # quitar para evitar override visual
            continue
        s2.append(ch)
    s = "".join(s2)

    # Eliminar caracteres de control (C0/C1)
    s = re.sub(r"[\x00-\x1f\x7f-\x9f]+", " ", s)

    # Neutralizar patrones de prompt injection / delimitadores/markdown
    s = _DELIM_RE.sub("[neutralizado]", s)

    # Colapsar espacios en blanco
    s = re.sub(r"\s+", " ", s).strip()

    # Truncar
    if len(s) > max_len:
        s = s[: max_len - 1] + "…"
    return s


def sanitize_untrusted_value(value: object, max_len: int = AI_FIELD_MAX_LEN) -> str:
    """Sanea un valor no confiable antes de persistirlo o enviarlo al LLM."""
    return _untrusted(value, max_len=max_len)


def make_untrusted_block(value: object, max_len: int = AI_FIELD_MAX_LEN) -> str:
    """Genera bloque delimitado con nonce aleatorio para valor no confiable."""
    nonce = secrets.token_urlsafe(12)
    sanitized = _untrusted(value, max_len=max_len)
    # Asegurar que el nonce no aparezca
    sanitized = sanitized.replace(nonce, "[x]")
    return f"<<DATO_NO_CONFIABLE_{nonce} {sanitized} DATO_NO_CONFIABLE_{nonce}>>"


def is_prompt_injection_attempt(text: str) -> bool:
    """Detecta intentos obvios de prompt injection."""
    if not text:
        return False
    t = text.lower()
    red_flags = [
        "ignore previous",
        "ignore all previous",
        "ignore above",
        "forget all",
        "you are now",
        "system prompt",
        "developer mode",
        "jailbreak",
        "act as system",
    ]
    return any(rf in t for rf in red_flags)


# ---------------------------------------------------------------------------
# Capa 3: validación y saneamiento de la salida (se aplica a TODOS los
# proveedores, incluido TemplateProvider).
# ---------------------------------------------------------------------------

AI_OUTPUT_MAX_CHARS = int(getattr(settings, "ai_output_max_chars", 30000))
AI_LINK_ALLOWLIST: list[str] = list(getattr(settings, "ai_link_allowlist", []))

# Etiquetas HTML y comentarios que deben eliminarse/escaparse de la salida.
_HTML_TAG_RE = re.compile(r"</?[a-zA-Z][^>]*>")
_HTML_COMMENT_RE = re.compile(r"<!--.*?-->", flags=re.DOTALL)

# Imagen Markdown: ![alt](url)
_MD_IMAGE_RE = re.compile(r"!\[[^\]]*\]\([^)]*\)")

# Enlace Markdown: [texto](url)
_MD_LINK_RE = re.compile(r"\[([^\]]*)\]\(([^)\s]+)\)")


def _link_allowed(url: str) -> bool:
    """True si la URL apunta a un host dentro de la allowlist."""
    u = url.strip().lower()
    if not u.startswith("https://"):
        return False
    hostpart = u[len("https://"):].split("/", 1)[0].split("?", 1)[0]
    for allowed in AI_LINK_ALLOWLIST:
        a = allowed.strip().lower()
        if not a:
            continue
        if hostpart == a or hostpart.endswith("." + a):
            return True
    return False


def sanitize_llm_output(text: str, max_chars: int | None = None) -> str:
    """Sanea la salida del LLM (o del TemplateProvider) antes de persistirla.

    - Largo máximo ``AI_OUTPUT_MAX_CHARS``; si se excede, se trunca y se marca.
    - Elimina/escapa etiquetas HTML y comentarios.
    - Elimina imágenes Markdown (posible vector de exfiltración).
    - Enlaces: solo ``https://`` hacia la allowlist; el resto se deja como
      texto sin enlace.
    """
    if not text:
        return ""
    limit = max_chars or AI_OUTPUT_MAX_CHARS

    t = text
    # Imágenes Markdown primero (antes de tocar los enlaces).
    t = _MD_IMAGE_RE.sub("", t)

    # Enlaces: permitir solo allowlist https; el resto se vuelve texto plano.
    def _link_repl(m: re.Match) -> str:
        label, url = m.group(1), m.group(2)
        if _link_allowed(url):
            return m.group(0)
        return label

    t = _MD_LINK_RE.sub(_link_repl, t)

    # HTML: eliminar etiquetas y comentarios.
    t = _HTML_COMMENT_RE.sub("", t)
    t = _HTML_TAG_RE.sub("", t)

    # Escapar cualquier '&' residual que imite una entidad (defensa en profundidad).
    t = re.sub(r"&(?!(?:[a-zA-Z][a-zA-Z0-9]{1,8});)", "&amp;", t)

    if len(t) > limit:
        t = t[: limit - 1] + "…"
        t += "\n\n> [Salida truncada por límite de longitud.]"
    return t.strip()


# ---------------------------------------------------------------------------
# Capa 4: cobertura de hallazgos -- el LLM no puede ocultar problemas.
# ---------------------------------------------------------------------------

def _coverage_section_text(findings: list[dict]) -> str:
    """Genera la sección determinística para hallazgos omitidos."""
    lines = [
        "## Hallazgos adicionales detectados por el motor de reglas",
        "",
        "Los siguientes hallazgos críticos/altos no fueron cubiertos por la "
        "redacción del modelo y se anexan de forma determinística para no "
        "ocultar vulnerabilidades:",
        "",
    ]
    for f in findings:
        sev = (f.get("severity") or "info").upper()
        title = f.get("title") or "(sin título)"
        rid = f.get("ruleId") or f.get("id") or ""
        rec = f.get("recommendation") or ""
        lines.append(f"- **[{sev}] {title}** (regla: {rid})")
        if rec:
            lines.append(f"  - Remediación: {rec}")
    lines.append("")
    return "\n".join(lines)


def ensure_coverage(text: str, findings: list[dict]) -> tuple[str, bool]:
    """Garantiza que cada hallazgo accionable crítico/alto aparezca en el texto.

    Para cada finding ``critical`` o ``high``, verifica que su ``rule_id`` o su
    título aparezca en el texto. Si falta alguno, se anexa al final una sección
    determinística. Devuelve ``(texto_final, hubo_omisiones)``.
    """
    if not findings:
        return text, False

    low = (text or "").lower()
    missing: list[dict] = []
    for f in findings:
        if not f.get("evaluable", True):
            continue
        if (f.get("severity") or "").lower() not in {"critical", "high"}:
            continue
        rid = (f.get("ruleId") or f.get("id") or "").strip()
        title = (f.get("title") or "").strip()
        found = False
        if rid and rid.lower() in low:
            found = True
        if title and title.lower() in low:
            found = True
        if not found:
            missing.append(f)

    if not missing:
        return text, False

    section = _coverage_section_text(missing)
    base = (text or "").strip()
    merged = f"{base}\n\n{section}".strip()
    return merged, True
