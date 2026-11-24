"""Estado local del agente (secreto, mapeo de seudonimos, marcas de tiempo).

Todo vive en un directorio local del host donde corre el agente y nunca se
envia a la plataforma (Parte 5.6). Por defecto ``~/.cryptoguard-agent`` y se
puede cambiar con ``CRYPTOGUARD_AGENT_STATE_DIR``.
"""

from __future__ import annotations

import json
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path


def state_dir() -> Path:
    override = os.getenv("CRYPTOGUARD_AGENT_STATE_DIR")
    base = Path(override) if override else Path.home() / ".cryptoguard-agent"
    base.mkdir(parents=True, exist_ok=True)
    return base


def _read_json(path: Path, default):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return default


def _write_json(path: Path, data) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def ensure_secret() -> bytes:
    """Secreto local del agente (HMAC para seudonimos). Se genera una vez."""
    path = state_dir() / "secret"
    if path.exists():
        return bytes.fromhex(path.read_text(encoding="utf-8").strip())
    secret = secrets.token_bytes(32)
    path.write_text(secret.hex(), encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return secret


def load_mapping() -> dict[str, str]:
    """Mapeo seudonimo -> valor real (solo local)."""
    return _read_json(state_dir() / "mapping.json", {})


def save_mapping(mapping: dict[str, str]) -> None:
    _write_json(state_dir() / "mapping.json", mapping)


def export_mapping_csv(out_path: str) -> int:
    """Escribe el mapeo como CSV (pseudonym,real). Devuelve la cantidad."""
    mapping = load_mapping()
    lines = ["pseudonym,real"]
    for pseudo, real in sorted(mapping.items()):
        lines.append(f"{pseudo},{real}")
    Path(out_path).write_text("\n".join(lines) + "\n", encoding="utf-8")
    return len(mapping)


def resolve_pseudonym(pseudo: str) -> str | None:
    return load_mapping().get(pseudo)


def load_state() -> dict:
    return _read_json(state_dir() / "state.json", {})


def save_state(state: dict) -> None:
    _write_json(state_dir() / "state.json", state)


def mark_run(key: str, when: datetime | None = None) -> None:
    st = load_state()
    st[key] = (when or datetime.now(timezone.utc)).isoformat()
    save_state(st)


def last_run(key: str) -> datetime | None:
    raw = load_state().get(key)
    if not raw:
        return None
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt
