"""Configuracion: ENV seguro por defecto y DISABLE_API_AUTH solo en dev."""

from __future__ import annotations

import os
import subprocess
import sys


def _clean_env() -> dict[str, str]:
    env = os.environ.copy()
    env.pop("ENV", None)
    env.pop("DISABLE_API_AUTH", None)
    return env


def _run(code: str, env_overrides: dict[str, str]) -> subprocess.CompletedProcess[str]:
    env = _clean_env()
    env.update(env_overrides)
    return subprocess.run(
        [sys.executable, "-c", code],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )


def test_env_default_is_not_dev():
    proc = _run(
        "from tls_analyzer.api.config import settings; print(settings.env)",
        {"JWT_SECRET": "x" * 40},
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "production"


def test_disable_api_auth_rejected_outside_dev():
    proc = _run(
        "import tls_analyzer.api.config",
        {"ENV": "production", "DISABLE_API_AUTH": "true", "JWT_SECRET": "x" * 40},
    )
    assert proc.returncode != 0
    assert "DISABLE_API_AUTH" in proc.stderr


def test_disable_api_auth_allowed_in_dev():
    proc = _run(
        "import tls_analyzer.api.config",
        {"ENV": "dev", "DISABLE_API_AUTH": "true"},
    )
    assert proc.returncode == 0, proc.stderr
    assert "organizacion por defecto" in proc.stderr
