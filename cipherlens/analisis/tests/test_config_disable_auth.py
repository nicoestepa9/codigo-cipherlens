"""La app no debe arrancar con DISABLE_API_AUTH=true fuera de ENV=dev."""

from __future__ import annotations

import os
import subprocess
import sys


def test_disable_api_auth_rejected_outside_dev(tmp_path):
    env = os.environ.copy()
    env["ENV"] = "production"
    env["DISABLE_API_AUTH"] = "true"
    env.pop("JWT_SECRET", None)
    code = (
        "from tls_analyzer.api.config import Settings\n"
        "try:\n"
        "    Settings()\n"
        "    print('BAD')\n"
        "    raise SystemExit(1)\n"
        "except SystemExit as e:\n"
        "    if e.code == 0:\n"
        "        raise\n"
        "    raise\n"
    )
    proc = subprocess.run(
        [sys.executable, "-c", code],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
    )
    assert proc.returncode != 0
    assert "DISABLE_API_AUTH" in proc.stderr or "DISABLE_API_AUTH" in proc.stdout
