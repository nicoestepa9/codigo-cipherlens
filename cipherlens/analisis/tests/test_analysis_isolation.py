"""Aislamiento del nucleo puro (Parte 5.1): el agente no debe arrastrar web/DB.

Importar ``tls_analyzer.analysis`` (base del agente on-premise) en un proceso
limpio no debe cargar ``fastapi`` ni ``sqlalchemy``.
"""

import subprocess
import sys
import textwrap


def test_core_import_does_not_load_web_or_db():
    code = textwrap.dedent(
        """
        import sys
        import tls_analyzer.analysis  # noqa: F401
        import tls_analyzer.agent  # noqa: F401
        import tls_analyzer.agent.runner  # noqa: F401
        import tls_analyzer.agent.client  # noqa: F401
        forbidden = [m for m in ("fastapi", "sqlalchemy") if m in sys.modules]
        assert not forbidden, "modulos de plataforma cargados: %s" % forbidden
        print("ISOLATED_OK")
        """
    )
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True
    )
    assert result.returncode == 0, result.stderr
    assert "ISOLATED_OK" in result.stdout


def test_analysis_result_roundtrip():
    from tls_analyzer.analysis import SCHEMA_VERSION, AnalysisResult

    ar = AnalysisResult(
        host="h.test",
        port=443,
        score=42,
        status="completed",
        started_at="2024-01-01T00:00:00+00:00",
        duration_ms=12,
        findings=[{"ruleId": "PROTO-01"}],
        handshake={"negotiated_protocol": "TLSv1.3"},
    )
    payload = ar.to_dict()
    assert payload["schemaVersion"] == SCHEMA_VERSION
    restored = AnalysisResult.from_dict(payload)
    assert restored.host == "h.test"
    assert restored.score == 42
    assert restored.findings == [{"ruleId": "PROTO-01"}]
    assert restored.handshake == {"negotiated_protocol": "TLSv1.3"}
