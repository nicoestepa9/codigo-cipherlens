"""Tests del proveedor de recomendaciones AI (F6)."""

import os

from tls_analyzer.ai_recommendations import (
    AnthropicProvider,
    GeminiProvider,
    TemplateProvider,
    _build_prompt,
    generate_recommendation,
    get_client,
)


def test_default_client_is_template():
    client = get_client()
    assert isinstance(client, TemplateProvider)


def test_generate_recommendation_returns_template_source():
    text, source = generate_recommendation(40, [], "vuln.example.com")
    assert source == "template"
    assert "vuln.example.com" in text


def test_template_low_score_mentions_actions():
    provider = TemplateProvider()
    text = provider.generate(score=40, findings=[
        {"title": "TLS 1.0 habilitado", "severity": "high",
         "recommendation": "Deshabilitar TLS 1.0.", "evaluable": True},
    ], host="host.example.com")
    assert "host.example.com" in text
    assert "40" in text
    assert "TLS 1.0 habilitado" in text
    assert "Deshabilitar TLS 1.0" in text


def test_template_high_score_no_alarm():
    provider = TemplateProvider()
    text = provider.generate(score=90, findings=[
        {"title": "AES aceptable", "severity": "info",
         "recommendation": "ninguna accion requerida", "evaluable": True},
    ], host="host.example.com")
    assert "90" in text
    assert "0 hallazgos que requieren acci" in text
    assert "AES aceptable" in text


def test_anthropic_provider_builds_prompt():
    prompt = _build_prompt(70, [
        {"title": "Weak cipher", "severity": "high", "recommendation": "disable", "evaluable": True},
        {"title": "Not evaluable", "severity": "info", "evaluable": False},
    ], "api.example.com")
    assert "api.example.com" in prompt
    assert "Weak cipher" in prompt
    assert "Not evaluable" not in prompt


def test_gemini_provider_uses_generate_content_url():
    client = get_client()
    assert isinstance(client, TemplateProvider)
    provider = GeminiProvider.__new__(GeminiProvider)
    provider.api_key = "k"
    provider.model = "gemini-2.0-flash"
    assert provider._API_BASE == "https://generativelanguage.googleapis.com/v1beta/models"


def test_get_client_returns_gemini_when_configured():
    import tls_analyzer.ai_recommendations as mod
    original = mod.settings.ai_provider
    mod.settings.ai_provider = "gemini"
    mod.settings.ai_api_key = "test-key"
    try:
        client = get_client()
        assert isinstance(client, GeminiProvider)
    finally:
        mod.settings.ai_provider = original
        mod.settings.ai_api_key = ""


def _gemini_with_model_chain(models):
    import tls_analyzer.ai_recommendations as mod
    original_models = os.getenv("AI_MODELS")
    original_model = mod.settings.ai_model
    try:
        os.environ["AI_MODELS"] = models
        mod.settings.ai_model = None
        return GeminiProvider()
    finally:
        if original_models is None:
            os.environ.pop("AI_MODELS", None)
        else:
            os.environ["AI_MODELS"] = original_models
        mod.settings.ai_model = original_model


def test_gemini_model_chain_respects_env():
    import os
    provider = _gemini_with_model_chain("gemini-a, gemini-b ,gemini-c")
    assert provider.models == ["gemini-a", "gemini-b", "gemini-c"]


def test_gemini_model_chain_defaults_primary_first():
    import os
    import tls_analyzer.ai_recommendations as mod
    original_model = mod.settings.ai_model
    original_models = os.getenv("AI_MODELS")
    try:
        os.environ.pop("AI_MODELS", None)
        mod.settings.ai_model = "gemini-mine"
        provider = GeminiProvider()
        assert provider.models[0] == "gemini-mine"
        assert "gemini-3.6-flash" in provider.models
        assert len(provider.models) > 1
    finally:
        if original_models is None:
            os.environ.pop("AI_MODELS", None)
        else:
            os.environ["AI_MODELS"] = original_models
        mod.settings.ai_model = original_model


def test_gemini_cascades_to_next_model_on_failure():
    provider = _gemini_with_model_chain("gemini-fail,gemini-ok")
    calls = []

    def fake_try(client, model, url_base, headers, payload, max_retries, retry_base):
        calls.append(model)
        if model == "gemini-fail":
            raise RuntimeError("503 over capacity")
        return f"RESPONSE from {model}"

    provider._try_model = fake_try
    result = provider.generate(score=60, findings=[], host="h.example.com")
    assert calls == ["gemini-fail", "gemini-ok"]
    assert result == "RESPONSE from gemini-ok"


def test_gemini_raises_when_all_models_fail():
    provider = _gemini_with_model_chain("gemini-fail1,gemini-fail2")

    def fake_try(client, model, url_base, headers, payload, max_retries, retry_base):
        raise RuntimeError(f"503: {model}")

    provider._try_model = fake_try
    try:
        provider.generate(score=40, findings=[], host="h.example.com")
        raise AssertionError("expected RuntimeError when all models fail")
    except RuntimeError as exc:
        assert "gemini-fail2" in str(exc)

