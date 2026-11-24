"""Meaningful checks of holdout isolation, portable inference and API bounds."""
import json
from pathlib import Path

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from tls_analyzer.crypto_ml.experiment import normalize
from tls_analyzer.crypto_ml.inference import MODEL_PATH, analyze_java, load_model, probability
from tls_analyzer.api.access_control import authorize_write
from tls_analyzer.api.deps import AuthContext, require_auth
from tls_analyzer.api.routers.crypto_ml import router


def test_normalization_preserves_strings_but_removes_label_leaks():
    source = '''package org.cryptoapi.bench.brokencrypto;
    // insecure example
    class InsecureExample { void bad() {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        String url = "https://example.com/path";
    }}'''
    clean = normalize(source)
    assert "brokencrypto" not in clean
    assert "InsecureExample" not in clean
    assert "insecure example" not in clean
    assert '"AES/ECB/PKCS5Padding"' in clean
    assert '"https://example.com/path"' in clean
    renamed = source.replace("InsecureExample", "SafeExample").replace("bad()", "good()")
    assert normalize(renamed) == clean
    assert normalize(source, skeleton=True) == normalize(source.replace("AES/ECB/PKCS5Padding", "AES/GCM/NoPadding"), skeleton=True)


def test_frozen_train_and_test_are_disjoint():
    root = MODEL_PATH.parent
    train = [json.loads(line) for line in (root / "train.jsonl").read_text(encoding="utf-8").splitlines()]
    test = [json.loads(line) for line in (root / "test.jsonl").read_text(encoding="utf-8").splitlines()]
    for field in ("id", "group", "sha256"):
        assert not {s[field] for s in train} & {s[field] for s in test}
    assert {s["label"] for s in train} == {0, 1}
    assert {s["label"] for s in test} == {0, 1}
    report = load_model()["report"]
    assert report["train"]["size"] == len(train)
    assert report["test"]["size"] == len(test)
    assert report["testUsedForTuning"] is False
    assert sum(sum(row) for row in report["test"]["metrics"]["confusionMatrix"]) == len(test)


def test_portable_predictions_match_frozen_test_scores():
    model = load_model()
    rows = {s["id"]: s for s in (json.loads(line) for line in (MODEL_PATH.parent / "test.jsonl").read_text(encoding="utf-8").splitlines())}
    for item in model["report"]["test"]["predictions"]:
        assert probability(rows[item["id"]]["text"], model) == pytest.approx(item["score"], abs=1e-10)


def test_evaluation_does_not_train_and_matches_recorded_metrics(tmp_path, monkeypatch):
    sklearn = pytest.importorskip("sklearn.linear_model")
    from tls_analyzer.crypto_ml.experiment import evaluate
    def forbidden(*args, **kwargs):
        raise AssertionError("Evaluation must never train")
    monkeypatch.setattr(sklearn.LogisticRegression, "fit", forbidden)
    result = evaluate(MODEL_PATH.parent, tmp_path)
    assert result["trainingPerformed"] is False
    assert result["confusionMatrix"] == load_model()["report"]["test"]["metrics"]["confusionMatrix"]
    assert (tmp_path / "metrics.csv").is_file()


def test_unsupported_source_abstains_and_paths_do_not_leak():
    result = analyze_java("class Example { int x = 1; }", "C:\\private\\Example.java")
    assert result["status"] == "not_evaluable"
    assert result["misuseScore"] is None
    assert result["filename"] == "Example.java"
    assert "private" not in json.dumps(result)
    assert analyze_java('// Cipher.getInstance("AES");\nclass A {}')["status"] == "not_evaluable"


@pytest.mark.parametrize("source,filename", [(" ", "A.java"), ("class A{}", "A.py"), ("á" * 50001, "A.java"), ("\0", "A.java")], ids=["blank", "extension", "utf8-size", "nul"])
def test_invalid_inputs_are_rejected(source, filename):
    with pytest.raises(ValueError):
        analyze_java(source, filename)


def client_for(role):
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[require_auth] = lambda: AuthContext(user_id="test", role=role, actor_type="user", organization_id=1)
    return TestClient(app)


def test_api_role_policy_and_validation():
    payload = {"filename": "A.java", "source": 'class A { Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding"); }'}
    for role in ("viewer", "agent", "operator"):
        assert client_for(role).post("/api/crypto-ml/analyze", json=payload).status_code == 403
        with pytest.raises(HTTPException):
            authorize_write(role, "POST", "/api/crypto-ml/analyze")
    for role in ("user", "lead", "admin"):
        authorize_write(role, "POST", "/api/crypto-ml/analyze")
        response = client_for(role).post("/api/crypto-ml/analyze", json=payload)
        assert response.status_code == 200
        assert response.json()["status"] in {"possible_misuse", "no_indication", "needs_review", "not_evaluable"}
        assert "source" not in response.json()
    assert client_for("user").post("/api/crypto-ml/analyze", json={**payload, "source": "x" * 100001}).status_code == 422
    assert client_for("user").post("/api/crypto-ml/analyze", json={**payload, "filename": "A.exe"}).status_code == 422


def test_missing_model_is_service_unavailable(monkeypatch):
    from tls_analyzer.crypto_ml import review
    review.model.cache_clear()
    monkeypatch.setattr(review, "MODEL_PATH", Path("nonexistent-model.json"))
    try:
        response = client_for("user").post("/api/crypto-ml/analyze", json={"source": 'Cipher.getInstance("AES");'})
        assert response.status_code == 503
    finally:
        review.model.cache_clear()
