"""External audit must preserve labels, reject changed sources and never fit."""
import hashlib
import json

import pytest

from tls_analyzer.crypto_ml.external import OWASP_REVISION, evaluate_external, expected_rows
from tls_analyzer.crypto_ml.inference import MODEL_PATH


@pytest.fixture
def external_source(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    entries = [
        ("BenchmarkTest00001", "crypto", "true", 'class A { Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding"); }'),
        ("BenchmarkTest00002", "crypto", "false", 'class A { Cipher c = Cipher.getInstance("AES/GCM/NoPadding"); }'),
        ("BenchmarkTest00003", "crypto", "true", 'class A { Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding"); }'),
        ("BenchmarkTest00004", "weakrand", "false", "class Empty {}"),
    ]
    (source / "expectedresults-1.2.csv").write_text("# header\n" + "".join(f"{name},{category},{label},327\n" for name, category, label, _ in entries), encoding="utf-8")
    (source / "LICENSE").write_text("Test fixture only", encoding="utf-8")
    files = []
    for name, _, _, text in entries:
        data = text.encode()
        (source / (name + ".java")).write_bytes(data)
        files.append({"id": name, "sha256": hashlib.sha256(data).hexdigest()})
    (source / "download-manifest.json").write_text(json.dumps({"revision": OWASP_REVISION, "source": "fixture", "files": files}), encoding="utf-8")
    return source


def test_external_evaluation_never_fits_and_records_duplicates_and_abstentions(external_source, tmp_path, monkeypatch):
    linear = pytest.importorskip("sklearn.linear_model")
    def forbidden(*args, **kwargs):
        raise AssertionError("External evaluation must never train")
    monkeypatch.setattr(linear.LogisticRegression, "fit", forbidden)
    before = MODEL_PATH.read_bytes()
    evaluate_external(external_source, tmp_path / "report")
    report = json.loads((tmp_path / "report/report.json").read_text(encoding="utf-8"))
    assert report["trainingPerformed"] is False
    assert report["thresholdChanged"] is False
    assert report["overall"]["size"] == 2
    assert len(report["abstentions"]) == 1
    assert report["coverage"] == pytest.approx(2 / 3)
    assert any(row["reason"] == "duplicate_normalized_source" for row in report["excluded"])
    assert MODEL_PATH.read_bytes() == before


def test_modified_external_source_is_rejected(external_source, tmp_path):
    pytest.importorskip("sklearn")
    (external_source / "BenchmarkTest00001.java").write_text("changed", encoding="utf-8")
    with pytest.raises(ValueError, match="hash mismatch"):
        evaluate_external(external_source, tmp_path / "report")


def test_unrelated_owasp_categories_are_not_imported(external_source):
    with (external_source / "expectedresults-1.2.csv").open("a", encoding="utf-8") as handle:
        handle.write("BenchmarkTest00005,sqli,true,89\n")
    assert len(expected_rows(external_source)) == 4
