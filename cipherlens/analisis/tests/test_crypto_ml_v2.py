"""V2 lexical observations and strict isolation, including representation clones."""
import json

from tls_analyzer.crypto_ml.context_v2 import extract_context
from tls_analyzer.crypto_ml.v2 import prepare, run
from tls_analyzer.crypto_ml.inference import MODEL_PATH


def test_context_preserves_literals_and_positions_without_claiming_a_defect():
    source = '''// Cipher.getInstance("DES");
class Demo {
  void create() {
    KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
    g.initialize(3072);
    System.out.println("Cipher.getInstance(\\"DES\\")");
  }
}'''
    context = extract_context(source)
    assert context["features"]["initialization_value"] == 3072
    assert context["features"]["factory_literal:RSA"] == 1
    assert "factory_literal:DES" not in context["features"]
    assert any(item["method"] == "initialize" and item["line"] == 5 for item in context["observations"])
    assert "defect" not in context


def test_semicolon_in_a_literal_does_not_split_the_statement():
    context = extract_context('class A { Cipher c = Cipher.getInstance("AES;not_a_delimiter"); }')
    assert context["features"]["factory_literal:AES;not_a_delimiter"] == 1


def test_representation_clones_are_grouped_and_insufficient_data_is_not_trained(tmp_path):
    initial = tmp_path / "initial.jsonl"
    owasp = tmp_path / "owasp.jsonl"
    records = []
    # Same observable crypto input despite different irrelevant string literals.
    for i in range(24):
        records.append({"id": str(i), "category": "brokencrypto", "label": i % 2, "group": "original-" + str(i), "text": f'class A {{ Cipher c = Cipher.getInstance("AES"); String unused = "unused{i}"; }}'})
    initial.write_text("".join(json.dumps(s) + "\n" for s in records), encoding="utf-8")
    owasp.write_text("", encoding="utf-8")
    output = tmp_path / "prepared"
    audit = prepare(initial, owasp, output)
    data = [json.loads(line) for line in (output / "dataset.jsonl").read_text().splitlines()]
    assert len({s["group"] for s in data}) <= 1
    before = MODEL_PATH.read_bytes()
    report = run(output / "dataset.jsonl", tmp_path / "experiment")
    assert report["deployed"] is False
    assert all(s["reason"] == "conflicting_labels_for_same_extracted_context" for s in audit["excluded"])
    assert report["tasks"] == {}
    assert MODEL_PATH.read_bytes() == before


def test_v2_cannot_overwrite_deployed_assets(tmp_path):
    import pytest
    with pytest.raises(ValueError, match="never overwrite"):
        run(tmp_path / "unused.jsonl", MODEL_PATH.parent)


def test_saved_strict_splits_have_no_shared_ids_groups_or_feature_patterns():
    from pathlib import Path
    folder = Path(__file__).parents[1] / "data/crypto_ml/v2-experiment-stratified/cipher_policy"
    partitions = {key: [json.loads(line) for line in (folder / f"{key}.jsonl").read_text(encoding="utf-8").splitlines()] for key in ("train", "validation", "test")}
    for left, right in (("train", "validation"), ("train", "test"), ("validation", "test")):
        for field in ("id", "group", "sha256"):
            assert not {s[field] for s in partitions[left]} & {s[field] for s in partitions[right]}
        assert not {json.dumps(s["features"], sort_keys=True) for s in partitions[left]} & {json.dumps(s["features"], sort_keys=True) for s in partitions[right]}
