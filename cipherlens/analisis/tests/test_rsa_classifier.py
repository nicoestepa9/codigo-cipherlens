"""Separate learned policy reproduction from complete cryptographic security."""
import json
from pathlib import Path

import pytest

from tls_analyzer.crypto_ml.rsa_classifier import load_rsa_model, predict_size


def test_catalog_sizes_do_not_cross_train_validation_test():
    root = Path(__file__).parents[1] / "data/crypto_ml/rsa-policy-v1"
    catalog = json.loads((root / "catalog.json").read_text())
    assert "Project-authored" in catalog["provenance"]
    for left, right in (("train", "validation"), ("train", "test"), ("validation", "test")):
        assert not {r[0] for r in catalog[left]} & {r[0] for r in catalog[right]}
    for bits, expected in catalog["test"]:
        assert int(predict_size(bits) >= 0.5) == expected


@pytest.mark.parametrize("bits,expected", [(2047, 1), (2048, 0), (2304, 0), (2816, 0), (4096, 0)])
def test_policy_boundaries_and_unseen_sizes(bits, expected):
    assert int(predict_size(bits) >= 0.5) == expected


@pytest.mark.parametrize("bits", [None, True, 1, 511, 16385, 2048.5, "1024"])
def test_unsupported_values_abstain(bits):
    assert predict_size(bits) is None


def test_evaluation_never_fits_a_model(tmp_path, monkeypatch):
    linear = pytest.importorskip("sklearn.tree")
    from tls_analyzer.crypto_ml.rsa_classifier import train, evaluate
    catalog = Path(__file__).parents[1] / "data/crypto_ml/rsa-policy-v1/catalog.json"
    train(catalog, tmp_path)
    def forbidden(*args, **kwargs):
        raise AssertionError("Evaluation cannot fit a model")
    monkeypatch.setattr(linear.DecisionTreeClassifier, "fit", forbidden)
    before = (tmp_path / "model.json").read_bytes()
    result = evaluate(catalog, tmp_path)
    assert result["trainingPerformed"] is False
    assert (tmp_path / "model.json").read_bytes() == before
