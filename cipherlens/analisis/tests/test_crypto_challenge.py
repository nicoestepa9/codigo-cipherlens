"""Challenge bookkeeping and evaluation isolation, not forced accuracy targets."""
import json

import pytest


def test_challenge_does_not_train_and_keeps_abstentions_separate(tmp_path, monkeypatch):
    tree = pytest.importorskip("sklearn.tree")
    from tls_analyzer.crypto_ml.challenge import evaluate
    def forbidden(*args, **kwargs):
        raise AssertionError("Challenge evaluation cannot train")
    monkeypatch.setattr(tree.DecisionTreeClassifier, "fit", forbidden)
    evaluate(tmp_path)
    report = json.loads((tmp_path / "report.json").read_text())
    definitions = json.loads((tmp_path / "cases.json").read_text())
    assert report["caseCount"] == len(definitions)
    assert report["trainingPerformed"] is False
    assert report["thresholdsChanged"] is False
    metric = report["controlsCoveredCases"]
    assert metric["covered"] + metric["abstentions"] == metric["labelled"]
    assert sum(map(sum, metric["confusionMatrix"])) == metric["covered"]
    expected = {s["id"]: s["expected"] for s in definitions}
    assert all(row["actual"] == expected[row["id"]] for row in report["results"])
    assert len(report["unknownGroundTruthCases"]) == 2
    assert report["analysisCodeHashes"]
