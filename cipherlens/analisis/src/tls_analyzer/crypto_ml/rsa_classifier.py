"""Supervised RSA size policy reproduction; portable inference and provenance.

This intentionally simple experiment must not be sold as outperforming rules.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from functools import lru_cache
from pathlib import Path

MODEL_PATH = Path(__file__).with_name("assets") / "rsa_policy_model.json"


@lru_cache(maxsize=1)
def load_rsa_model() -> dict:
    return json.loads(MODEL_PATH.read_text(encoding="utf-8"))


def predict_size(bits: int, artifact: dict | None = None) -> float | None:
    artifact = artifact if artifact is not None else load_rsa_model()
    low, high = artifact["domain"]
    if isinstance(bits, bool) or not isinstance(bits, int) or not low <= bits <= high:
        return None
    node = 0
    while artifact["left"][node] != -1:
        node = artifact["left"][node] if bits <= artifact["threshold"][node] else artifact["right"][node]
    values = artifact["values"][node][0]
    return values[1] / sum(values)


def train(catalog_path: Path, output: Path) -> dict:
    import sklearn
    from sklearn.tree import DecisionTreeClassifier
    from sklearn.metrics import classification_report, confusion_matrix
    catalog_bytes = catalog_path.read_bytes()
    catalog = json.loads(catalog_bytes)
    sets = {key: catalog[key] for key in ("train", "validation", "test")}
    for a, b in (("train", "validation"), ("train", "test"), ("validation", "test")):
        if {row[0] for row in sets[a]} & {row[0] for row in sets[b]}:
            raise ValueError("RSA parameter values must not cross splits")
    if any({label for _, label in rows} != {0, 1} for rows in sets.values()):
        raise ValueError("Each split must contain both labels")
    model = DecisionTreeClassifier(max_depth=1, random_state=42)
    model.fit([[bits] for bits, _ in sets["train"]], [label for _, label in sets["train"]])
    tree = model.tree_
    version = hashlib.sha256(catalog_bytes).hexdigest()[:16]
    artifact = {"version": version, "kind": "supervised_rsa_size_policy", "catalogSha256": hashlib.sha256(catalog_bytes).hexdigest(), "domain": catalog["domain"], "policyMinimum": catalog["policyMinimum"], "left": tree.children_left.tolist(), "right": tree.children_right.tolist(), "threshold": tree.threshold.tolist(), "values": tree.value.tolist(), "provenance": catalog["provenance"], "limitations": catalog["limitations"]}
    report = {"version": version, "sklearnVersion": sklearn.__version__, "provenance": catalog["provenance"], "method": "Depth-one decision tree; train only, fixed seed 42, no hyperparameter search", "learnedThreshold": float(tree.threshold[0]), "limitations": catalog["limitations"], "metrics": {}}
    output.mkdir(parents=True, exist_ok=True)
    for name, rows in sets.items():
        actual = [label for _, label in rows]
        predicted = model.predict([[bits] for bits, _ in rows]).tolist()
        for (bits, _), expected in zip(rows, predicted):
            if int(predict_size(bits, artifact) >= 0.5) != expected:
                raise ValueError("Portable RSA inference differs from sklearn")
        report["metrics"][name] = {"size": len(rows), "classificationReport": classification_report(actual, predicted, labels=[0, 1], output_dict=True, zero_division=0), "confusionMatrix": confusion_matrix(actual, predicted, labels=[0, 1]).tolist(), "ruleReference": classification_report(actual, [int(bits < catalog["policyMinimum"]) for bits, _ in rows], labels=[0, 1], output_dict=True, zero_division=0), "predictions": [{"bits": bits, "actual": label, "predicted": int(p)} for (bits, label), p in zip(rows, predicted)]}
        (output / f"{name}.jsonl").write_text("".join(json.dumps({"bits": bits, "label": label, "provenance": "project_authored_policy_example"}) + "\n" for bits, label in rows), encoding="utf-8")
    (output / "model.json").write_text(json.dumps(artifact, indent=2), encoding="utf-8")
    (output / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return {"version": version, "learnedThreshold": report["learnedThreshold"], "counts": {name: len(rows) for name, rows in sets.items()}, "testMacroF1": report["metrics"]["test"]["classificationReport"]["macro avg"]["f1-score"], "provenance": catalog["provenance"]}


def evaluate(catalog_path: Path, output: Path) -> dict:
    """Recalculate frozen test metrics without importing or fitting an estimator."""
    from sklearn.metrics import classification_report, confusion_matrix
    catalog_bytes = catalog_path.read_bytes()
    catalog = json.loads(catalog_bytes)
    artifact = json.loads((output / "model.json").read_text(encoding="utf-8"))
    if artifact["catalogSha256"] != hashlib.sha256(catalog_bytes).hexdigest():
        raise ValueError("Catalog differs from the trained experiment")
    rows = [json.loads(line) for line in (output / "test.jsonl").read_text(encoding="utf-8").splitlines()]
    if [[s["bits"], s["label"]] for s in rows] != catalog["test"]:
        raise ValueError("Frozen test values/labels have changed")
    actual, predicted = [s["label"] for s in rows], []
    for sample in rows:
        score = predict_size(sample["bits"], artifact)
        if score is None:
            raise ValueError("Test example outside declared domain")
        predicted.append(int(score >= 0.5))
    report = {"trainingPerformed": False, "size": len(rows), "provenance": artifact["provenance"], "classificationReport": classification_report(actual, predicted, labels=[0, 1], output_dict=True, zero_division=0), "confusionMatrix": confusion_matrix(actual, predicted, labels=[0, 1]).tolist()}
    (output / "evaluation.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("catalog", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--evaluate-only", action="store_true")
    args = parser.parse_args()
    print(json.dumps((evaluate if args.evaluate_only else train)(args.catalog, args.output), indent=2))
