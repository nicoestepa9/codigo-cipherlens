"""Train a narrowly scoped supervised classifier from upstream file labels.

Only one literal Cipher factory per source, outside conditional/loop branches.
No labels are generated from encryption rules. OWASP is development data.
"""
from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path

from .experiment import digest, normalize
from .inference import probability, load_model


def parameter_features(transformation: str) -> dict:
    parts = transformation.upper().split("/")
    return {"algorithm": parts[0], "mode": parts[1] if len(parts) > 1 else "UNSPECIFIED", "padding": parts[2] if len(parts) > 2 else "UNSPECIFIED", "explicit_parts": len(parts)}


def collect(initial: Path, owasp: Path, raw_initial: Path, raw_owasp: Path) -> tuple[list, list]:
    import javalang
    from javalang import tree as t
    rows, excluded = [], []
    branch_types = (t.IfStatement, t.ForStatement, t.WhileStatement, t.DoStatement, t.SwitchStatement, t.TernaryExpression)
    for dataset, origin in ((initial, "cryptoapi"), (owasp, "owasp")):
        for line in dataset.read_text(encoding="utf-8").splitlines():
            item = json.loads(line)
            if item["category"] not in ({"brokencrypto", "ecbcrypto"} if origin == "cryptoapi" else {"crypto"}):
                continue
            if origin == "cryptoapi":
                source = "\n".join((raw_initial / p).read_text(encoding="utf-8-sig") for p in item["sourcePaths"])
            else:
                source = (raw_owasp / (item["id"] + ".java")).read_text(encoding="utf-8-sig")
            if digest(normalize(source)) != item["sha256"]:
                raise ValueError("Source hash mismatch")
            try:
                unit = javalang.parse.parse(source)
            except (javalang.parser.JavaSyntaxError, javalang.tokenizer.LexerError):
                excluded.append({"id": item["id"], "reason": "parse_error"})
                continue
            calls = [(path, call) for path, call in unit.filter(t.MethodInvocation) if call.member == "getInstance" and call.qualifier.split(".")[-1] == "Cipher"]
            reason = None
            if len(calls) != 1:
                reason = "requires_one_cipher_factory"
            elif any(isinstance(parent, branch_types) for parent in calls[0][0]):
                reason = "conditional_factory"
            elif len(calls[0][1].arguments) != 1 or not isinstance(calls[0][1].arguments[0], t.Literal):
                reason = "nonliteral_or_provider_specific_factory"
            if reason:
                excluded.append({"id": origin + ":" + item["id"], "reason": reason})
                continue
            literal = calls[0][1].arguments[0].value
            if not literal.startswith('"') or "\\" in literal:
                excluded.append({"id": item["id"], "reason": "unsupported_literal"})
                continue
            transformation = literal[1:-1]
            rows.append({"id": origin + ":" + item["id"], "label": item["label"], "transformation": transformation, "features": parameter_features(transformation), "group": item["group"], "sourceSha256": item["sha256"], "v1Score": probability(item["text"], load_model()), "labelSource": "upstream spreadsheet" if origin == "cryptoapi" else "upstream expectedresults CSV"})
    # Deduplicate full source, not the intentionally shared measured attributes.
    seen = set()
    unique = []
    for row in rows:
        if row["sourceSha256"] in seen:
            excluded.append({"id": row["id"], "reason": "duplicate_source"})
            continue
        seen.add(row["sourceSha256"])
        unique.append(row)
    return unique, excluded


def train(rows: list, excluded: list, output: Path, model_output: Path) -> dict:
    from sklearn.feature_extraction import DictVectorizer
    from sklearn.tree import DecisionTreeClassifier
    from sklearn.model_selection import StratifiedGroupKFold
    from sklearn.metrics import classification_report, confusion_matrix
    import sklearn

    labels, groups = [s["label"] for s in rows], [s["group"] for s in rows]
    dev, test_idx = next(StratifiedGroupKFold(5, shuffle=True, random_state=42).split(rows, labels, groups))
    development = [rows[i] for i in dev]
    tr, va = next(StratifiedGroupKFold(4, shuffle=True, random_state=42).split(development, [s["label"] for s in development], [s["group"] for s in development]))
    splits = {"train": [development[i] for i in tr], "validation": [development[i] for i in va], "test": [rows[i] for i in test_idx]}
    if any({s["label"] for s in part} != {0, 1} for part in splits.values()):
        raise ValueError("Fixed split has insufficient class coverage; do not search favorable seeds")
    vectorizer = DictVectorizer(sparse=False)
    xtrain = vectorizer.fit_transform([s["features"] for s in splits["train"]])
    model = DecisionTreeClassifier(max_depth=4, class_weight="balanced", random_state=42)
    model.fit(xtrain, [s["label"] for s in splits["train"]])
    known = sorted({s["transformation"].upper() for s in splits["train"]})
    def metric(actual, predicted):
        return {"classificationReport": classification_report(actual, predicted, labels=[0, 1], output_dict=True, zero_division=0), "confusionMatrix": confusion_matrix(actual, predicted, labels=[0, 1]).tolist()}
    report = {"scope": "Known literal Cipher transformations, not RSA key sizes or whole-file security", "deployed": False, "sklearnVersion": sklearn.__version__, "split": "first stratified grouped 5-fold test + first grouped 4-fold validation, seed 42", "selectedRows": len(rows), "exclusions": excluded, "uniqueTransformations": len({s["transformation"] for s in rows}), "metrics": {}, "limitations": ["Observed academic sources, not untouched external validation", "Input attributes intentionally recur across source templates: this evaluates known-parameter recognition, not discovery of unseen algorithms", "Identical source groups never cross splits", "Abstains on transformations absent from train", "Dataset labels concern a target misuse, not full-file security", "No evidence of superiority to a complete static rule analyzer"]}
    for name, part in splits.items():
        covered = [s for s in part if s["transformation"].upper() in known]
        actual = [s["label"] for s in covered]
        prediction = model.predict(vectorizer.transform([s["features"] for s in covered])).tolist() if covered else []
        report["metrics"][name] = {"size": len(part), "covered": len(covered), "coverage": len(covered) / len(part), "uniqueTransformations": len({s["transformation"] for s in part}), **metric(actual, prediction), "v1SameCases": metric(actual, [int(s["v1Score"] >= 0.5) for s in covered]), "predictions": [{"id": s["id"], "actual": s["label"], "predicted": p} for s, p in zip(covered, prediction)]}
    tree = model.tree_
    artifact = {"schemaVersion": 3, "kind": "supervised_cipher_tree", "version": digest(json.dumps(rows, sort_keys=True))[:16], "knownTransformations": known, "features": vectorizer.get_feature_names_out().tolist(), "childrenLeft": tree.children_left.tolist(), "childrenRight": tree.children_right.tolist(), "feature": tree.feature.tolist(), "threshold": tree.threshold.tolist(), "values": tree.value.tolist(), "scope": report["scope"], "report": {key: value for key, value in report.items() if key != "exclusions"}}
    output.mkdir(parents=True, exist_ok=True)
    for name, part in splits.items():
        (output / f"{name}.jsonl").write_text("".join(json.dumps(s) + "\n" for s in part), encoding="utf-8")
    (output / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    with (output / "metrics.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["split", "total", "covered", "coverage", "precision_positive", "recall_positive", "f1_positive", "macro_f1", "v1_macro_f1_same_cases"])
        for name, metrics in report["metrics"].items():
            positive = metrics["classificationReport"]["1"]
            writer.writerow([name, metrics["size"], metrics["covered"], metrics["coverage"], positive["precision"], positive["recall"], positive["f1-score"], metrics["classificationReport"]["macro avg"]["f1-score"], metrics["v1SameCases"]["classificationReport"]["macro avg"]["f1-score"]])
    model_output.parent.mkdir(parents=True, exist_ok=True)
    model_output.write_text(json.dumps(artifact), encoding="utf-8")
    return {"rows": len(rows), "excluded": len(excluded), "knownTransformations": known, "metrics": {key: {k: v for k, v in values.items() if k != "predictions"} for key, values in report["metrics"].items()}}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("initial", "owasp", "raw_initial", "raw_owasp", "output", "model"):
        p.add_argument(name, type=Path)
    args = p.parse_args()
    rows, excluded = collect(args.initial, args.owasp, args.raw_initial, args.raw_owasp)
    print(json.dumps(train(rows, excluded, args.output, args.model), indent=2))


if __name__ == "__main__":
    main()
