"""Isolated V2 experiment: scoped tasks, grouped train/validation/test.

No deployed artifact is overwritten. OWASP is development data, no longer an
untouched external test. CCA files require reviewed labels before inclusion.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import Counter
from pathlib import Path

from .context_v2 import extract_context
from .experiment import digest, normalize


def prepare(initial: Path, owasp: Path, output: Path, raw_initial: Path | None = None, raw_owasp: Path | None = None) -> dict:
    """Use only upstream labels. Task definitions are recorded, not inferred."""
    rows, excluded = [], []
    sources = [
        (initial, "cryptoapi", {"brokencrypto": "cipher_policy", "ecbcrypto": "cipher_policy", "insecureasymmetriccrypto": "rsa_key_size"}),
        (owasp, "owasp_observed", {"crypto": "cipher_policy"}),
    ]
    for path, origin, categories in sources:
        for line in path.read_text(encoding="utf-8").splitlines():
            sample = json.loads(line)
            if sample["category"] not in categories:
                continue
            code = sample["text"]
            if origin == "cryptoapi" and raw_initial is not None:
                code = "\n".join((raw_initial / path).read_text(encoding="utf-8-sig") for path in sample["sourcePaths"])
            elif origin == "owasp_observed" and raw_owasp is not None:
                code = (raw_owasp / (sample["id"] + ".java")).read_text(encoding="utf-8-sig")
            if (raw_initial is not None and origin == "cryptoapi") or (raw_owasp is not None and origin == "owasp_observed"):
                if digest(normalize(code)) != sample["sha256"]:
                    raise ValueError(f"Raw source does not match audited dataset: {sample['id']}")
            context = extract_context(code)
            if not context["text"]:
                excluded.append({"id": sample["id"], "reason": "no_context"})
                continue
            rows.append({"id": origin + ":" + sample["id"], "source": origin, "category": sample["category"], "task": categories[sample["category"]], "label": sample["label"], "text": context["text"], "features": context["features"], "originalGroup": sample["group"], "contextGroup": digest(normalize(context["text"], skeleton=True)), "sha256": digest(context["text"])})
    # Connected components enforce original structure, context and observable
    # feature groups globally, including duplicates across source datasets.
    parents = list(range(len(rows)))
    def find(i):
        while parents[i] != i:
            parents[i] = parents[parents[i]]
            i = parents[i]
        return i
    seen = {}
    for i, row in enumerate(rows):
        for key in (("original", row["originalGroup"]), ("context", row["contextGroup"]), ("exact", row["sha256"]), ("observations", digest(json.dumps(row["features"], sort_keys=True)))):
            if key in seen:
                parents[find(i)] = find(seen[key])
            else:
                seen[key] = i
    exact_labels = {}
    for row in rows:
        exact_labels.setdefault((row["task"], row["sha256"]), set()).add(row["label"])
    kept, used = [], set()
    for i, row in enumerate(rows):
        key = (row["task"], row["sha256"])
        if len(exact_labels[key]) > 1:
            excluded.append({"id": row["id"], "reason": "conflicting_labels_for_same_extracted_context"})
            continue
        if key in used:
            excluded.append({"id": row["id"], "reason": "duplicate_context"})
            continue
        used.add(key)
        row["group"] = str(find(i))
        kept.append(row)
    audit = {"definition": {"cipher_policy": "Potential symmetric cipher misuse under the source benchmark policy (weak algorithms or ECB); not full AES security", "rsa_key_size": "Potential insufficient asymmetric key size under CryptoAPI-Bench labels; not padding detection"}, "sourceHashes": {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path, _, _ in sources}, "taskCounts": {task: {"rows": sum(s["task"] == task for s in kept), "labels": dict(Counter(s["label"] for s in kept if s["task"] == task)), "groups": len({s["group"] for s in kept if s["task"] == task})} for task in sorted({s["task"] for s in kept})}, "excluded": excluded, "ccaIncluded": False, "owaspRole": "Observed development source; cannot claim independent external validation", "limitations": ["Lexical extraction does not resolve control flow", "Conflicts after extraction are excluded and reported, reducing coverage", "Derived OWASP samples retain GPL-2.0 source licensing"]}
    output.mkdir(parents=True, exist_ok=True)
    audit["rawSourcesUsed"] = {"cryptoapi": raw_initial is not None, "owasp": raw_owasp is not None}
    audit["grouping"] = "Connected components of original skeleton, extracted skeleton, exact context, and observable feature vector"
    (output / "dataset.jsonl").write_text("".join(json.dumps(s) + "\n" for s in kept), encoding="utf-8")
    (output / "audit.json").write_text(json.dumps(audit, indent=2), encoding="utf-8")
    return audit


def run(dataset: Path, output: Path) -> dict:
    """Fixed candidate list; validation selects, test is evaluated once after."""
    import joblib
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.feature_extraction import DictVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics import classification_report, confusion_matrix, f1_score
    from sklearn.model_selection import StratifiedGroupKFold
    from sklearn.pipeline import make_pipeline

    if output.resolve() == Path(__file__).with_name("assets").resolve():
        raise ValueError("V2 must never overwrite the deployed V1 assets")
    output.mkdir(parents=True, exist_ok=True)
    rows = [json.loads(line) for line in dataset.read_text(encoding="utf-8").splitlines() if line]
    report = {"deployed": False, "datasetSha256": hashlib.sha256(dataset.read_bytes()).hexdigest(), "seed": 42, "selectionMetric": "validation macro F1", "splitRule": "First fold of stratified grouped 5-fold for test, then first fold of grouped 4-fold for validation; seed 42; no seed search", "tasks": {}}
    for task in sorted({s["task"] for s in rows}):
        samples = [s for s in rows if s["task"] == task]
        counts = Counter(s["label"] for s in samples)
        if min(counts.get(0, 0), counts.get(1, 0)) < 10:
            report["tasks"][task] = {"status": "insufficient_data", "rows": len(samples), "labels": dict(counts), "reason": "Fewer than 10 examples in a class before grouped three-way split"}
            continue
        groups = [s["group"] for s in samples]
        class_groups = {label: len({s["group"] for s in samples if s["label"] == label}) for label in (0, 1)}
        if len(set(groups)) < 5 or min(class_groups.values()) < 3:
            report["tasks"][task] = {"status": "insufficient_independent_patterns", "rows": len(samples), "groups": len(set(groups)), "classGroups": class_groups, "reason": "Too few independent connected groups to isolate train/validation/test; no model fitted"}
            continue
        first = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=42)
        development, test = next(first.split(samples, [s["label"] for s in samples], groups))
        remaining = [samples[i] for i in development]
        second = StratifiedGroupKFold(n_splits=4, shuffle=True, random_state=42)
        train_local, validation_local = next(second.split(remaining, [s["label"] for s in remaining], groups=[s["group"] for s in remaining]))
        partitions = {"train": [remaining[i] for i in train_local], "validation": [remaining[i] for i in validation_local], "test": [samples[i] for i in test]}
        folder = output / task
        folder.mkdir(exist_ok=True)
        manifest = {key: [{"id": s["id"], "group": s["group"], "label": s["label"]} for s in values] for key, values in partitions.items()}
        (folder / "split-manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        if any({s["label"] for s in values} != {0, 1} for values in partitions.values()):
            report["tasks"][task] = {"status": "insufficient_split", "reason": "Fixed grouped split does not contain both classes in every set", "sizes": {key: len(values) for key, values in partitions.items()}}
            continue
        for key, values in partitions.items():
            (folder / f"{key}.jsonl").write_text("".join(json.dumps(s) + "\n" for s in values), encoding="utf-8")
        candidates = [
            ("context_logistic", "text", make_pipeline(TfidfVectorizer(ngram_range=(1, 2), lowercase=False), LogisticRegression(class_weight="balanced", random_state=42, max_iter=2000))),
            ("observations_forest", "features", make_pipeline(DictVectorizer(), RandomForestClassifier(n_estimators=100, max_depth=6, class_weight="balanced", random_state=42))),
        ]
        scores, fitted = [], []
        for name, representation, model in candidates:
            model.fit([s[representation] for s in partitions["train"]], [s["label"] for s in partitions["train"]])
            predicted = model.predict([s[representation] for s in partitions["validation"]])
            score = f1_score([s["label"] for s in partitions["validation"]], predicted, average="macro", zero_division=0)
            scores.append({"name": name, "representation": representation, "validationMacroF1": score})
            fitted.append(model)
        winner = max(range(len(scores)), key=lambda i: scores[i]["validationMacroF1"])
        model, chosen = fitted[winner], scores[winner]
        metrics = {}
        for key, values in partitions.items():
            actual = [s["label"] for s in values]
            predicted = model.predict([s[chosen["representation"]] for s in values])
            metrics[key] = {"size": len(values), "classificationReport": classification_report(actual, predicted, labels=[0, 1], output_dict=True, zero_division=0), "confusionMatrix": confusion_matrix(actual, predicted, labels=[0, 1]).tolist(), "predictions": [{"id": s["id"], "actual": s["label"], "predicted": int(p)} for s, p in zip(values, predicted)]}
        # Compare a small literal reference on exactly the same test set. It is
        # not a complete static analyzer and must not be described as one.
        import re
        actual = [s["label"] for s in partitions["test"]]
        baseline = [int(bool(re.search(r'ECB|DES|Blowfish|RC2|RC4|IDEA', s["text"]))) for s in partitions["test"]]
        baseline_metrics = classification_report(actual, baseline, labels=[0, 1], output_dict=True, zero_division=0)
        joblib.dump(model, folder / "local-experiment-only.joblib")
        report["tasks"][task] = {"status": "evaluated_not_deployed", "selected": chosen, "candidates": scores, "metrics": metrics, "literalBaselineTest": baseline_metrics, "limitations": ["No untouched external evaluation of V2", "Excluded ambiguous contexts reduce coverage", "Joblib is a local experiment artifact; never load user-supplied pickle/joblib"]}
    (output / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def audit_cca(tree_path: Path, output: Path) -> dict:
    """Inventory upstream candidates without inferring labels from filenames."""
    tree = json.loads(tree_path.read_text(encoding="utf-8-sig"))
    paths = [entry["path"] for entry in tree["tree"] if entry["type"] == "blob"]
    candidates = [path for path in paths if path.startswith(("dataset/ecbcrypto/", "dataset/insecureasymmetriccipher/", "dataset/insecurepadding/")) and path.endswith(".java")]
    audit = {"source": "https://github.com/AndroidSeclab/CCA-Droid", "revision": tree["sha"], "counts": dict(Counter(path.split("/")[1] for path in candidates)), "licenseFilesFound": [path for path in paths if Path(path).name.lower().startswith(("license", "copying"))], "labelFilesFound": [path for path in paths if path.startswith("dataset/") and path.endswith((".csv", ".xlsx", ".json", ".jsonl"))], "trainingIncluded": False, "reason": "Requires explicit label review and provenance/licensing review; Corrected/Case filenames are not labels", "candidates": candidates}
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(audit, indent=2), encoding="utf-8")
    return audit


def summarize(report_path: Path, output: Path) -> dict:
    """Export metrics from an existing report; no model or dataset is fitted."""
    report = json.loads(report_path.read_text(encoding="utf-8"))
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["task", "split", "samples", "precision_positive", "recall_positive", "f1_positive", "f1_macro"])
        for task, item in report["tasks"].items():
            for split, metrics in item.get("metrics", {}).items():
                values = metrics["classificationReport"]
                writer.writerow([task, split, metrics["size"], values["1"]["precision"], values["1"]["recall"], values["1"]["f1-score"], values["macro avg"]["f1-score"]])
    return {"csv": str(output), "trainingPerformed": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    prep = commands.add_parser("prepare")
    prep.add_argument("initial", type=Path)
    prep.add_argument("owasp", type=Path)
    prep.add_argument("output", type=Path)
    prep.add_argument("--raw-initial", type=Path)
    prep.add_argument("--raw-owasp", type=Path)
    experiment = commands.add_parser("run")
    experiment.add_argument("dataset", type=Path)
    experiment.add_argument("output", type=Path)
    cca = commands.add_parser("audit-cca")
    cca.add_argument("tree", type=Path)
    cca.add_argument("output", type=Path)
    summary = commands.add_parser("summarize")
    summary.add_argument("report", type=Path)
    summary.add_argument("output", type=Path)
    args = parser.parse_args()
    if args.command == "prepare":
        result = prepare(args.initial, args.owasp, args.output, args.raw_initial, args.raw_owasp)
    elif args.command == "run":
        result = run(args.dataset, args.output)
        # Full predictions are saved in report.json; keep terminal output small.
        result = {**result, "tasks": {task: {key: value for key, value in item.items() if key not in {"metrics", "literalBaselineTest"}} for task, item in result["tasks"].items()}}
    elif args.command == "audit-cca":
        result = audit_cca(args.tree, args.output)
    else:
        result = summarize(args.report, args.output)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
