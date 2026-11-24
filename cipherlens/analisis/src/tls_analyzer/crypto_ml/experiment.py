"""Reproducible benchmark preparation and grouped holdout evaluation.

Run with --help. Labels come from the upstream spreadsheet, never filenames.
No input Java is compiled or executed. Test is never used for model selection.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import csv
from collections import Counter
from pathlib import Path

REVISION = "e6b6b50fef6970151300c1ac2de62e188ba6de19"
TOKEN = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|//[^\n]*|/\*[\s\S]*?\*/|[A-Za-z_$][\w$]*|\d+|[^\s]')
KEEP = frozenset("Cipher KeyGenerator KeyPairGenerator SecretKeySpec IvParameterSpec GCMParameterSpec MessageDigest Mac SecureRandom Random PBEKeySpec PBEParameterSpec KeyStore SSLContext TrustManager X509TrustManager HostnameVerifier HttpsURLConnection getInstance init initialize setSeed ENCRYPT_MODE DECRYPT_MODE generateKey generateKeyPair nextBytes verify checkServerTrusted checkClientTrusted getAcceptedIssuers return new if else for while true false null String byte int char public private static final void class throws throw try catch import package".split())


def normalize(source: str, *, skeleton: bool = False) -> str:
    """Remove comments and provenance, anonymize user identifiers, retain literals.

    String-aware tokenization avoids mistaking URLs inside literals for comments.
    Skeleton also masks literal values so near-identical variants share a group.
    """
    source = re.sub(r"(?m)^\s*(?:package|import)\s+[^;]+;", "", source)
    tokens = []
    for match in TOKEN.finditer(source):
        token = match.group()
        if token.startswith(("//", "/*")):
            continue
        if token.startswith(('"', "'")):
            token = "LITERAL" if skeleton else token
        elif token[0].isdigit():
            token = "NUMBER" if skeleton else token
        elif re.fullmatch(r"[A-Za-z_$][\w$]*", token) and token not in KEEP:
            token = "identifier"
        tokens.append(token)
    return " ".join(tokens)


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def prepare(source: Path, output: Path) -> dict:
    """Import explicitly labelled spreadsheet rows, combining multi-file cases."""
    from openpyxl import load_workbook

    workbook = load_workbook(source / "CryptoAPI-Bench_details.xlsx", data_only=True)
    files = {p.name: p for p in (source / "src").rglob("*.java")}
    samples, skipped = [], []
    for index, row in enumerate(workbook.active.iter_rows(values_only=True), 1):
        names, label = row[1], row[3]
        if not isinstance(names, str) or label not in (0, 1):
            continue
        paths = [files.get(n.strip() if n.strip().endswith(".java") else n.strip() + ".java") for n in names.splitlines() if n.strip()]
        if not paths or any(p is None for p in paths):
            skipped.append({"row": index, "names": names, "reason": "source_not_found"})
            continue
        code = "\n".join(p.read_text(encoding="utf-8-sig") for p in paths)
        clean = normalize(code)
        samples.append({"id": f"cryptoapi-row-{index}", "sourcePaths": [p.relative_to(source).as_posix() for p in paths], "label": int(label), "category": paths[0].parent.name, "group": digest(normalize(code, skeleton=True)), "text": clean, "sha256": digest(clean)})
    # Exact duplicates cannot cross sets, even if structural groups change later.
    seen = {}
    for sample in samples:
        key = sample["sha256"]
        if key in seen and seen[key]["label"] != sample["label"]:
            raise ValueError("Conflicting labels after normalization; manual review required")
        seen.setdefault(key, sample)
    samples = sorted(seen.values(), key=lambda x: x["id"])
    output.mkdir(parents=True, exist_ok=True)
    (output / "dataset.jsonl").write_text("".join(json.dumps(s, ensure_ascii=False) + "\n" for s in samples), encoding="utf-8")
    (output / "LICENSE-CryptoAPI-Bench.txt").write_text((source / "LICENSE").read_text(), encoding="utf-8")
    audit = {"source": "https://github.com/CryptoAPI-Bench/CryptoAPI-Bench", "revision": REVISION, "samples": len(samples), "labels": dict(Counter(s["label"] for s in samples)), "categories": dict(Counter(s["category"] for s in samples)), "groups": len({s["group"] for s in samples}), "skipped": skipped, "labelSource": "CryptoAPI-Bench_details.xlsx column D", "limitations": ["Academic synthetic benchmark; not production validation", "Binary labels across benchmark categories, not per-vulnerability localization", "Skeleton grouping reduces but cannot eliminate semantic similarity"]}
    (output / "audit.json").write_text(json.dumps(audit, indent=2), encoding="utf-8")
    return audit


def train(dataset: Path, output: Path) -> dict:
    """Freeze a grouped test fold, fit on train only, report both and baselines."""
    import sklearn
    from sklearn.dummy import DummyClassifier
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import classification_report, confusion_matrix, balanced_accuracy_score
    from sklearn.model_selection import StratifiedGroupKFold
    from sklearn.pipeline import make_pipeline

    samples = [json.loads(line) for line in dataset.read_text(encoding="utf-8").splitlines() if line]
    texts = [s["text"] for s in samples]
    labels = [s["label"] for s in samples]
    groups = [s["group"] for s in samples]
    # Fixed fold and hyperparameters, declared before evaluating test.
    splitter = StratifiedGroupKFold(n_splits=4, shuffle=True, random_state=42)
    train_idx, test_idx = next(splitter.split(texts, labels, groups))
    if set(labels[i] for i in train_idx) != {0, 1} or set(labels[i] for i in test_idx) != {0, 1}:
        raise ValueError("Fixed split lacks a class; expand dataset rather than search test folds")
    train_rows = [samples[i] for i in train_idx]
    test_rows = [samples[i] for i in test_idx]
    assert not {s["group"] for s in train_rows} & {s["group"] for s in test_rows}
    assert not {s["sha256"] for s in train_rows} & {s["sha256"] for s in test_rows}
    x_train, y_train = [s["text"] for s in train_rows], [s["label"] for s in train_rows]
    model = make_pipeline(TfidfVectorizer(ngram_range=(1, 2), lowercase=False, token_pattern=r"(?u)\b\w+\b"), LogisticRegression(class_weight="balanced", random_state=42, max_iter=2000))
    model.fit(x_train, y_train)
    def metrics(actual, predicted):
        return {"classificationReport": classification_report(actual, predicted, labels=[0, 1], target_names=["no_misuse_in_benchmark", "misuse"], output_dict=True, zero_division=0), "confusionMatrix": confusion_matrix(actual, predicted, labels=[0, 1]).tolist(), "balancedAccuracy": balanced_accuracy_score(actual, predicted)}
    report = {"seed": 42, "sklearnVersion": sklearn.__version__, "split": "first fold StratifiedGroupKFold(n_splits=4, shuffle=True, random_state=42)", "model": "TF-IDF word unigrams/bigrams + balanced logistic regression; fixed parameters", "testUsedForTuning": False, "train": {"size": len(train_rows), "metrics": metrics(y_train, model.predict(x_train))}, "test": {"size": len(test_rows), "metrics": metrics([s['label'] for s in test_rows], model.predict([s['text'] for s in test_rows]))}, "baselines": {}, "limitations": ["Small, imbalanced academic benchmark", "No independent real-world validation", "No dataflow/control-flow resolution; false positives and negatives expected", "Binary score is not calibrated vulnerability probability", "Test results do not imply TLS rule accuracy or full AES/RSA coverage"]}
    dummy = DummyClassifier(strategy="most_frequent").fit(x_train, y_train)
    report["baselines"]["majority"] = metrics([s["label"] for s in test_rows], dummy.predict([s["text"] for s in test_rows]))
    report["baselines"]["literal_patterns"] = metrics([s["label"] for s in test_rows], [int(bool(re.search(r'ECB|DES|MD5|SHA1|1024|NoPadding', s["text"]))) for s in test_rows])
    test_prediction = model.predict([s["text"] for s in test_rows])
    test_scores = model.predict_proba([s["text"] for s in test_rows])[:, 1]
    report["test"]["predictions"] = [
        {"id": sample["id"], "category": sample["category"], "actual": sample["label"], "predicted": int(prediction), "score": float(score)}
        for sample, prediction, score in zip(test_rows, test_prediction, test_scores)
    ]
    report["test"]["byCategory"] = {}
    for category in sorted({s["category"] for s in test_rows}):
        indexes = [i for i, s in enumerate(test_rows) if s["category"] == category]
        report["test"]["byCategory"][category] = {
            "size": len(indexes),
            "correct": sum(int(test_prediction[i]) == test_rows[i]["label"] for i in indexes),
        }
    report["datasetSha256"] = hashlib.sha256(dataset.read_bytes()).hexdigest()
    report["confusionMatrixOrder"] = "rows=actual, columns=predicted; class order [0, 1] => [[TN, FP], [FN, TP]]"
    vectorizer, classifier = model.steps[0][1], model.steps[1][1]
    artifact = {"schemaVersion": 1, "modelVersion": digest(json.dumps([s["sha256"] for s in train_rows]))[:16], "datasetRevision": REVISION, "vocabulary": vectorizer.vocabulary_, "idf": vectorizer.idf_.tolist(), "coefficients": classifier.coef_[0].tolist(), "intercept": float(classifier.intercept_[0]), "threshold": 0.5, "report": report}
    output.mkdir(parents=True, exist_ok=True)
    manifest = {
        "seed": 42,
        "datasetSha256": report["datasetSha256"],
        "trainIds": [s["id"] for s in train_rows],
        "testIds": [s["id"] for s in test_rows],
        "groupOverlap": [],
        "normalizedSourceOverlap": [],
        "groupDefinition": "SHA256 of comment-free, identifier-anonymized source with literals and numbers masked; not a guarantee of semantic independence",
    }
    (output / "split-manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    for name, rows in [("train", train_rows), ("test", test_rows)]:
        (output / f"{name}.jsonl").write_text("".join(json.dumps(s, ensure_ascii=False) + "\n" for s in rows), encoding="utf-8")
    (output / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    (output / "model.json").write_text(json.dumps(artifact, ensure_ascii=False), encoding="utf-8")
    # Verify portable runtime against the trained sklearn pipeline.
    from .inference import probability
    for text in texts:
        expected = float(model.predict_proba([text])[0, 1])
        if abs(expected - probability(text, artifact)) > 1e-10:
            raise ValueError("Portable inference differs from sklearn")
    return report


def evaluate(artifact_directory: Path, output: Path) -> dict:
    """Evaluate the frozen test using saved weights only; never call fit."""
    from sklearn.metrics import classification_report, confusion_matrix, balanced_accuracy_score
    from .inference import probability

    artifact = json.loads((artifact_directory / "model.json").read_text(encoding="utf-8"))
    manifest = json.loads((artifact_directory / "split-manifest.json").read_text(encoding="utf-8"))
    rows = [json.loads(line) for line in (artifact_directory / "test.jsonl").read_text(encoding="utf-8").splitlines() if line]
    if [s["id"] for s in rows] != manifest["testIds"]:
        raise ValueError("Test IDs differ from the frozen split manifest")
    # Check contents against the recorded dataset rather than trusting IDs alone.
    expected = {s["id"]: s for s in artifact["report"]["test"]["predictions"]}
    for sample in rows:
        if digest(sample["text"]) != sample["sha256"] or sample["label"] != expected[sample["id"]]["actual"]:
            raise ValueError("Test text or labels changed")
        # Reference scores also catch edits with a recomputed text hash.
        if abs(probability(sample["text"], artifact) - expected[sample["id"]]["score"]) > 1e-10:
            raise ValueError("Frozen test/model no longer matches the recorded experiment")
    actual = [s["label"] for s in rows]
    predicted = [int(probability(s["text"], artifact) >= artifact["threshold"]) for s in rows]
    report = {
        "modelVersion": artifact["modelVersion"],
        "size": len(rows),
        "trainingPerformed": False,
        "classificationReport": classification_report(actual, predicted, labels=[0, 1], target_names=["no_misuse_in_benchmark", "misuse"], output_dict=True, zero_division=0),
        "confusionMatrix": confusion_matrix(actual, predicted, labels=[0, 1]).tolist(),
        "balancedAccuracy": balanced_accuracy_score(actual, predicted),
    }
    output.mkdir(parents=True, exist_ok=True)
    (output / "evaluation.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    with (output / "metrics.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["class_or_average", "precision", "recall", "f1", "support"])
        for name, values in report["classificationReport"].items():
            if isinstance(values, dict):
                writer.writerow([name, values["precision"], values["recall"], values["f1-score"], values["support"]])
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("prepare", "train", "evaluate"):
        cmd = commands.add_parser(name)
        cmd.add_argument("input", type=Path)
        cmd.add_argument("output", type=Path)
    args = parser.parse_args()
    result = {"prepare": prepare, "train": train, "evaluate": evaluate}[args.command](args.input, args.output)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
