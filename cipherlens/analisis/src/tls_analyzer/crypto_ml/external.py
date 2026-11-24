"""Download pinned OWASP cases and evaluate frozen weights without fitting.

Only source text is fetched; no Java or upstream scripts are executed.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.request import urlopen

from .experiment import digest, normalize
from .inference import MODEL_PATH, probability, supports_normalized_source

OWASP_REVISION = "10dfcc54ad02dcfcb358b0ba4a0fef8c919a6d17"
BASE = f"https://raw.githubusercontent.com/OWASP-Benchmark/BenchmarkJava/{OWASP_REVISION}"
CATEGORIES = frozenset({"crypto", "hash", "weakrand"})


def expected_rows(source: Path) -> list[dict]:
    """Use explicit expectedresults labels, not comments or test filenames."""
    text = (source / "expectedresults-1.2.csv").read_text(encoding="utf-8-sig")
    result = []
    for row in csv.reader(io.StringIO(text)):
        if not row or row[0].startswith("#") or len(row) < 4:
            continue
        name, category, label, cwe = [s.strip() for s in row[:4]]
        if category not in CATEGORIES:
            continue
        if label not in {"true", "false"} or not name.startswith("BenchmarkTest") or not name[13:].isdigit():
            raise ValueError(f"Unexpected benchmark row: {row}")
        result.append({"id": name, "category": category, "label": int(label == "true"), "cwe": cwe})
    if not result:
        raise ValueError("No selected benchmark labels found")
    return result


def fetch(output: Path) -> dict:
    """Fetch three compatible categories, pinning and hashing downloaded files."""
    output.mkdir(parents=True, exist_ok=True)
    def download(remote: str, target: Path):
        with urlopen(f"{BASE}/{remote}", timeout=45) as response:
            data = response.read()
        target.write_bytes(data)
        return hashlib.sha256(data).hexdigest()
    download("expectedresults-1.2.csv", output / "expectedresults-1.2.csv")
    download("LICENSE", output / "LICENSE")
    rows = expected_rows(output)
    def get_case(row):
        name = row["id"] + ".java"
        sha = download("src/main/java/org/owasp/benchmark/testcode/" + name, output / name)
        return {"id": row["id"], "sha256": sha}
    with ThreadPoolExecutor(max_workers=6) as pool:
        files = list(pool.map(get_case, rows))
    manifest = {"source": "https://github.com/OWASP-Benchmark/BenchmarkJava", "revision": OWASP_REVISION, "categories": sorted(CATEGORIES), "files": files}
    (output / "download-manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return {"downloaded": len(files), "revision": OWASP_REVISION}


def evaluate_external(source: Path, output: Path, model_path: Path = MODEL_PATH) -> dict:
    """Audit overlap, preserve errors/abstentions, evaluate without retraining."""
    from sklearn.metrics import classification_report, confusion_matrix, balanced_accuracy_score

    model_bytes = model_path.read_bytes()
    model = json.loads(model_bytes)
    initial = []
    for split in ("train", "test"):
        initial.extend(json.loads(line) for line in (model_path.parent / f"{split}.jsonl").read_text(encoding="utf-8").splitlines() if line)
    known_hashes = {s["sha256"] for s in initial}
    known_groups = {s["group"] for s in initial}
    download_manifest = json.loads((source / "download-manifest.json").read_text(encoding="utf-8"))
    if download_manifest["revision"] != OWASP_REVISION:
        raise ValueError("Unexpected OWASP revision")
    expected_hashes = {s["id"]: s["sha256"] for s in download_manifest["files"]}
    candidates, excluded = [], []
    for row in expected_rows(source):
        raw = (source / (row["id"] + ".java")).read_bytes()
        if hashlib.sha256(raw).hexdigest() != expected_hashes.get(row["id"]):
            raise ValueError(f"Source hash mismatch: {row['id']}")
        text = normalize(raw.decode("utf-8-sig"))
        sample = {**row, "text": text, "sha256": digest(text), "group": digest(normalize(raw.decode("utf-8-sig"), skeleton=True))}
        if sample["sha256"] in known_hashes or sample["group"] in known_groups:
            excluded.append({"id": row["id"], "reason": "overlap_with_initial_train_or_test"})
        else:
            candidates.append(sample)
    buckets = defaultdict(list)
    for sample in candidates:
        buckets[sample["sha256"]].append(sample)
    samples = []
    for bucket in buckets.values():
        if len({s["label"] for s in bucket}) > 1:
            excluded.extend({"id": s["id"], "reason": "conflicting_labels_after_normalization"} for s in bucket)
            continue
        samples.append(bucket[0])
        excluded.extend({"id": s["id"], "reason": "duplicate_normalized_source"} for s in bucket[1:])
    if not samples:
        raise ValueError("No independent examples remain")
    abstentions = [{"id": s["id"], "category": s["category"], "actual": s["label"], "reason": "not_evaluable_by_api"} for s in samples if not supports_normalized_source(s["text"])]
    predictions = [{"id": s["id"], "category": s["category"], "actual": s["label"], "predicted": int(probability(s["text"], model) >= model["threshold"]), "score": probability(s["text"], model)} for s in samples if supports_normalized_source(s["text"])]
    if not predictions:
        raise ValueError("No examples are evaluable by the current API")
    def metrics(items):
        actual, predicted = [s["actual"] for s in items], [s["predicted"] for s in items]
        return {"size": len(items), "classificationReport": classification_report(actual, predicted, labels=[0, 1], target_names=["no_target_misuse", "target_misuse"], output_dict=True, zero_division=0), "confusionMatrix": confusion_matrix(actual, predicted, labels=[0, 1]).tolist(), "balancedAccuracy": balanced_accuracy_score(actual, predicted)}
    report = {"source": download_manifest["source"], "revision": OWASP_REVISION, "modelVersion": model["modelVersion"], "modelSha256": hashlib.sha256(model_bytes).hexdigest(), "trainingPerformed": False, "thresholdChanged": False, "selectedRows": len(expected_rows(source)), "excluded": excluded, "labels": dict(Counter(s["label"] for s in samples)), "overall": metrics(predictions), "byCategory": {cat: metrics([p for p in predictions if p["category"] == cat]) for cat in sorted(CATEGORIES) if any(p["category"] == cat for p in predictions)}, "predictions": predictions, "limitations": ["OWASP labels concern a particular target CWE, not all potential flaws in the file", "Source-level screening does not resolve servlet helper code or dataflow", "Exact/structural overlap filtering does not guarantee semantic independence", "External evaluation is now observed: do not tune against it and claim untouched test performance"]}
    output.mkdir(parents=True, exist_ok=True)
    report["abstentions"] = abstentions
    report["coverage"] = len(predictions) / len(samples)
    (output / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    (output / "dataset.jsonl").write_text("".join(json.dumps(s) + "\n" for s in samples), encoding="utf-8")
    (output / "LICENSE-OWASP.txt").write_bytes((source / "LICENSE").read_bytes())
    with (output / "predictions.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["id", "category", "actual", "predicted", "score"])
        writer.writeheader()
        writer.writerows(predictions)
    if model_path.read_bytes() != model_bytes:
        raise RuntimeError("Model changed during evaluation")
    return {key: value for key, value in report.items() if key not in {"predictions", "excluded"}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    fetch_parser = commands.add_parser("fetch")
    fetch_parser.add_argument("output", type=Path)
    evaluate_parser = commands.add_parser("evaluate")
    evaluate_parser.add_argument("source", type=Path)
    evaluate_parser.add_argument("output", type=Path)
    args = parser.parse_args()
    result = fetch(args.output) if args.command == "fetch" else evaluate_external(args.source, args.output)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
