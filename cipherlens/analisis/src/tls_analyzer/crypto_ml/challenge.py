"""Project-authored challenge evaluation, without training or threshold changes.

Labels are declared in the case definitions before analysis. These are not an
independent public benchmark. Abstentions remain separate from binary errors.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path

from .review import analyze


def cases() -> list[dict]:
    result = []
    def rsa(identifier, expression, expected, setup="", extra=""):
        source = f'''import java.security.*;
public class Challenge {{
 {extra}
 public static void main(String[] args) throws Exception {{
  {setup}
  KeyPairGenerator g=KeyPairGenerator.getInstance("RSA");
  g.initialize({expression});
 }}
}}'''
        result.append({"id": identifier, "target": "JAVA-RSA-SIZE", "expected": expected, "source": source})
    rsa("rsa_hex_weak", "0x400", 1)
    rsa("rsa_octal_minimum", "04000", 0)
    rsa("rsa_unseen_2051", "2051", 0)
    rsa("rsa_unseen_2011", "2011", 1)
    rsa("rsa_arithmetic_weak", "2048 / 2", 1)
    rsa("rsa_arithmetic_strong", "1536 * 2", 0)
    rsa("rsa_cast_weak", "(int) 1024", 1)
    rsa("rsa_helper_return", "size()", 1, extra="static int size(){ return 1024; }")
    rsa("rsa_increment_safe", "size", 0, setup="int size=2047; size++;")
    rsa("rsa_nested_assignment_safe", "size", 0, setup="int size=1024; {size=3072;}")
    rsa("rsa_boundary_minus_one", "2047", 1)
    rsa("rsa_outside_model_domain", "32768", 0)
    rsa("rsa_dynamic_input", "Integer.parseInt(args[0])", None)
    rsa("rsa_conditional_input", "size", None, setup="int size=args.length>0 ? 1024 : 3072;")

    def material(identifier, target, expected, body, extra=""):
        source = f'''import javax.crypto.*; import javax.crypto.spec.*;
import java.security.*; import java.util.Arrays;
public class Challenge {{
 {extra}
 public static void main(String[] args) throws Exception {{
  KeyGenerator generator=KeyGenerator.getInstance("AES");
  SecretKey key=generator.generateKey();
  {body}
 }}
}}'''
        result.append({"id": identifier, "target": target, "expected": expected, "source": source})
    cbc = 'Cipher c=Cipher.getInstance("AES/CBC/PKCS5Padding");'
    enc = 'c.init(Cipher.ENCRYPT_MODE,key,new IvParameterSpec(iv));'
    material("cbc_direct_fixed", "JAVA-CBC-CONSTANT-IV", 1, cbc + "byte[] iv=new byte[16];" + enc)
    material("cbc_direct_random", "JAVA-CBC-CONSTANT-IV", 0, cbc + "byte[] iv=new byte[16]; new SecureRandom().nextBytes(iv);" + enc)
    material("cbc_decrypt_fixture", "JAVA-CBC-CONSTANT-IV", 0, cbc + 'byte[] iv=new byte[16]; c.init(Cipher.DECRYPT_MODE,key,new IvParameterSpec(iv));')
    material("cbc_alias_random", "JAVA-CBC-CONSTANT-IV", 0, cbc + "byte[] iv=new byte[16];byte[] alias=iv;new SecureRandom().nextBytes(alias);" + enc)
    material("cbc_literal_loop", "JAVA-CBC-CONSTANT-IV", 1, cbc + "byte[] iv=new byte[16]; for(int i=0;i<iv.length;i++){iv[i]=(byte)i;}" + enc)
    material("cbc_copy_constructor_range", "JAVA-CBC-CONSTANT-IV", 1, cbc + 'byte[] iv=new byte[32]; c.init(Cipher.ENCRYPT_MODE,key,new IvParameterSpec(iv,0,16));')
    material("cbc_helper_returns_fixed", "JAVA-CBC-CONSTANT-IV", 1, cbc + "byte[] iv=fixed();" + enc, extra="static byte[] fixed(){return new byte[16];}")
    material("cbc_global_helper_randomizes", "JAVA-CBC-CONSTANT-IV", 0, cbc + "byte[] iv=new byte[16];shared=iv;randomize();" + enc, extra="static byte[] shared; static void randomize(){new SecureRandom().nextBytes(shared);}")
    material("cbc_global_helper_clears", "JAVA-CBC-CONSTANT-IV", 1, cbc + "byte[] iv=new byte[16];new SecureRandom().nextBytes(iv);shared=iv;clear();" + enc, extra="static byte[] shared; static void clear(){Arrays.fill(shared,(byte)0);}")
    gcm = 'Cipher c=Cipher.getInstance("AES/GCM/NoPadding");'
    material("gcm_snapshot_before_random", "JAVA-GCM-CONSTANT-NONCE", 1, gcm + 'byte[] iv=new byte[12];GCMParameterSpec p=new GCMParameterSpec(128,iv);new SecureRandom().nextBytes(iv);c.init(Cipher.ENCRYPT_MODE,key,p);')
    material("gcm_snapshot_after_random", "JAVA-GCM-CONSTANT-NONCE", 0, gcm + 'byte[] iv=new byte[12];new SecureRandom().nextBytes(iv);GCMParameterSpec p=new GCMParameterSpec(128,iv);c.init(Cipher.ENCRYPT_MODE,key,p);')
    material("key_explicit_literal", "JAVA-EMBEDDED-KEY", 1, gcm + 'key=new SecretKeySpec("FIXTURE_KEY_1234".getBytes(),"AES");c.init(Cipher.ENCRYPT_MODE,key);')
    material("key_runtime_generated", "JAVA-EMBEDDED-KEY", 0, gcm + 'c.init(Cipher.ENCRYPT_MODE,key);')
    material("key_range_constructor", "JAVA-EMBEDDED-KEY", 1, gcm + 'byte[] raw=new byte[32];key=new SecretKeySpec(raw,0,16,"AES");c.init(Cipher.ENCRYPT_MODE,key);')
    material("key_global_helper_clears", "JAVA-EMBEDDED-KEY", 1, gcm + 'byte[] raw=new byte[16];new SecureRandom().nextBytes(raw);shared=raw;clear();key=new SecretKeySpec(raw,"AES");c.init(Cipher.ENCRYPT_MODE,key);', extra="static byte[] shared;static void clear(){Arrays.fill(shared,(byte)0);}")
    material("implicit_aes", "JAVA-CIPHER-IMPLICIT-DEFAULTS", 1, 'Cipher c=Cipher.getInstance("AES");')
    material("explicit_aes", "JAVA-CIPHER-IMPLICIT-DEFAULTS", 0, gcm)
    return result


def evaluate(output: Path) -> dict:
    from sklearn.metrics import classification_report, confusion_matrix
    assets = Path(__file__).with_name("assets")
    before = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in assets.glob("*.json")}
    code_hashes = {name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest() for name in ("java_review.py", "material_review.py", "review.py", "rsa_classifier.py", "challenge.py")}
    rsa_catalog = Path(__file__).parents[3] / "data/crypto_ml/rsa-policy-v1/catalog.json"
    train_sizes = {bits for bits, _ in json.loads(rsa_catalog.read_text())["train"]}
    definitions = cases()
    output.mkdir(parents=True, exist_ok=True)
    # Freeze case definitions/expected labels before running the analyzer.
    (output / "cases.json").write_text(json.dumps(definitions, indent=2), encoding="utf-8")
    rows = []
    for case in definitions:
        result = analyze(case["source"], case["id"] + ".java")
        target = case["target"]
        if any(f["id"] == target for f in result["findings"]):
            predicted = 1
        elif target == "JAVA-RSA-SIZE":
            predicted = 0 if any(f["kind"] == "rsa_bits" for f in result["observations"]) else None
        else:
            predicted = None if result["unresolved"] or result["status"] == "not_evaluable" else 0
        ml = result["ml"]["rsaPredictions"] if target == "JAVA-RSA-SIZE" else []
        rsa_bits = ml[0]["bits"] if len(ml) == 1 else None
        rows.append({"id": case["id"], "target": target, "actual": case["expected"], "predicted": predicted, "mlRsaPredicted": int(ml[0]["score"] >= 0.5) if len(ml) == 1 else None, "mlRsaBits": rsa_bits, "rsaSizeSeenInTrain": rsa_bits in train_sizes if rsa_bits is not None else None, "status": result["status"], "unresolved": result["unresolved"]})
    def metrics(items, field):
        labelled = [s for s in items if s["actual"] is not None]
        covered = [s for s in labelled if s[field] is not None]
        actual, predicted = [s["actual"] for s in covered], [s[field] for s in covered]
        return {"labelled": len(labelled), "covered": len(covered), "abstentions": len(labelled) - len(covered), "coverage": len(covered)/len(labelled) if labelled else 0, "confusionMatrix": confusion_matrix(actual,predicted,labels=[0,1]).tolist(), "classificationReport": classification_report(actual,predicted,labels=[0,1],output_dict=True,zero_division=0)}
    report = {"provenance": "New project-authored functional challenges; not independent public validation", "trainingPerformed": False, "thresholdsChanged": False, "modelHashes": before, "caseCount": len(rows), "knownLabelCases": sum(s["actual"] is not None for s in rows), "controlsCoveredCases": metrics(rows,"predicted"), "byControl": {target:metrics([s for s in rows if s["target"]==target],"predicted") for target in sorted({s["target"] for s in rows})}, "rsaML": metrics([s for s in rows if s["target"]=="JAVA-RSA-SIZE"],"mlRsaPredicted"), "unknownGroundTruthCases": [s for s in rows if s["actual"] is None], "results": rows, "limitations": ["Metrics on covered cases exclude abstentions; report coverage alongside them", "No global accuracy claim for the application", "Expected labels describe the target control, not complete security", "Some labels require reading simple helper effects beyond analyzer scope", "Cases are now observed; future fixes turn them into regression tests, not untouched validation"]}
    (output / "report.json").write_text(json.dumps(report,indent=2),encoding="utf-8")
    report["analysisCodeHashes"] = code_hashes
    report["rsaMLUnseenSizes"] = metrics([s for s in rows if s["mlRsaBits"] is not None and s["rsaSizeSeenInTrain"] is False], "mlRsaPredicted")
    (output / "report.json").write_text(json.dumps(report,indent=2),encoding="utf-8")
    with (output / "results.csv").open("w",encoding="utf-8",newline="") as handle:
        writer=csv.DictWriter(handle,fieldnames=["id","target","actual","predicted","mlRsaPredicted","mlRsaBits","rsaSizeSeenInTrain","status"],extrasaction="ignore")
        writer.writeheader(); writer.writerows(rows)
    after={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in assets.glob("*.json")}
    if before!=after:
        raise RuntimeError("Model files changed during evaluation")
    return {k:v for k,v in report.items() if k not in {"results","byControl","unknownGroundTruthCases","modelHashes"}}


if __name__ == "__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("output",type=Path)
    args=p.parse_args()
    print(json.dumps(evaluate(args.output),indent=2))
