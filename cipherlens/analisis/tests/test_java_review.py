"""Regression checks for useful bounded AES/RSA evidence, independent of ML."""
import json
from pathlib import Path

import pytest

pytest.importorskip("javalang")
from tls_analyzer.crypto_ml.java_review import inspect_java
from tls_analyzer.crypto_ml.review import analyze, model, predict_cipher


def rsa_source(size):
    return f'''import java.security.KeyPairGenerator;
public class Example {{
 public static void main(String[] args) throws Exception {{
  KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
  g.initialize({size});
 }}
}}'''


def test_rsa_1024_and_3072_are_distinguished_without_attributing_it_to_ml():
    weak, strong = analyze(rsa_source(1024)), analyze(rsa_source(3072))
    assert weak["status"] == "possible_misuse"
    assert weak["findings"][0]["id"] == "JAVA-RSA-SIZE"
    assert weak["findings"][0]["value"] == 1024
    assert weak["findings"][0]["line"] == 5
    assert "g.initialize(1024)" in weak["findings"][0]["evidence"]
    assert weak["findings"][0]["source"] == "deterministic_parameter_check"
    assert strong["status"] in {"no_indication", "needs_review"}
    assert strong["findings"] == []
    assert weak["ml"]["rsaPredictions"][0]["classification"] == "below_size_minimum"
    assert strong["ml"]["rsaPredictions"][0]["classification"] == "meets_size_minimum"
    assert strong["ml"]["rsaPredictions"][0]["score"] == 0


def test_local_aliases_and_immutable_constants_resolve():
    source = '''class Demo {
 static final int SIZE = 1024;
 void go() throws Exception {
  java.security.KeyPairGenerator g = java.security.KeyPairGenerator.getInstance("RSA");
  int a = SIZE;
  int b = a;
  g.initialize(b);
 }
}'''
    result = inspect_java(source)
    assert any(f["id"] == "JAVA-RSA-SIZE" and f["value"] == 1024 for f in result["findings"])


@pytest.mark.parametrize("body", [
    'int size; if (args.length > 0) size = 1024; else size = 3072; g.initialize(size);',
    'g.initialize(Integer.parseInt(args[0]));',
])
def test_indirect_or_conditional_sizes_abstain(body):
    result = inspect_java(rsa_source(3072).replace("g.initialize(3072);", body))
    assert not result["findings"]
    assert result["unresolved"]


def test_parameter_shadows_class_constant_and_is_not_guessed():
    result = inspect_java('''class Demo { static final int SIZE = 1024;
      void f(int SIZE) throws Exception { KeyPairGenerator g = KeyPairGenerator.getInstance("RSA"); g.initialize(SIZE); }
    }''')
    assert not result["findings"]
    assert result["unresolved"]


def test_standalone_increment_invalidates_a_previously_resolved_value():
    result = inspect_java(rsa_source(3072).replace("g.initialize(3072);", "int size = 2047; size++; g.initialize(size);"))
    assert not result["findings"]
    assert result["unresolved"]


def test_bounded_static_setter_chain_from_main_is_resolved():
    source = '''class Demo {
      static final int DEFAULT = 1024;
      static int first; static int second;
      static void step1() { first = DEFAULT; }
      static void step2() { second = first; }
      public static void main(String[] args) throws Exception {
        step1(); step2();
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(second);
      }
    }'''
    result = analyze(source)
    assert result["findings"][0]["value"] == 1024
    assert result["ml"]["rsaPredictions"][0]["classification"] == "below_size_minimum"


def test_unsupported_setter_invalidates_propagated_fields():
    source = '''class Demo {
      static final int DEFAULT = 1024; static int size;
      static void set() { size = DEFAULT; }
      static void mutate() { size = Integer.parseInt("3072"); }
      public static void main(String[] args) throws Exception {
        set(); mutate(); KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(size);
      }
    }'''
    result = analyze(source)
    assert not result["findings"]
    assert result["unresolved"]


def test_qualified_static_setter_is_resolved_without_executing_java():
    source = '''class Demo {
      static final int DEFAULT = 1024; static int size;
      static void set() { size = DEFAULT; }
      public static void main(String[] args) throws Exception {
        Demo.set(); KeyPairGenerator g = KeyPairGenerator.getInstance("RSA"); g.initialize(size);
      }
    }'''
    assert analyze(source)["findings"][0]["value"] == 1024


def test_aes_key_generator_128_is_not_rsa():
    source = rsa_source(1024).replace("KeyPairGenerator", "KeyGenerator").replace('"RSA"', '"AES"').replace("1024", "128")
    assert inspect_java(source)["findings"] == []


def test_java_octal_literal_is_not_misread_as_decimal():
    result = inspect_java(rsa_source("03000"))
    assert result["findings"][0]["value"] == 1536


def test_user_class_named_cipher_is_not_assumed_to_be_jca():
    result = inspect_java('''class Cipher { static Cipher getInstance(String s) { return null; } }
      class Demo { void f() { Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding"); } }''')
    assert result["findings"] == []


def test_unicode_escape_input_abstains_instead_of_reporting_wrong_lines():
    result = inspect_java(rsa_source(1024) + " // \\u000a")
    assert not result["parsed"]
    assert not result["findings"]


@pytest.mark.parametrize("transformation,expected", [
    ("AES/ECB/PKCS5Padding", "JAVA-AES-ECB"),
    ("RSA/ECB/NoPadding", "JAVA-RSA-NOPADDING"),
    ("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", None),
    ("AES/GCM/NoPadding", None),
])
def test_cipher_checks_are_algorithm_specific(transformation, expected):
    result = inspect_java(f'class Demo {{ void f() throws Exception {{ Cipher c = Cipher.getInstance("{transformation}"); }} }}')
    assert [f["id"] for f in result["findings"]] == ([expected] if expected else [])


def test_comments_strings_and_branches_do_not_become_verified_findings():
    result = inspect_java('''class Demo { void f(boolean condition) throws Exception {
      // Cipher.getInstance("AES/ECB/PKCS5Padding");
      String sample = "Cipher.getInstance(\\"AES/ECB/PKCS5Padding\\")";
      if (condition) { Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding"); }
    }}''')
    assert result["findings"] == []
    assert result["unresolved"]


def test_invalid_syntax_is_explicitly_not_evaluable():
    result = analyze("this is not java")
    assert result["status"] == "needs_review"
    assert result["unresolved"]


def test_ml_is_scoped_and_abstains_on_unknown_transformations():
    artifact = model()
    assert predict_cipher("DES/CBC/PKCS5Padding", artifact) >= 0.5
    assert predict_cipher("AES/GCM/NoPadding", artifact) < 0.5
    assert predict_cipher("unknown/unknown/unknown", artifact) is None


def test_v3_train_validation_test_are_disjoint_by_source_and_groups():
    root = Path(__file__).parents[1] / "data/crypto_ml/v3-cipher"
    parts = {key: [json.loads(line) for line in (root / f"{key}.jsonl").read_text().splitlines()] for key in ("train", "validation", "test")}
    for a, b in (("train", "test"), ("train", "validation"), ("test", "validation")):
        for field in ("id", "sourceSha256", "group"):
            assert not {s[field] for s in parts[a]} & {s[field] for s in parts[b]}


def test_portable_tree_matches_recorded_test_predictions():
    root = Path(__file__).parents[1] / "data/crypto_ml/v3-cipher"
    report = json.loads((root / "report.json").read_text())
    rows = {s["id"]: s for s in (json.loads(line) for line in (root / "test.jsonl").read_text().splitlines())}
    predictions = report["metrics"]["test"]["predictions"]
    for item in predictions:
        assert int(predict_cipher(rows[item["id"]]["transformation"], model()) >= 0.5) == item["predicted"]
    covered = {s["id"] for s in predictions}
    for identifier, row in rows.items():
        if identifier not in covered:
            assert predict_cipher(row["transformation"], model()) is None
