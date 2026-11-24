"""Material provenance: encrypt/decrypt, alias mutation, copies and redaction."""
import json

import pytest

pytest.importorskip("javalang")
from tls_analyzer.crypto_ml.review import analyze


HEADER = '''import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
class MaterialExample {
 void run(byte[] input, SecretKey externalKey, boolean condition) throws Exception {
'''


def review(body):
    return analyze(HEADER + body + "\n}}")


def identifiers(result):
    return {item["id"] for item in result["findings"]}


def test_embedded_string_key_is_linked_and_never_returned():
    secret = "PRIVATE_KEY_1234"
    result = review(f'''
      byte[] raw = "{secret}".getBytes();
      SecretKey key = new SecretKeySpec(raw, "AES");
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      byte[] nonce = new byte[12]; new SecureRandom().nextBytes(nonce);
      cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, nonce));
    ''')
    assert "JAVA-EMBEDDED-KEY" in identifiers(result)
    assert "JAVA-GCM-CONSTANT-NONCE" not in identifiers(result)
    assert secret not in json.dumps(result)
    item = next(f for f in result["findings"] if f["id"] == "JAVA-EMBEDDED-KEY")
    assert item["line"] is not None
    assert "cipher.init" in item["evidence"]
    assert item["redacted"] is True


def test_one_line_source_cannot_leak_key_in_cipher_evidence():
    secret = "SECRET_16_BYTES!"
    result = review(f'Cipher c=Cipher.getInstance("AES/GCM/NoPadding"); SecretKey k=new SecretKeySpec("{secret}".getBytes(),"AES"); c.init(1,k,new GCMParameterSpec(128,new byte[12]));')
    assert "JAVA-EMBEDDED-KEY" in identifiers(result)
    assert secret not in json.dumps(result)


def test_fixed_cbc_iv_is_only_reported_when_encrypting():
    body = '''Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
      byte[] iv = new byte[16];
      IvParameterSpec params = new IvParameterSpec(iv);
      c.init(Cipher.ENCRYPT_MODE, externalKey, params);'''
    assert "JAVA-CBC-CONSTANT-IV" in identifiers(review(body))
    assert "JAVA-CBC-CONSTANT-IV" not in identifiers(review(body.replace("ENCRYPT_MODE", "DECRYPT_MODE")))


def test_gcm_constant_nonce_does_not_claim_proven_reuse():
    result = review('''Cipher c=Cipher.getInstance("AES/GCM/NoPadding");
      GCMParameterSpec params=new GCMParameterSpec(128,new byte[12]);
      c.init(Cipher.ENCRYPT_MODE,externalKey,params);''')
    item = next(f for f in result["findings"] if f["id"] == "JAVA-GCM-CONSTANT-NONCE")
    assert "no demuestra reutilización" in item["recommendation"]


@pytest.mark.parametrize("fill", [
    "SecureRandom rng = new SecureRandom(); rng.nextBytes(iv);",
    "new SecureRandom().nextBytes(iv);",
    'SecureRandom.getInstance("SHA1PRNG").nextBytes(iv);',
    "SecureRandom.getInstanceStrong().nextBytes(iv);",
])
def test_runtime_filled_iv_is_not_misreported_as_constant(fill):
    result = review(f'''Cipher c=Cipher.getInstance("AES/CBC/PKCS5Padding");
      byte[] iv=new byte[16]; {fill}
      c.init(Cipher.ENCRYPT_MODE,externalKey,new IvParameterSpec(iv));''')
    assert "JAVA-CBC-CONSTANT-IV" not in identifiers(result)


def test_array_alias_randomization_updates_provenance():
    result = review('''Cipher c=Cipher.getInstance("AES/GCM/NoPadding");
      byte[] original=new byte[12]; byte[] alias=original;
      new SecureRandom().nextBytes(alias);
      c.init(Cipher.ENCRYPT_MODE,externalKey,new GCMParameterSpec(128,original));''')
    assert "JAVA-GCM-CONSTANT-NONCE" not in identifiers(result)


def test_parameter_constructor_snapshots_before_array_randomization():
    result = review('''Cipher c=Cipher.getInstance("AES/GCM/NoPadding");
      byte[] iv=new byte[12]; GCMParameterSpec copied=new GCMParameterSpec(128,iv);
      new SecureRandom().nextBytes(iv);
      c.init(Cipher.ENCRYPT_MODE,externalKey,copied);''')
    assert "JAVA-GCM-CONSTANT-NONCE" in identifiers(result)


def test_random_key_is_not_an_embedded_key():
    result = review('''KeyGenerator generator=KeyGenerator.getInstance("AES");
      SecretKey key=generator.generateKey(); Cipher c=Cipher.getInstance("AES/GCM/NoPadding");
      byte[] iv=new byte[12]; new SecureRandom().nextBytes(iv);
      c.init(Cipher.ENCRYPT_MODE,key,new GCMParameterSpec(128,iv));''')
    assert not identifiers(result)
    assert not result["unresolved"]


def test_unused_key_and_iv_are_not_reported_as_used_for_encryption():
    result = review('''SecretKey key=new SecretKeySpec("PRIVATE_KEY_12345".getBytes(),"AES");
      IvParameterSpec unused=new IvParameterSpec(new byte[16]);''')
    assert not identifiers(result)
    assert "PRIVATE_KEY_12345" not in json.dumps(result)


def test_unknown_array_mutation_requires_review_instead_of_fixed_iv_verdict():
    result = review('''Cipher c=Cipher.getInstance("AES/CBC/PKCS5Padding");
      byte[] iv=new byte[16]; fillFromElsewhere(iv);
      c.init(Cipher.ENCRYPT_MODE,externalKey,new IvParameterSpec(iv));''')
    assert "JAVA-CBC-CONSTANT-IV" not in identifiers(result)
    assert any("IV/nonce" in item["reason"] for item in result["unresolved"])


def test_conditional_randomization_does_not_establish_either_constant_or_random():
    result = review('''Cipher c=Cipher.getInstance("AES/CBC/PKCS5Padding");
      byte[] iv=new byte[16]; if(condition){new SecureRandom().nextBytes(iv);}
      c.init(Cipher.ENCRYPT_MODE,externalKey,new IvParameterSpec(iv));''')
    assert "JAVA-CBC-CONSTANT-IV" not in identifiers(result)
    assert any("IV/nonce" in item["reason"] for item in result["unresolved"])


def test_cipher_alias_and_local_parameter_alias_are_followed():
    result = review('''Cipher first=Cipher.getInstance("AES/CBC/PKCS5Padding");
      Cipher second=first; IvParameterSpec p=new IvParameterSpec(new byte[16]);
      IvParameterSpec alias=p; int operation=Cipher.ENCRYPT_MODE;
      second.init(operation,externalKey,alias);''')
    assert "JAVA-CBC-CONSTANT-IV" in identifiers(result)


def test_explicit_defaults_warning_does_not_assert_ecb():
    result = review('Cipher c=Cipher.getInstance("AES");')
    assert "JAVA-CIPHER-IMPLICIT-DEFAULTS" in identifiers(result)
    assert "JAVA-AES-ECB" not in identifiers(result)


def test_different_init_method_is_not_cipher():
    result = review('SomeObject object=new SomeObject(); object.init(1,externalKey,new IvParameterSpec(new byte[16]));')
    assert not identifiers(result)


def test_invalid_cbc_iv_length_is_not_a_claim_of_successful_weak_encryption():
    result = review('''Cipher c=Cipher.getInstance("AES/CBC/PKCS5Padding");
      c.init(Cipher.ENCRYPT_MODE,externalKey,new IvParameterSpec(new byte[3]));''')
    assert "JAVA-CBC-CONSTANT-IV" not in identifiers(result)
    assert any("16 bytes" in item["reason"] for item in result["unresolved"])


def test_array_key_constructor_snapshots_before_randomization():
    result = review('''byte[] raw=new byte[16]; SecretKey key=new SecretKeySpec(raw,"AES");
      new SecureRandom().nextBytes(raw);
      Cipher c=Cipher.getInstance("AES/GCM/NoPadding");
      byte[] nonce=new SecureRandom().generateSeed(12);
      c.init(Cipher.ENCRYPT_MODE,key,new GCMParameterSpec(128,nonce));''')
    assert "JAVA-EMBEDDED-KEY" in identifiers(result)
    assert "JAVA-GCM-CONSTANT-NONCE" not in identifiers(result)


def test_key_array_filled_before_constructor_is_not_reported_constant():
    result = review('''byte[] raw=new byte[16]; new SecureRandom().nextBytes(raw);
      SecretKey key=new SecretKeySpec(raw,"AES"); Cipher c=Cipher.getInstance("AES/GCM/NoPadding");
      byte[] nonce=new byte[12]; new SecureRandom().nextBytes(nonce);
      c.init(Cipher.ENCRYPT_MODE,key,new GCMParameterSpec(128,nonce));''')
    assert "JAVA-EMBEDDED-KEY" not in identifiers(result)
    assert not result["unresolved"]


def test_known_utf8_invalid_key_length_is_reviewed_not_claimed_used_successfully():
    result = review('''SecretKey key=new SecretKeySpec("tiny".getBytes(java.nio.charset.StandardCharsets.UTF_8),"AES");
      Cipher c=Cipher.getInstance("AES/GCM/NoPadding"); c.init(Cipher.ENCRYPT_MODE,key);''')
    assert "JAVA-EMBEDDED-KEY" not in identifiers(result)
    assert any("Longitud" in item["reason"] for item in result["unresolved"])


def test_unknown_array_element_write_invalidates_constant_provenance():
    result = review('''byte[] iv=new byte[16]; iv[0]=input[0];
      Cipher c=Cipher.getInstance("AES/CBC/PKCS5Padding");
      c.init(Cipher.ENCRYPT_MODE,externalKey,new IvParameterSpec(iv));''')
    assert "JAVA-CBC-CONSTANT-IV" not in identifiers(result)


def test_constructor_not_named_jca_is_not_assumed_key_material():
    result = review('''Object ignored=new OtherKeySpec("PRIVATE_KEY_1234".getBytes(),"AES");''')
    assert not identifiers(result)


def test_decryption_with_received_iv_does_not_raise_constant_iv_finding():
    result = review('''Cipher c=Cipher.getInstance("AES/GCM/NoPadding");
      c.init(Cipher.DECRYPT_MODE,externalKey,new GCMParameterSpec(128,new byte[12]));''')
    assert "JAVA-GCM-CONSTANT-NONCE" not in identifiers(result)


def test_bare_rsa_is_an_implicit_defaults_warning_not_a_no_padding_claim():
    result = review('Cipher c=Cipher.getInstance("RSA");')
    assert "JAVA-CIPHER-IMPLICIT-DEFAULTS" in identifiers(result)
    assert "JAVA-RSA-NOPADDING" not in identifiers(result)


def test_chained_cipher_init_is_not_silently_skipped():
    result = review('''Cipher.getInstance("AES/GCM/NoPadding").init(
      Cipher.ENCRYPT_MODE, externalKey, new GCMParameterSpec(128,new byte[12]));''')
    assert "JAVA-GCM-CONSTANT-NONCE" in identifiers(result)


@pytest.mark.parametrize("mutation", [
    "Object ignored=mutate(iv);",
    "Object ignored=new Mutator(iv);",
    "Object ignored; ignored=mutate(iv);",
])
def test_unknown_constructor_or_returning_helper_invalidates_arrays(mutation):
    result = review(f'''byte[] iv=new byte[16]; {mutation}
      Cipher c=Cipher.getInstance("AES/CBC/PKCS5Padding");
      c.init(Cipher.ENCRYPT_MODE,externalKey,new IvParameterSpec(iv));''')
    assert "JAVA-CBC-CONSTANT-IV" not in identifiers(result)
    assert any("IV/nonce" in item["reason"] for item in result["unresolved"])


def test_unknown_cipher_reassignment_requires_review_instead_of_silent_skip():
    result = review('''Cipher c=Cipher.getInstance("AES/GCM/NoPadding");
      c=loadCipher(); c.init(Cipher.ENCRYPT_MODE,externalKey,new GCMParameterSpec(128,new byte[12]));''')
    assert "JAVA-GCM-CONSTANT-NONCE" not in identifiers(result)
    assert any("transformación" in item["reason"] for item in result["unresolved"])


def test_static_final_text_key_is_traced_without_disclosing_it():
    source = '''import javax.crypto.*; import javax.crypto.spec.*;
      class Demo { static final String TEXT="PRIVATE_KEY_1234";
      void run(SecretKey externalKey) throws Exception {
        byte[] bytes=TEXT.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        SecretKey key=new SecretKeySpec(bytes,"AES");
        Cipher c=Cipher.getInstance("AES/GCM/NoPadding"); c.init(Cipher.ENCRYPT_MODE,key);
      }}'''
    result = analyze(source)
    assert "JAVA-EMBEDDED-KEY" in identifiers(result)
    assert "PRIVATE_KEY_1234" not in json.dumps(result)


def test_byte_array_initializer_key_is_redacted():
    result = review('''byte[] material={1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
      SecretKey key=new SecretKeySpec(material,"AES");
      Cipher c=Cipher.getInstance("AES/GCM/NoPadding"); c.init(Cipher.ENCRYPT_MODE,key);''')
    assert "JAVA-EMBEDDED-KEY" in identifiers(result)
    assert "1,2,3,4,5" not in json.dumps(result)


def test_api_serializes_redacted_evidence_without_private_internal_state():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from tls_analyzer.api.routers.crypto_ml import router
    from tls_analyzer.api.deps import require_auth, AuthContext
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[require_auth] = lambda: AuthContext(user_id="test", role="user", actor_type="user", organization_id=1)
    source = HEADER + '''Cipher c=Cipher.getInstance("AES/GCM/NoPadding");
      SecretKey k=new SecretKeySpec("PRIVATE_KEY_1234".getBytes(),"AES");
      c.init(Cipher.ENCRYPT_MODE,k,new GCMParameterSpec(128,new byte[12])); }}'''
    response = TestClient(app).post("/api/crypto-ml/analyze", json={"filename": "Demo.java", "source": source})
    assert response.status_code == 200
    assert "JAVA-EMBEDDED-KEY" in {f["id"] for f in response.json()["findings"]}
    assert "PRIVATE_KEY_1234" not in response.text
    assert "_secret_strings" not in response.text
