"""
Unit tests for all cryptographic operations.

Each test verifies that a real cryptographic round-trip works correctly,
confirming that the operations perform genuine cryptographic work.
"""

import base64
import pytest


# ─────────────────────────────────────────────────────────────────────────────
# RSA
# ─────────────────────────────────────────────────────────────────────────────

class TestRSA:
    def setup_method(self):
        """Generate a fresh RSA key pair before each test."""
        import app.crypto.rsa_operations as rsa_mod
        # Reset module-level key state
        rsa_mod._rsa_private_key = None
        rsa_mod._rsa_public_key = None
        from app.crypto.rsa_operations import generate_rsa_key
        result = generate_rsa_key()
        assert "public_key" in result

    def test_encrypt_decrypt_roundtrip(self):
        from app.crypto.rsa_operations import rsa_encrypt, rsa_decrypt
        plaintext = "RSA round-trip test"
        enc = rsa_encrypt(plaintext)
        assert "ciphertext" in enc
        dec = rsa_decrypt(enc["ciphertext"])
        assert dec["plaintext"] == plaintext

    def test_sign_verify_roundtrip(self):
        from app.crypto.rsa_operations import rsa_sign, rsa_verify
        message = "Sign this RSA message"
        signed = rsa_sign(message)
        assert "signature" in signed
        verified = rsa_verify(message, signed["signature"])
        assert verified["valid"] is True

    def test_verify_invalid_signature(self):
        from app.crypto.rsa_operations import rsa_sign, rsa_verify
        message = "Original message"
        signed = rsa_sign(message)
        result = rsa_verify("Tampered message", signed["signature"])
        assert result["valid"] is False

    def test_decrypt_with_no_key_raises(self):
        import app.crypto.rsa_operations as rsa_mod
        rsa_mod._rsa_private_key = None
        rsa_mod._rsa_public_key = None
        from app.crypto.rsa_operations import rsa_decrypt
        with pytest.raises(ValueError, match="No RSA key"):
            rsa_decrypt("AAAA")


# ─────────────────────────────────────────────────────────────────────────────
# ECDSA
# ─────────────────────────────────────────────────────────────────────────────

class TestECDSA:
    def setup_method(self):
        import app.crypto.ecdsa_operations as ecdsa_mod
        ecdsa_mod._ecdsa_private_key = None
        ecdsa_mod._ecdsa_public_key = None
        from app.crypto.ecdsa_operations import generate_ecdsa_key
        result = generate_ecdsa_key()
        assert result["curve"] == "P-256 (secp256r1)"

    def test_sign_verify_roundtrip(self):
        from app.crypto.ecdsa_operations import ecdsa_sign, ecdsa_verify
        message = "ECDSA test payload"
        signed = ecdsa_sign(message)
        assert "signature" in signed
        verified = ecdsa_verify(message, signed["signature"])
        assert verified["valid"] is True

    def test_verify_tampered_message_fails(self):
        from app.crypto.ecdsa_operations import ecdsa_sign, ecdsa_verify
        message = "Original ECDSA message"
        signed = ecdsa_sign(message)
        result = ecdsa_verify("Different message", signed["signature"])
        assert result["valid"] is False


# ─────────────────────────────────────────────────────────────────────────────
# ECDH
# ─────────────────────────────────────────────────────────────────────────────

class TestECDH:
    def test_exchange_produces_matching_secrets(self):
        from app.crypto.ecdh_operations import perform_ecdh
        result = perform_ecdh()
        assert result["secrets_match"] is True

    def test_derived_keys_are_different_each_time(self):
        from app.crypto.ecdh_operations import perform_ecdh
        r1 = perform_ecdh()
        r2 = perform_ecdh()
        # Different ephemeral keys → different derived keys
        assert r1["derived_key_a"] != r2["derived_key_a"]

    def test_result_fields(self):
        from app.crypto.ecdh_operations import perform_ecdh
        result = perform_ecdh()
        assert "party_a_public_key" in result
        assert "party_b_public_key" in result
        assert result["curve"] == "P-256 (secp256r1)"


# ─────────────────────────────────────────────────────────────────────────────
# DH
# ─────────────────────────────────────────────────────────────────────────────

class TestDH:
    def test_exchange_produces_matching_secrets(self):
        from app.crypto.dh_operations import perform_dh
        result = perform_dh()
        assert result["secrets_match"] is True

    def test_group_label(self):
        from app.crypto.dh_operations import perform_dh
        result = perform_dh()
        assert "RFC 3526" in result["group"]


# ─────────────────────────────────────────────────────────────────────────────
# AES
# ─────────────────────────────────────────────────────────────────────────────

class TestAES:
    def setup_method(self):
        import app.crypto.aes_operations as aes_mod
        aes_mod._aes_key = None  # reset session key

    def test_encrypt_decrypt_roundtrip(self):
        from app.crypto.aes_operations import aes_encrypt, aes_decrypt
        plaintext = "AES-GCM round-trip test message"
        enc = aes_encrypt(plaintext)
        assert "ciphertext" in enc
        assert "nonce" in enc
        dec = aes_decrypt(enc["ciphertext"], enc["nonce"])
        assert dec["plaintext"] == plaintext

    def test_encrypt_decrypt_with_aad(self):
        from app.crypto.aes_operations import aes_encrypt, aes_decrypt
        plaintext = "Authenticated plaintext"
        aad = "additional-auth-data"
        enc = aes_encrypt(plaintext, aad)
        dec = aes_decrypt(enc["ciphertext"], enc["nonce"], aad)
        assert dec["plaintext"] == plaintext

    def test_wrong_aad_fails_authentication(self):
        from app.crypto.aes_operations import aes_encrypt, aes_decrypt
        enc = aes_encrypt("secret", "correct-aad")
        with pytest.raises(Exception):
            aes_decrypt(enc["ciphertext"], enc["nonce"], "wrong-aad")

    def test_each_encryption_uses_fresh_nonce(self):
        from app.crypto.aes_operations import aes_encrypt
        r1 = aes_encrypt("text")
        r2 = aes_encrypt("text")
        assert r1["nonce"] != r2["nonce"]

    def test_no_key_raises(self):
        from app.crypto.aes_operations import aes_decrypt
        with pytest.raises(ValueError, match="No AES key"):
            aes_decrypt("AAAA", "BBBB")


# ─────────────────────────────────────────────────────────────────────────────
# Hashing
# ─────────────────────────────────────────────────────────────────────────────

class TestHash:
    def test_sha256_known_digest(self):
        from app.crypto.hash_operations import sha256_hash
        # echo -n "" | sha256sum
        result = sha256_hash("")
        assert result["algorithm"] == "SHA-256"
        assert result["digest_hex"] == (
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )

    def test_sha256_non_empty(self):
        from app.crypto.hash_operations import sha256_hash
        result = sha256_hash("hello")
        assert len(result["digest_hex"]) == 64  # 256-bit → 64 hex chars

    def test_sha512_known_digest(self):
        from app.crypto.hash_operations import sha512_hash
        # echo -n "" | sha512sum
        result = sha512_hash("")
        assert result["algorithm"] == "SHA-512"
        assert result["digest_hex"] == (
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
            "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        )

    def test_sha512_non_empty(self):
        from app.crypto.hash_operations import sha512_hash
        result = sha512_hash("hello")
        assert len(result["digest_hex"]) == 128  # 512-bit → 128 hex chars

    def test_sha256_deterministic(self):
        from app.crypto.hash_operations import sha256_hash
        r1 = sha256_hash("deterministic")
        r2 = sha256_hash("deterministic")
        assert r1["digest_hex"] == r2["digest_hex"]

    def test_sha256_different_inputs(self):
        from app.crypto.hash_operations import sha256_hash
        assert sha256_hash("aaa")["digest_hex"] != sha256_hash("bbb")["digest_hex"]


# ─────────────────────────────────────────────────────────────────────────────
# Flask API integration (lightweight — no external network)
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def client():
    import app.crypto.rsa_operations as rsa_mod
    import app.crypto.ecdsa_operations as ecdsa_mod
    import app.crypto.aes_operations as aes_mod
    rsa_mod._rsa_private_key = None
    rsa_mod._rsa_public_key = None
    ecdsa_mod._ecdsa_private_key = None
    ecdsa_mod._ecdsa_public_key = None
    aes_mod._aes_key = None

    from app.main import app as flask_app
    flask_app.config["TESTING"] = True
    with flask_app.test_client() as c:
        yield c


class TestFlaskAPI:
    def test_health(self, client):
        r = client.get("/health")
        assert r.status_code == 200
        assert r.get_json()["status"] == "ok"

    def test_rsa_full_flow(self, client):
        assert client.post("/api/rsa/generate", json={}).get_json()["ok"]
        enc = client.post("/api/rsa/encrypt", json={"plaintext": "test"}).get_json()
        assert enc["ok"]
        dec = client.post("/api/rsa/decrypt", json={"ciphertext": enc["result"]["ciphertext"]}).get_json()
        assert dec["ok"]
        assert dec["result"]["plaintext"] == "test"

    def test_ecdsa_full_flow(self, client):
        assert client.post("/api/ecdsa/generate", json={}).get_json()["ok"]
        s = client.post("/api/ecdsa/sign", json={"message": "hi"}).get_json()
        assert s["ok"]
        v = client.post("/api/ecdsa/verify", json={"message": "hi", "signature": s["result"]["signature"]}).get_json()
        assert v["ok"]
        assert v["result"]["valid"] is True

    def test_ecdh_exchange(self, client):
        r = client.post("/api/ecdh/exchange", json={}).get_json()
        assert r["ok"]
        assert r["result"]["secrets_match"] is True

    def test_dh_exchange(self, client):
        r = client.post("/api/dh/exchange", json={}).get_json()
        assert r["ok"]
        assert r["result"]["secrets_match"] is True

    def test_aes_full_flow(self, client):
        enc = client.post("/api/aes/encrypt", json={"plaintext": "hello", "aad": ""}).get_json()
        assert enc["ok"]
        dec = client.post("/api/aes/decrypt", json={
            "ciphertext": enc["result"]["ciphertext"],
            "nonce": enc["result"]["nonce"],
            "aad": "",
        }).get_json()
        assert dec["ok"]
        assert dec["result"]["plaintext"] == "hello"

    def test_sha256(self, client):
        r = client.post("/api/hash/sha256", json={"text": "test"}).get_json()
        assert r["ok"]
        assert len(r["result"]["digest_hex"]) == 64

    def test_sha512(self, client):
        r = client.post("/api/hash/sha512", json={"text": "test"}).get_json()
        assert r["ok"]
        assert len(r["result"]["digest_hex"]) == 128

    def test_missing_plaintext_returns_400(self, client):
        r = client.post("/api/rsa/encrypt", json={})
        assert r.status_code == 400
