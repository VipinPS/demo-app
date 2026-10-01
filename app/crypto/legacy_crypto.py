"""
Legacy cryptographic paths.

Scenario B — Static Only:
This module contains valid, realistic cryptographic code that exists in the
repository and is discoverable by a static scanner, but is NOT called by the
normal application flow or workload generator.

Purpose: demonstrate that a static scanner finds more crypto patterns than
         the eBPF runtime agent observes during a standard demo run.

DO NOT import or call functions from this module in the main application routes.
"""

import base64
import logging

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.asymmetric.dh import DHParameterNumbers
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Legacy RSA-1024 path (intentionally undersized — for detection demo only)
# ---------------------------------------------------------------------------

def legacy_rsa_1024_keygen():
    """
    Generate an RSA-1024 key pair.

    NOTE: 1024-bit RSA is no longer considered secure for production use.
    This function exists solely so that the static scanner can detect a
    legacy RSA key-size usage pattern in the codebase.

    This function is NOT called from the main application.
    """
    logger.warning("[DEMO][LEGACY] RSA-1024 key generation — legacy path, not used in production")

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=1024,
    )
    public_key = private_key.public_key()

    return {
        "private_key": private_key,
        "public_key": public_key,
        "key_size": 1024,
        "warning": "RSA-1024 is not considered secure. This is a legacy demo path.",
    }


def legacy_rsa_encrypt_pkcs1v15(plaintext: bytes, public_key) -> bytes:
    """
    Encrypt with RSA PKCS#1 v1.5 padding.

    NOTE: PKCS#1 v1.5 is vulnerable to padding-oracle attacks.
    This function exists solely so the scanner can detect PKCS1v15 usage.

    This function is NOT called from the main application.
    """
    logger.warning("[DEMO][LEGACY] RSA PKCS1v15 encryption — legacy path")

    return public_key.encrypt(plaintext, padding.PKCS1v15())


# ---------------------------------------------------------------------------
# Legacy DH with small group (512-bit) — for scanner detection only
# ---------------------------------------------------------------------------

_LEGACY_DH_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B13",
    16,
)
_LEGACY_DH_G = 2


def legacy_dh_small_group():
    """
    Perform a DH key exchange using a small (non-standard) group.

    NOTE: Small DH groups are not secure for production use.
    This function exists solely so the scanner detects a legacy DH pattern.

    This function is NOT called from the main application.
    """
    logger.warning("[DEMO][LEGACY] DH small-group key exchange — legacy path, not used in production")

    pn = DHParameterNumbers(_LEGACY_DH_P, _LEGACY_DH_G)
    params = pn.parameters()

    key_a = params.generate_private_key()
    key_b = params.generate_private_key()
    secret_a = key_a.exchange(key_b.public_key())
    secret_b = key_b.exchange(key_a.public_key())

    return {
        "secrets_match": secret_a == secret_b,
        "warning": "Small DH group — legacy demo path only.",
    }


# ---------------------------------------------------------------------------
# Legacy AES-CBC (no authentication — for scanner detection only)
# ---------------------------------------------------------------------------

def legacy_aes_128_cbc_encrypt(plaintext: bytes) -> dict:
    """
    Encrypt with AES-128-CBC (unauthenticated).

    NOTE: CBC without authentication is vulnerable to padding-oracle and
    bit-flipping attacks. This function exists so the scanner can detect
    AES-CBC usage alongside the preferred AES-GCM path.

    This function is NOT called from the main application.
    """
    logger.warning("[DEMO][LEGACY] AES-128-CBC encryption — legacy path")

    key = os.urandom(16)   # 128-bit key
    iv = os.urandom(16)

    # Pad to block boundary (manual PKCS7 for visibility in source)
    pad_len = 16 - (len(plaintext) % 16)
    padded = plaintext + bytes([pad_len] * pad_len)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    return {
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "iv": base64.b64encode(iv).decode(),
        "key_preview": base64.b64encode(key).decode()[:16] + "...",
        "warning": "AES-128-CBC — legacy demo path only.",
    }
