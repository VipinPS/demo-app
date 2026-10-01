"""
ECDH key exchange operations.

Scenario A — Static + Dynamic:
These operations appear in source code AND are exercised at runtime.
Uses P-256 (secp256r1) curve.
"""

import base64
import logging

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

logger = logging.getLogger(__name__)


def perform_ecdh() -> dict:
    """
    Simulate a full ECDH key exchange between two parties (A and B).
    Both parties generate key pairs, exchange public keys, and each derives
    the same shared secret using HKDF.
    """
    logger.info("[DEMO] ECDH key exchange executed")

    # Party A generates a key pair
    private_key_a = ec.generate_private_key(ec.SECP256R1())
    public_key_a = private_key_a.public_key()

    # Party B generates a key pair
    private_key_b = ec.generate_private_key(ec.SECP256R1())
    public_key_b = private_key_b.public_key()

    # Party A computes shared secret using B's public key
    shared_secret_a = private_key_a.exchange(ec.ECDH(), public_key_b)

    # Party B computes shared secret using A's public key
    shared_secret_b = private_key_b.exchange(ec.ECDH(), public_key_a)

    # Derive a consistent key from each shared secret via HKDF
    derived_a = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"ecdh-demo",
    ).derive(shared_secret_a)

    derived_b = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"ecdh-demo",
    ).derive(shared_secret_b)

    secrets_match = derived_a == derived_b

    pub_a_pem = public_key_a.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    pub_b_pem = public_key_b.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    logger.info("[DEMO] ECDH key exchange complete — secrets_match=%s", secrets_match)

    return {
        "party_a_public_key": pub_a_pem,
        "party_b_public_key": pub_b_pem,
        "derived_key_a": base64.b64encode(derived_a).decode(),
        "derived_key_b": base64.b64encode(derived_b).decode(),
        "secrets_match": secrets_match,
        "curve": "P-256 (secp256r1)",
    }
