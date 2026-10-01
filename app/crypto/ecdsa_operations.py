"""
ECDSA cryptographic operations.

Scenario A — Static + Dynamic:
These operations appear in source code AND are exercised at runtime.
Uses P-256 (secp256r1) curve.
"""

import base64
import logging

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

logger = logging.getLogger(__name__)

_ecdsa_private_key = None
_ecdsa_public_key = None


def generate_ecdsa_key() -> dict:
    """Generate an ECDSA key pair on P-256."""
    global _ecdsa_private_key, _ecdsa_public_key

    logger.info("[DEMO] ECDSA key generation started (P-256 / secp256r1)")

    _ecdsa_private_key = ec.generate_private_key(ec.SECP256R1())
    _ecdsa_public_key = _ecdsa_private_key.public_key()

    pub_pem = _ecdsa_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    logger.info("[DEMO] ECDSA key generation complete")
    return {"public_key": pub_pem, "curve": "P-256 (secp256r1)"}


def ecdsa_sign(message: str) -> dict:
    """Sign a message with ECDSA (SHA-256)."""
    if _ecdsa_private_key is None:
        raise ValueError("No ECDSA key loaded. Generate a key first.")

    logger.info("[DEMO] ECDSA signature generated")

    signature = _ecdsa_private_key.sign(
        message.encode(),
        ec.ECDSA(hashes.SHA256()),
    )
    return {"signature": base64.b64encode(signature).decode()}


def ecdsa_verify(message: str, signature_b64: str) -> dict:
    """Verify an ECDSA signature against the in-memory public key."""
    if _ecdsa_public_key is None:
        raise ValueError("No ECDSA key loaded. Generate a key first.")

    logger.info("[DEMO] ECDSA signature verification executed")

    signature = base64.b64decode(signature_b64)
    try:
        _ecdsa_public_key.verify(
            signature,
            message.encode(),
            ec.ECDSA(hashes.SHA256()),
        )
        return {"valid": True, "message": "Signature is valid"}
    except Exception as exc:
        return {"valid": False, "message": f"Verification failed: {exc}"}
