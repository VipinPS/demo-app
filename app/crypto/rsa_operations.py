"""
RSA cryptographic operations.

Scenario A — Static + Dynamic:
These operations appear in source code AND are exercised at runtime.
"""

import base64
import logging

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

logger = logging.getLogger(__name__)

# In-memory key store for the demo session
_rsa_private_key = None
_rsa_public_key = None


def generate_rsa_key() -> dict:
    """Generate an RSA-2048 key pair."""
    global _rsa_private_key, _rsa_public_key

    logger.info("[DEMO] RSA-2048 key generation started")

    _rsa_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    _rsa_public_key = _rsa_private_key.public_key()

    pub_pem = _rsa_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    priv_pem = _rsa_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()

    logger.info("[DEMO] RSA-2048 key generation complete")
    return {
        "public_key": pub_pem,
        "private_key_preview": priv_pem[:64] + "...",
    }


def rsa_encrypt(plaintext: str) -> dict:
    """Encrypt plaintext using the in-memory RSA public key (OAEP/SHA-256)."""
    if _rsa_public_key is None:
        raise ValueError("No RSA key loaded. Generate a key first.")

    logger.info("[DEMO] RSA encryption executed")

    ciphertext = _rsa_public_key.encrypt(
        plaintext.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return {"ciphertext": base64.b64encode(ciphertext).decode()}


def rsa_decrypt(ciphertext_b64: str) -> dict:
    """Decrypt base64-encoded ciphertext using the in-memory RSA private key."""
    if _rsa_private_key is None:
        raise ValueError("No RSA key loaded. Generate a key first.")

    logger.info("[DEMO] RSA decryption executed")

    ciphertext = base64.b64decode(ciphertext_b64)
    plaintext = _rsa_private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return {"plaintext": plaintext.decode()}


def rsa_sign(message: str) -> dict:
    """Sign a message using the in-memory RSA private key (PSS/SHA-256)."""
    if _rsa_private_key is None:
        raise ValueError("No RSA key loaded. Generate a key first.")

    logger.info("[DEMO] RSA-PSS signature generated")

    signature = _rsa_private_key.sign(
        message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return {"signature": base64.b64encode(signature).decode()}


def rsa_verify(message: str, signature_b64: str) -> dict:
    """Verify an RSA-PSS signature against the in-memory public key."""
    if _rsa_public_key is None:
        raise ValueError("No RSA key loaded. Generate a key first.")

    logger.info("[DEMO] RSA signature verification executed")

    signature = base64.b64decode(signature_b64)
    try:
        _rsa_public_key.verify(
            signature,
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return {"valid": True, "message": "Signature is valid"}
    except Exception as exc:
        return {"valid": False, "message": f"Verification failed: {exc}"}
